"""内存伪权威 DNS：实现 RFC 2136 动态更新子集 + TSIG 校验 + TXT 查询。

仅用于无 Docker/BIND 环境下的端到端测试，走 dnspython 真实协议（UDP 查询、
TCP 更新、TSIG 签名验证），与生产 DnsClient 的代码路径一致。

运行：python3 -I tests/test_e2e.py
"""

from __future__ import annotations

import base64
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.message  # noqa: E402
import dns.name  # noqa: E402
import dns.rcode  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402
import dns.tsigkeyring  # noqa: E402

from app.config import Settings  # noqa: E402
from app.dns_client import DnsClient  # noqa: E402
from app.domain import acme_challenge_name, content_hash, now_ts  # noqa: E402
from app.store import (  # noqa: E402
    STATUS_PENDING,
    STATUS_READY,
    STATUS_WITHDRAWN,
    Store,
)
from app.worker import DnsChallengeWorker  # noqa: E402

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok - {name}")
    else:
        failures.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")


class FakeAuthoritativeDNS:
    """单线程 UDP 查询 + TCP 更新服务器；数据为 {qname: set[str]}。"""

    def __init__(self, tsig_name: str, tsig_secret: str):
        self.keyring = dns.tsigkeyring.from_text({tsig_name: tsig_secret})
        self.data: dict[str, set[str]] = {}
        self._lock = threading.RLock()
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self.port = 0
        self._stop = threading.Event()
        self.threads: list[threading.Thread] = []

    def start(self) -> int:
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", 0))
        self.port = self._udp.getsockname()[1]
        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind(("127.0.0.1", self.port))
        self._tcp.listen(8)
        t1 = threading.Thread(target=self._serve_udp, daemon=True)
        t2 = threading.Thread(target=self._serve_tcp, daemon=True)
        t1.start(); t2.start()
        self.threads = [t1, t2]
        return self.port

    def stop(self) -> None:
        self._stop.set()
        for s in (self._udp, self._tcp):
            try:
                s.close()
            except Exception:
                pass
        # 等待服务线程结束，避免解释器关闭时 daemon 线程竞争 stdout
        for t in self.threads:
            t.join(timeout=2.0)

    # ------------------------------------------------------------------ #
    def _serve_udp(self) -> None:
        assert self._udp is not None
        self._udp.settimeout(0.5)
        while not self._stop.is_set():
            try:
                wire, addr = self._udp.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                msg = dns.message.from_wire(wire)
                resp = self._handle_query(msg)
            except Exception as exc:  # pragma: no cover
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.SERVFAIL)
                print("fake udp error:", exc)
            self._udp.sendto(resp.to_wire(), addr)

    def _serve_tcp(self) -> None:
        assert self._tcp is not None
        self._tcp.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle_tcp_conn, args=(conn,),
                             daemon=True).start()

    def _handle_tcp_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(2)
            hdr = self._recv_n(conn, 2)
            if not hdr:
                return
            length = int.from_bytes(hdr, "big")
            wire = self._recv_n(conn, length)
            # keyring 传入即触发 TSIG 校验；坏签名会抛异常 -> REFUSED
            try:
                msg = dns.message.from_wire(wire, keyring=self.keyring)
            except Exception:
                err = dns.message.make_response(
                    dns.message.from_wire(wire) if wire else dns.message.Message()
                )
                err.set_rcode(dns.rcode.REFUSED)
                payload = err.to_wire()
                conn.sendall(len(payload).to_bytes(2, "big") + payload)
                return
            resp = self._handle_update(msg)
            data = resp.to_wire()
            conn.sendall(len(data).to_bytes(2, "big") + data)
        finally:
            conn.close()

    @staticmethod
    def _recv_n(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # ------------------------------------------------------------------ #
    def _handle_query(self, msg: dns.message.Message) -> dns.message.Message:
        resp = dns.message.make_response(msg)
        question = msg.question[0]
        # 统一用不带尾点的绝对名作为字典键
        qname = question.name.to_text().rstrip(".")
        with self._lock:
            values = list(self.data.get(qname, ()))
        if not values:
            resp.set_rcode(dns.rcode.NXDOMAIN)
            return resp
        rrset = dns.rrset.from_text_list(question.name, 30, dns.rdataclass.IN,
                                         dns.rdatatype.TXT,
                                         [f'"{v}"' for v in values])
        resp.answer.append(rrset)
        resp.set_rcode(dns.rcode.NOERROR)
        return resp

    def _handle_update(self, msg: dns.message.Message) -> dns.message.Message:
        # 用 make_response 保证 id/opcode/zone question 与请求匹配，
        # 否则 dnspython 客户端会报 "does not respond to the question asked"
        resp = dns.message.make_response(msg)
        with self._lock:
            for rrset in msg.update:
                # 更新消息里的 owner 是绝对名，去掉尾点作为统一键
                name = rrset.name.to_text().rstrip(".")
                if rrset.rdtype != dns.rdatatype.TXT:
                    continue
                if rrset.covers != 0:
                    continue
                for rdata in rrset:
                    value = rdata.strings[0].decode()
                    if rrset.ttl == 0:
                        # 删除精确 RDATA；不存在视为成功（NXRRSET 容忍）
                        self.data.setdefault(name, set()).discard(value)
                        if not self.data.get(name):
                            self.data.pop(name, None)
                    else:
                        self.data.setdefault(name, set()).add(value)
        resp.set_rcode(dns.rcode.NOERROR)
        return resp

    def values(self, name: str) -> set[str]:
        with self._lock:
            return set(self.data.get(name, set()))


# --------------------------------------------------------------------------- #
# 测试基础设施
# --------------------------------------------------------------------------- #
def make_settings(port: int, tmp_db: str) -> Settings:
    secret = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
    return Settings(
        management_key="k",
        database_path=tmp_db,
        allowed_domains=["acme.test", "*.acme.test"],
        dns_server="127.0.0.1",
        dns_port=port,
        tsig_key_name="acme-key.",
        tsig_secret=secret,
        tsig_algorithm="hmac-sha256",
        dns_update_timeout=3.0,
        dns_query_timeout=3.0,
        worker_poll_interval=0.2,
        ready_poll_interval=0.2,
        ready_poll_max=8,
        retry_base_delay=0.4,
        retry_max_delay=2.0,
    )


def wait_until(deadline_s: float, predicate, label: str):
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.1)
    raise AssertionError(f"等待超时: {label}")


def insert_app(store: Store, app_id: str, domain: str, value: str,
               ttl: int = 120) -> None:
    store.insert_application(
        app_id=app_id, domain=domain, record_name=acme_challenge_name(domain),
        txt_value=value, ttl_seconds=ttl,
        fingerprint=content_hash(domain, value, ttl),
        expires_at=now_ts() + ttl,
    )


def run_worker_steps(settings: Settings, store: Store, client: DnsClient,
                     ticks: int) -> DnsChallengeWorker:
    """同步跑指定轮数的 worker 逻辑（不起常驻线程，便于确定性断言）。"""
    worker = DnsChallengeWorker(settings=settings, store=store, dns=client)
    for _ in range(ticks):
        store.due_expirations()
        worker.process_publish()
        worker.process_withdraw()
    return worker


def main() -> int:
    import tempfile
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    fake = FakeAuthoritativeDNS("acme-key.",
                                base64.b64encode(b"0123456789abcdef0123456789abcdef").decode())
    port = fake.start()
    settings = make_settings(port, db)
    store = Store(db)
    client = DnsClient(
        server=settings.dns_server, port=port,
        tsig_key_name=settings.tsig_key_name, tsig_secret=settings.tsig_secret,
        tsig_algorithm=settings.tsig_algorithm,
        update_timeout=3.0, query_timeout=3.0,
    )
    rec1 = acme_challenge_name("host1.acme.test")
    rec2 = acme_challenge_name("host2.acme.test")

    try:
        print("test_publish_ready_and_dns_verify")
        insert_app(store, "a1", "host1.acme.test", "VALUE-A")
        run_worker_steps(settings, store, client, ticks=3)
        r = store.get_application("a1")
        check("发布后状态 ready", r["status"] == STATUS_READY, r["status"])
        check("权威 DNS 可查到本值", client.txt_present(rec1, "VALUE-A"))
        check("发布注册表已登记", store.publication_exists(rec1, "VALUE-A"))
        check("核对接口数据一致", "VALUE-A" in client.query_txt(rec1))

        print("test_multiple_values_coexist")
        insert_app(store, "a2", "host1.acme.test", "VALUE-B")
        insert_app(store, "a3", "host2.acme.test", "VALUE-C")
        run_worker_steps(settings, store, client, ticks=4)
        check("同记录两个 TXT 共存",
              fake.values(rec1) == {"VALUE-A", "VALUE-B"}, str(fake.values(rec1)))
        check("另一记录独立", fake.values(rec2) == {"VALUE-C"})
        check("a2/a3 均 ready",
              store.get_application("a2")["status"] == STATUS_READY
              and store.get_application("a3")["status"] == STATUS_READY)

        print("test_withdraw_keeps_shared_and_foreign_txt")
        # 外部（非本模块）TXT，撤回时必须保留
        fake.data.setdefault(rec1, set()).add("FOREIGN-TXT")
        # a2 到期撤回；VALUE-B 仅 a2 引用 -> 应删除；VALUE-A 仍有效 -> 保留
        with store.tx() as conn:
            conn.execute("UPDATE applications SET expires_at=? WHERE id=?",
                         (now_ts() - 1, "a2"))
        run_worker_steps(settings, store, client, ticks=4)
        check("a2 已撤回终态", store.get_application("a2")["status"] == STATUS_WITHDRAWN)
        check("VALUE-B 已从 DNS 删除", "VALUE-B" not in fake.values(rec1))
        check("VALUE-A 仍保留（其它有效申请）", "VALUE-A" in fake.values(rec1))
        check("他方 TXT 原样保留", "FOREIGN-TXT" in fake.values(rec1))

        print("test_shared_value_retained_until_last_reference")
        # a1 与新申请 a4 共用 VALUE-A
        insert_app(store, "a4", "host1.acme.test", "VALUE-A")
        run_worker_steps(settings, store, client, ticks=2)
        with store.tx() as conn:
            conn.execute("UPDATE applications SET expires_at=? WHERE id=?",
                         (now_ts() - 1, "a1"))
        run_worker_steps(settings, store, client, ticks=3)
        check("a1 结束但共享 VALUE-A 被 a4 引用而保留",
              store.get_application("a1")["status"] == STATUS_WITHDRAWN
              and "VALUE-A" in fake.values(rec1))
        with store.tx() as conn:
            conn.execute("UPDATE applications SET expires_at=? WHERE id=?",
                         (now_ts() - 1, "a4"))
        run_worker_steps(settings, store, client, ticks=3)
        check("最后一个引用消失后 VALUE-A 才删除",
              "VALUE-A" not in fake.values(rec1))
        check("他方 TXT 始终保留", "FOREIGN-TXT" in fake.values(rec1))

        print("test_cancel_during_publish_late_result_rejected")
        insert_app(store, "a5", "host1.acme.test", "VALUE-E")
        # 认领到 publishing 后立即取消，再让 worker 处理：迟到 ready 不得复活
        claimed = store.claim_due_publish()
        check("认领的是 a5", claimed["id"] == "a5")
        v = claimed["version"]
        accepted, state = store.request_cancel("a5")
        check("发布途中取消受理", accepted and state == "withdrawing")
        # 直接尝试用旧版本号置 ready，必须失败
        check("迟到 ready 被拒绝", store.mark_ready("a5", v) is False)
        # 让 worker 完整跑：DNS 即便已写入，撤回流程也要清理
        run_worker_steps(settings, store, client, ticks=4)
        r5 = store.get_application("a5")
        check("a5 终态为 withdrawn（DNS 已清理）",
              r5["status"] == STATUS_WITHDRAWN, r5["status"])
        check("VALUE-E 未残留", "VALUE-E" not in fake.values(rec1))
        check("他方 TXT 依旧保留", "FOREIGN-TXT" in fake.values(rec1))

        print("test_lost_receipt_reconcile")
        insert_app(store, "a6", "host1.acme.test", "VALUE-F")
        worker = DnsChallengeWorker(settings=settings, store=store, dns=client)
        store.set_config("fault_lost_receipt", "1")
        worker.process_publish()  # DNS 已写但丢回执
        check("丢回执后 DNS 已有值", "VALUE-F" in fake.values(rec1))
        r6 = store.get_application("a6")
        check("丢回执后申请退回 pending 待续办", r6["status"] == STATUS_PENDING)
        check("注册表暂未登记", not store.publication_exists(rec1, "VALUE-F"))
        store.set_config("fault_lost_receipt", "0")
        # 下一轮 worker 重查续办
        worker.reconcile()
        run_worker_steps(settings, store, client, ticks=2)
        r6 = store.get_application("a6")
        check("续办后补登记并 ready",
              r6["status"] == STATUS_READY and store.publication_exists(rec1, "VALUE-F"),
              r6["status"])

        print("test_restart_reconcile_orphan_cleanup")
        # 模拟“重启”：新建 worker 实例（新连接），跑启动对账
        store2 = Store(db)
        worker2 = DnsChallengeWorker(settings=settings, store=store2, dns=client)
        # 造一个注册表有、但无任何申请引用、DNS 仍存在的孤儿
        rec_orphan = acme_challenge_name("orphan.acme.test")
        fake.data.setdefault(rec_orphan, set()).add("ORPHAN-V")
        store2.record_publication(rec_orphan, "ORPHAN-V", "dead-app")
        worker2.reconcile()
        check("孤儿 TXT 被启动对账清理", "ORPHAN-V" not in fake.values(rec_orphan))
        check("孤儿登记已移除", not store2.publication_exists(rec_orphan, "ORPHAN-V"))

        print("test_tsig_enforced")
        bad_client = DnsClient(
            server="127.0.0.1", port=port, tsig_key_name="acme-key.",
            tsig_secret=base64.b64encode(b"wrong-secret-wrong-secret-32byte!!").decode(),
            tsig_algorithm="hmac-sha256", update_timeout=3.0, query_timeout=3.0,
        )
        raised = False
        try:
            bad_client.add_txt("acme.test", rec1, "SHOULD-FAIL", 30)
        except Exception:
            raised = True
        check("错误 TSIG 密钥的更新被拒绝", raised)
        check("拒绝后未写入", "SHOULD-FAIL" not in fake.values(rec1))

    finally:
        fake.stop()
        store.close()

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        return 1
    print("全部端到端测试通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
