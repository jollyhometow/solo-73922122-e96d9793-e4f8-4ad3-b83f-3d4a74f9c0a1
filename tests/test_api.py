"""HTTP API 集成测试：FastAPI TestClient + 伪权威 DNS + 真实 worker 线程。

验证：管理密钥鉴权、白名单 403、TTL 422、同 ID 同内容幂等不延期、异内容 409、
取消不阻塞、状态/核对接口、故障开关、/docs 可演示。

运行：python3 -I tests/test_api.py
"""

from __future__ import annotations

import base64
import os
import sys
import tempfile
import threading
import time

# app.main 在导入期即创建 Store，先给一个临时数据库路径
_fd, _db = tempfile.mkstemp(suffix=".db")
os.close(_fd)
os.environ["DATABASE_PATH"] = _db

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from app import main as web  # noqa: E402
from app.config import Settings  # noqa: E402
from app.dns_client import DnsClient  # noqa: E402
from app.store import Store  # noqa: E402
from app.worker import DnsChallengeWorker  # noqa: E402
from tests.test_e2e import FakeAuthoritativeDNS  # noqa: E402

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok - {name}")
    else:
        failures.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")


SECRET = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
HEADERS = {"X-Management-Key": "k"}


def wait_for(predicate, label: str, timeout: float = 8.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(f"等待超时: {label}")


def build_app():
    fd, db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    fake = FakeAuthoritativeDNS("acme-key.", SECRET)
    port = fake.start()
    settings = Settings(
        management_key="k",
        database_path=db,
        allowed_domains=["acme.test", "*.acme.test"],
        dns_server="127.0.0.1", dns_port=port,
        tsig_key_name="acme-key.", tsig_secret=SECRET,
        tsig_algorithm="hmac-sha256",
        worker_poll_interval=0.15, ready_poll_interval=0.1, ready_poll_max=10,
        retry_base_delay=0.3, retry_max_delay=2.0,
    )
    store = Store(db)
    client = DnsClient("127.0.0.1", port, "acme-key.", SECRET, "hmac-sha256", 3, 3)
    worker = DnsChallengeWorker(settings=settings, store=store, dns=client)
    thread = threading.Thread(target=worker.run, daemon=True)
    # 让 web 模块使用这套 store/settings
    web._settings = settings
    web._store = store
    thread.start()
    return fake, store, worker, thread, db


def main() -> int:
    fake, store, worker, thread, db = build_app()
    app = web.app
    client = TestClient(app)
    try:
        print("test_docs_and_health")
        check("/docs 可访问", client.get("/docs").status_code == 200)
        check("openapi.json 可访问", client.get("/openapi.json").status_code == 200)
        h = client.get("/health").json()
        check("健康检查返回 ok", h["status"] == "ok" and h["database"] == "ok")
        check("根路径重定向到 /docs", client.get("/", follow_redirects=False).status_code in (302, 307))

        print("test_auth_required")
        r = client.post("/api/v1/challenges", json={
            "application_id": "x", "domain": "host1.acme.test",
            "txt_value": "V", "ttl_seconds": 120})
        check("无密钥 401", r.status_code == 401)
        r = client.post("/api/v1/challenges",
                        headers={"X-Management-Key": "wrong"},
                        json={"application_id": "x", "domain": "host1.acme.test",
                              "txt_value": "V", "ttl_seconds": 120})
        check("错密钥 401", r.status_code == 401)
        r = client.post("/api/v1/challenges",
                        headers={"Authorization": "Bearer k"},
                        json={"application_id": "bearer1", "domain": "host1.acme.test",
                              "txt_value": "VB", "ttl_seconds": 60})
        check("Bearer 方案可用", r.status_code == 201)

        print("test_validation_whitelist_ttl")
        r = client.post("/api/v1/challenges", headers=HEADERS, json={
            "application_id": "bad1", "domain": "evil.com",
            "txt_value": "V", "ttl_seconds": 120})
        check("非白名单域名 403", r.status_code == 403)
        r = client.post("/api/v1/challenges", headers=HEADERS, json={
            "application_id": "bad2", "domain": "host1.acme.test",
            "txt_value": "V", "ttl_seconds": 29})
        check("TTL 小于下限 422", r.status_code == 422)
        r = client.post("/api/v1/challenges", headers=HEADERS, json={
            "application_id": "bad3", "domain": "host1.acme.test",
            "txt_value": "V", "ttl_seconds": 301})
        check("TTL 大于上限 422", r.status_code == 422)
        r = client.post("/api/v1/challenges", headers=HEADERS, json={
            "application_id": "bad4", "domain": "host1.acme.test",
            "txt_value": "bad value", "ttl_seconds": 120})
        check("非法 TXT 值 422", r.status_code == 422)

        print("test_create_publish_ready_verify")
        payload = {"application_id": "app1", "domain": "host1.acme.test",
                   "txt_value": "TXT-1", "ttl_seconds": 120}
        r = client.post("/api/v1/challenges", headers=HEADERS, json=payload)
        check("首次创建 201", r.status_code == 201)
        first_expiry = r.json()["expires_at"]
        check("初始 pending", r.json()["status"] == "pending")
        wait_for(lambda: client.get("/api/v1/challenges/app1").json()["status"] == "ready",
                 "app1 ready")
        r = client.get("/api/v1/challenges/app1")
        check("状态 ready 且 ready=true", r.json()["status"] == "ready" and r.json()["ready"])
        v = client.get("/api/v1/challenges/app1/verify")
        check("核对接口 dns_present", v.status_code == 200 and v.json()["dns_present"] is True)
        check("核对接口显示本模块发布", v.json()["published_by_this_module"] is True)
        check("记录名正确", v.json()["record_name"] == "_acme-challenge.host1.acme.test")

        print("test_idempotent_same_content_no_extension")
        time.sleep(1.05)
        r2 = client.post("/api/v1/challenges", headers=HEADERS, json=payload)
        check("同 ID 同内容重试被受理（200/201）", r2.status_code in (200, 201))
        check("同内容重试不延期", r2.json()["expires_at"] == first_expiry)
        check("重试不改变 version", r2.json()["version"] == client.get(
            "/api/v1/challenges/app1").json()["version"])

        print("test_same_id_different_content_conflict")
        r = client.post("/api/v1/challenges", headers=HEADERS, json={
            "application_id": "app1", "domain": "host1.acme.test",
            "txt_value": "TXT-CHANGED", "ttl_seconds": 120})
        check("异内容重试 409", r.status_code == 409)

        print("test_coexist_and_cancel")
        client.post("/api/v1/challenges", headers=HEADERS, json={
            "application_id": "app2", "domain": "host1.acme.test",
            "txt_value": "TXT-2", "ttl_seconds": 120})
        wait_for(lambda: client.get("/api/v1/challenges/app2").json()["status"] == "ready",
                 "app2 ready")
        rec = "_acme-challenge.host1.acme.test"
        vals = set(client.get("/api/v1/challenges/app1/verify").json()["live_txt_values"])
        check("两个申请的 TXT 共存", {"TXT-1", "TXT-2"}.issubset(vals), str(vals))
        t0 = time.monotonic()
        r = client.post("/api/v1/challenges/app2/cancel", headers=HEADERS, json={})
        check("取消立即返回（不被网络阻塞）", r.status_code == 200 and time.monotonic() - t0 < 0.2)
        wait_for(lambda: client.get("/api/v1/challenges/app2").json()["status"] == "withdrawn",
                 "app2 withdrawn")
        def txt2_gone() -> bool:
            live = set(client.get("/api/v1/challenges/app1/verify").json()["live_txt_values"])
            return "TXT-2" not in live
        wait_for(txt2_gone, "TXT-2 removed from DNS")
        vals = set(client.get("/api/v1/challenges/app1/verify").json()["live_txt_values"])
        check("取消后仅删除本申请值，另一个保留",
              "TXT-2" not in vals and "TXT-1" in vals, str(vals))
        check("其它申请（Bearer 用例 VB）的 TXT 不受影响", "VB" in vals)
        check("终态再取消幂等",
              client.post("/api/v1/challenges/app2/cancel", headers=HEADERS).status_code == 200)
        check("取消不存在申请 404",
              client.post("/api/v1/challenges/nope/cancel", headers=HEADERS).status_code == 404)
        check("查询不存在申请 404",
              client.get("/api/v1/challenges/nope").status_code == 404)

        print("test_list_and_fault_switches")
        r = client.get("/api/v1/challenges")
        check("列表接口返回多条", r.json()["total"] >= 3)
        r = client.post("/api/v1/admin/faults", headers=HEADERS,
                        json={"lost_receipt": 1, "delay_seconds": 0.3})
        check("设置故障开关 200", r.status_code == 200)
        check("回显丢回执模式", r.json()["lost_receipt"] == 1)
        g = client.get("/api/v1/admin/faults")
        check("读取故障开关持久化", g.json()["lost_receipt"] == 1 and g.json()["delay_seconds"] == 0.3)
        # 无密钥不能改故障开关
        check("故障开关也要密钥",
              client.post("/api/v1/admin/faults", json={"lost_receipt": 0}).status_code == 401)
        # 复位
        client.post("/api/v1/admin/faults", headers=HEADERS,
                    json={"lost_receipt": 0, "delay_seconds": 0})

        print("test_lost_receipt_then_reconcile_via_api")
        client.post("/api/v1/admin/faults", headers=HEADERS, json={"lost_receipt": 1})
        client.post("/api/v1/challenges", headers=HEADERS, json={
            "application_id": "app3", "domain": "host1.acme.test",
            "txt_value": "TXT-3", "ttl_seconds": 120})
        # 等 worker 至少处理一次（DNS 已写、回执丢弃）
        time.sleep(1.5)
        check("DNS 实际已写入 TXT-3", "TXT-3" in fake.values(rec))
        client.post("/api/v1/admin/faults", headers=HEADERS, json={"lost_receipt": 0})
        wait_for(lambda: client.get("/api/v1/challenges/app3").json()["status"] == "ready",
                 "app3 reconcile ready", timeout=12.0)
        check("丢回执后经重查续办恢复 ready",
              client.get("/api/v1/challenges/app3").json()["status"] == "ready")

    finally:
        worker.request_stop()
        thread.join(timeout=3)
        fake.stop()
        store.close()

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        return 1
    print("全部 API 集成测试通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
