"""独立后台 worker：独占 DNS 写入，负责发布、就绪确认、到期/取消撤回与重启续办。

并发模型
========
* API 进程只读写数据库并立即返回；所有 DNS 网络等待都发生在这个独立进程，
  因此“网络等待不得阻塞取消”：取消请求只在数据库里翻转状态，worker 在每次
  网络调用前后都核对版本号，迟到结果无法复活已取消/到期的申请。
* 每个申请带单调 ``version``：worker 认领时记录期望版本，DNS 调用返回后若版本
  已变化（被取消、到期、重启重新认领），本次结果一律丢弃。

崩溃/回执丢失
==============
* ``lost_receipt=1``：DNS 已接受 TSIG 更新，但 worker 故意不写发布注册表/状态
  （回执丢失）。下一轮或重启后经“重查续办”发现值已在 DNS，补登记并继续。
* ``lost_receipt=2``：在 1 的基础上直接 ``os._exit`` 模拟进程崩溃；
  容器 restart 策略拉起后由启动对账续办。

撤回安全
========
只删除“本模块发布且已无有效申请引用”的精确 RDATA；同名其它 TXT 一律保留。
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from .config import Settings, get_settings
from .dns_client import DnsClient, DnsError
from .domain import now_ts, retry_delay, zone_of
from .store import (
    STATUS_PENDING,
    STATUS_PUBLISHING,
    STATUS_READY,
    Store,
)

LOG = logging.getLogger("acme.worker")

FAULT_LOST_KEY = "fault_lost_receipt"
FAULT_DELAY_KEY = "fault_delay_seconds"


class DnsChallengeWorker:
    def __init__(self, settings: Settings | None = None,
                 store: Store | None = None,
                 dns: DnsClient | None = None):
        self.settings = settings or get_settings()
        self.store = store or Store(self.settings.database_path)
        self.dns = dns or DnsClient(
            server=self.settings.dns_server,
            port=self.settings.dns_port,
            tsig_key_name=self.settings.tsig_key_name,
            tsig_secret=self.settings.tsig_secret,
            tsig_algorithm=self.settings.tsig_algorithm,
            update_timeout=self.settings.dns_update_timeout,
            query_timeout=self.settings.dns_query_timeout,
        )
        self._stop = threading.Event()
        self._tick = 0

    # ------------------------------------------------------------------ #
    # 故障注入开关（数据库覆盖优先于环境变量，支持运行期切换）
    # ------------------------------------------------------------------ #
    def fault_settings(self) -> tuple[int, float]:
        cfg = self.store.get_fault_settings(
            {
                FAULT_LOST_KEY: self.settings.fault_lost_receipt,
                FAULT_DELAY_KEY: self.settings.fault_delay_seconds,
            }
        )
        return int(cfg[FAULT_LOST_KEY]), float(cfg[FAULT_DELAY_KEY])

    def _interruptible_sleep(self, seconds: float) -> None:
        """可被停止信号立即唤醒的睡眠。"""
        self._stop.wait(timeout=max(0.0, seconds))

    # ------------------------------------------------------------------ #
    # 启动对账 / 重查续办
    # ------------------------------------------------------------------ #
    def reconcile(self) -> None:
        """重启（或周期性）对账：重查 DNS，补齐丢失回执，清理孤儿发布。"""
        LOG.info("开始对账（重查续办）")
        lost, delay = self.fault_settings()
        # 1) 重查所有非终态申请，依据 DNS 实况纠正状态/注册表
        for row in self.store.non_terminal_applications():
            app_id = row["id"]
            record_name = row["record_name"]
            txt_value = row["txt_value"]
            try:
                present = self.dns.txt_present(record_name, txt_value,
                                               delay_seconds=delay)
            except DnsError as exc:
                LOG.warning("对账查询失败 app=%s: %s", app_id, exc)
                continue
            if present:
                # DNS 已更新但回执丢失/进程退出：补登记发布注册表
                if not self.store.publication_exists(record_name, txt_value):
                    self.store.record_publication(record_name, txt_value, app_id)
                    LOG.info("续办：补登记已发布值 app=%s", app_id)
                # 值已在权威 DNS 生效：无论此前停在 pending（丢回执）还是
                # publishing（崩溃），都直接补确认到 ready（版本号防迟到复活）
                if row["status"] in (STATUS_PUBLISHING, STATUS_PENDING):
                    if self.store.mark_ready(app_id, row["version"]):
                        LOG.info("续办：依据 DNS 实况补确认 ready app=%s", app_id)
                    else:
                        LOG.info("续办：申请已变更，跳过补确认 app=%s", app_id)
            else:
                # DNS 里没有该值
                if self.store.publication_exists(record_name, txt_value):
                    # 注册表说发过但 DNS 没有：以 DNS 实况为准，移除孤儿登记，
                    # 交回正常流程按当前状态重试
                    self.store.remove_publication(record_name, txt_value)
                    LOG.warning("续办：注册表孤儿已清理 app=%s", app_id)
                if row["status"] == STATUS_READY:
                    # ready 但值消失（外部清理或未同步）：退回发布重试
                    self._requeue_publish(row, "就绪值在 DNS 中缺失，重新发布")
        # 2) 注册表中的孤儿（已无任何申请引用）：尝试安全撤回
        self._reap_orphan_publications(delay)
        LOG.info("对账完成")

    def _reap_orphan_publications(self, delay: float) -> None:
        for pub in self.store.all_publications():
            record_name = pub["record_name"]
            txt_value = pub["txt_value"]
            if self.store.value_still_referenced(record_name, txt_value):
                continue
            try:
                present = self.dns.txt_present(record_name, txt_value,
                                               delay_seconds=delay)
            except DnsError as exc:
                LOG.warning("孤儿清理查询失败 %s: %s", record_name, exc)
                continue
            if not present:
                self.store.remove_publication(record_name, txt_value)
                continue
            try:
                self.dns.delete_txt(zone_of(record_name), record_name, txt_value,
                                    delay_seconds=delay)
                self._confirm_removed(record_name, txt_value, delay)
                self.store.remove_publication(record_name, txt_value)
                LOG.info("孤儿 TXT 已撤回 %s", record_name)
            except DnsError as exc:
                LOG.warning("孤儿撤回失败 %s: %s", record_name, exc)

    # ------------------------------------------------------------------ #
    # 发布
    # ------------------------------------------------------------------ #
    def process_publish(self) -> bool:
        row = self.store.claim_due_publish()
        if not row:
            return False
        app_id = row["id"]
        expected_version = row["version"]  # claim 已 +1
        record_name = row["record_name"]
        txt_value = row["txt_value"]
        zone = zone_of(record_name)
        lost, delay = self.fault_settings()
        LOG.info("发布申请 app=%s record=%s version=%s", app_id, record_name,
                 expected_version)
        try:
            already = self.dns.txt_present(record_name, txt_value,
                                           delay_seconds=delay)
            if not already:
                self.dns.add_txt(zone, record_name, txt_value,
                                 ttl=row["ttl_seconds"], delay_seconds=delay)
                # DNS 已接受更新。故障注入：丢回执 / 崩溃
                if lost in (1, 2):
                    LOG.warning("故障注入 lost_receipt=%s：丢弃发布回执 app=%s",
                                lost, app_id)
                    if lost == 2:
                        LOG.error("故障注入：模拟进程退出（重启后将重查续办）")
                        os._exit(70)
                    # 模式 1：本轮不写库，等下一轮/重启对账补登记
                    self._requeue_for_reconcile(row)
                    return True
            # 正常路径：登记发布（幂等 upsert）
            self.store.record_publication(record_name, txt_value, app_id)
            if self._await_ready(app_id, expected_version, record_name,
                                 txt_value, delay):
                return True
            # 有界轮询内未查到：保留待办、记录原因、自动重试
            self._fail_with_retry(
                row, expected_version,
                f"更新已发送但在 {self.settings.ready_poll_max} 次查询内未确认就绪",
            )
        except DnsError as exc:
            self._fail_with_retry(row, expected_version, f"发布失败: {exc}")
        return True

    def _requeue_for_reconcile(self, row) -> None:
        """丢回执后把申请退回 pending，下一轮由重查续办补齐。"""
        retry_at = now_ts() + 1
        with self.store.tx() as conn:
            conn.execute(
                "UPDATE applications SET status=?, next_retry_at=?, "
                "last_error=? WHERE id=? AND version=?",
                (STATUS_PENDING, retry_at,
                 "DNS 已接受更新但回执丢失，等待重查续办", row["id"], row["version"]),
            )

    def _await_ready(self, app_id: str, expected_version: int,
                     record_name: str, txt_value: str, delay: float) -> bool:
        """有界轮询直到查到本值；期间若版本变化（取消/到期）立即停止。"""
        for attempt in range(1, self.settings.ready_poll_max + 1):
            if self._stop.is_set():
                return False
            fresh = self.store.get_application(app_id)
            if fresh is None or fresh["version"] != expected_version:
                LOG.info("发布期间申请状态已变更，放弃本次结果 app=%s", app_id)
                return False
            try:
                values = self.dns.query_txt(record_name, delay_seconds=delay)
            except DnsError as exc:
                LOG.warning("就绪查询出错 app=%s: %s", app_id, exc)
                values = []
            if txt_value in values:
                if self.store.mark_ready(app_id, expected_version):
                    LOG.info("申请就绪 app=%s（同名共存 %d 个 TXT）",
                             app_id, len(values))
                    return True
                return False
            if attempt < self.settings.ready_poll_max:
                self._interruptible_sleep(self.settings.ready_poll_interval)
        return False

    # ------------------------------------------------------------------ #
    # 撤回
    # ------------------------------------------------------------------ #
    def process_withdraw(self) -> bool:
        row = self.store.claim_due_withdraw()
        if not row:
            return False
        app_id = row["id"]
        expected_version = row["version"]
        record_name = row["record_name"]
        txt_value = row["txt_value"]
        zone = zone_of(record_name)
        _, delay = self.fault_settings()
        LOG.info("撤回申请 app=%s record=%s version=%s", app_id, record_name,
                 expected_version)
        try:
            # 仅处理本模块发布过的值；他人 TXT 永不触碰
            if not self.store.publication_exists(record_name, txt_value):
                LOG.info("本模块未发布该值，直接结束 app=%s", app_id)
                self.store.mark_terminal_withdrawn(app_id, expected_version)
                return True
            # 仍被其它有效申请引用 -> 保留 TXT，本申请结束（排除自身，
            # 撤回中的自己不算有效引用）
            if self.store.value_still_referenced(record_name, txt_value,
                                                 exclude_app_id=app_id):
                LOG.info("值仍被其它有效申请引用，保留 TXT app=%s", app_id)
                self.store.mark_terminal_withdrawn(app_id, expected_version)
                return True
            # 重查 DNS：可能已被外部移除
            present = self.dns.txt_present(record_name, txt_value,
                                           delay_seconds=delay)
            if present:
                self.dns.delete_txt(zone, record_name, txt_value,
                                    delay_seconds=delay)
                self._confirm_removed(record_name, txt_value, delay)
            # 确认撤回完成才移除登记并终态
            self.store.remove_publication(record_name, txt_value)
            if self.store.mark_terminal_withdrawn(app_id, expected_version):
                LOG.info("申请撤回完成 app=%s", app_id)
            return True
        except DnsError as exc:
            self._fail_with_retry(row, expected_version, f"撤回失败: {exc}")
            return True

    def _confirm_removed(self, record_name: str, txt_value: str,
                         delay: float) -> None:
        """结束前必须确认本值已撤回（有界轮询），失败抛 DnsError 触发重试。"""
        for attempt in range(1, self.settings.ready_poll_max + 1):
            values = self.dns.query_txt(record_name, delay_seconds=delay)
            if txt_value not in values:
                return
            if attempt < self.settings.ready_poll_max:
                self._interruptible_sleep(self.settings.ready_poll_interval)
        raise DnsError(f"删除后仍能查到本值 {record_name}")

    # ------------------------------------------------------------------ #
    # 失败与重试
    # ------------------------------------------------------------------ #
    def _fail_with_retry(self, row, expected_version: int, error: str) -> None:
        attempts = row["attempts"] + 1
        delay = retry_delay(attempts, self.settings.retry_base_delay,
                            self.settings.retry_max_delay)
        retry_at = now_ts() + int(delay)
        ok = self.store.mark_failed(row["id"], expected_version, error, retry_at)
        if ok:
            LOG.warning("保留待办并安排自动重试 app=%s 第%d次: %s",
                        row["id"], attempts, error)
        else:
            LOG.info("失败结果因状态已变更被丢弃 app=%s", row["id"])

    def _requeue_publish(self, row, reason: str) -> None:
        with self.store.tx() as conn:
            conn.execute(
                "UPDATE applications SET status=?, next_retry_at=?, last_error=? "
                "WHERE id=?",
                (STATUS_PENDING, now_ts(), reason, row["id"]),
            )

    # ------------------------------------------------------------------ #
    # 主循环
    # ------------------------------------------------------------------ #
    def request_stop(self, *_args) -> None:
        LOG.info("收到停止信号，等待当前网络步骤结束后退出")
        self._stop.set()

    def run(self) -> None:
        # 信号只能在主线程注册（测试中 worker 可能运行于子线程）
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, self.request_stop)
            signal.signal(signal.SIGINT, self.request_stop)
        # stdin 关闭也触发停止：仅在显式开启时启用（无信号权限的测试环境）。
        # 生产容器中 stdin 常为 /dev/null（立即 EOF），默认不能启用，避免误退出；
        # 容器内优雅停止由上面的 SIGTERM 处理器负责。
        stdin_thread: threading.Thread | None = None
        if (
            os.environ.get("DNS01_STDIN_SHUTDOWN") == "1"
            and threading.current_thread() is threading.main_thread()
            and not sys.stdin.closed
        ):
            def _watch_stdin() -> None:
                try:
                    sys.stdin.read()
                except Exception:
                    pass
                self._stop.set()

            stdin_thread = threading.Thread(target=_watch_stdin, daemon=True)
            stdin_thread.start()
        LOG.info("worker 启动 dns=%s:%s db=%s", self.settings.dns_server,
                 self.settings.dns_port, self.settings.database_path)
        self.reconcile()
        reconcile_every = max(1, int(30 / max(0.1, self.settings.worker_poll_interval)))
        while not self._stop.is_set():
            self._tick += 1
            try:
                # 1) 到期翻转（网络等待不影响：仅数据库操作）
                self.store.due_expirations()
                # 2) 发布、撤回各处理一个；网络步骤内部可被停止信号打断睡眠
                self.process_publish()
                if self._stop.is_set():
                    break
                self.process_withdraw()
                # 3) 周期性重查续办
                if self._tick % reconcile_every == 0:
                    self.reconcile()
            except Exception:
                LOG.exception("worker 循环异常，将在下个周期继续")
            self._interruptible_sleep(self.settings.worker_poll_interval)
        LOG.info("worker 已停止")


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    DnsChallengeWorker().run()


if __name__ == "__main__":
    main()
