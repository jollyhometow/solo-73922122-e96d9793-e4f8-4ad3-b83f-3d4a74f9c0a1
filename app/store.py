"""SQLite 持久层：申请单、DNS 发布注册表、运行期故障开关。

设计要点
========
* API 与 worker 是两个独立进程，经 WAL 模式共享同一数据库；写操作都很短，
  配合 ``busy_timeout`` 避免互相阻塞。
* 申请单带单调递增的 ``version``：worker 每次拿到网络结果后都重新核对版本，
  迟到的结果（发布途中取消、到期、进程重启）无法把申请“复活”。
* ``dns_publications`` 只记录本模块真正发布到权威 DNS 的 (记录名, 值)，
  撤回时据此判断该值是否仍被其它有效申请引用，绝不误删他人 TXT。
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from .domain import now_ts

# 申请状态机
STATUS_PENDING = "pending"          # 已受理，等待 worker 发布
STATUS_PUBLISHING = "publishing"    # worker 正在发布（DNS 更新/就绪确认中）
STATUS_READY = "ready"              # 已在权威 DNS 查到本值，挑战可用
STATUS_WITHDRAWING = "withdrawing"  # 到期或取消，worker 正在撤回
STATUS_WITHDRAWN = "withdrawn"      # 终态：本值已确认撤回，或仍被其它有效申请引用
STATUS_CANCELLED = "cancelled"      # 终态：发布完成前被取消（DNS 侧无需处理或由注册表兜底）
STATUS_EXPIRED = "expired"          # 终态语义别名：到期且撤回完成（库里仍记 withdrawn + expired 标记）

ACTIVE_STATUSES = (STATUS_PENDING, STATUS_PUBLISHING, STATUS_READY, STATUS_WITHDRAWING)
# “有效申请”：仍需要该 TXT 值存在的状态。withdrawing（到期/取消中）不再算有效，
# 否则撤回中的申请会把自己的值误判为“仍被引用”而永不删除。
EFFECTIVE_STATUSES = (STATUS_PENDING, STATUS_PUBLISHING, STATUS_READY)
TERMINAL_STATUSES = (STATUS_WITHDRAWN, STATUS_CANCELLED)

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS applications (
    id              TEXT PRIMARY KEY,
    domain          TEXT NOT NULL,
    record_name     TEXT NOT NULL,
    txt_value       TEXT NOT NULL,
    ttl_seconds     INTEGER NOT NULL,
    content_hash    TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_retry_at   INTEGER NOT NULL DEFAULT 0,
    expired_flag    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_app_expires ON applications(expires_at);
CREATE INDEX IF NOT EXISTS idx_app_retry ON applications(next_retry_at);

CREATE TABLE IF NOT EXISTS dns_publications (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    record_name      TEXT NOT NULL,
    txt_value        TEXT NOT NULL,
    published_at     INTEGER NOT NULL,
    owner_app_id     TEXT NOT NULL,
    UNIQUE(record_name, txt_value)
);
CREATE INDEX IF NOT EXISTS idx_pub_lookup ON dns_publications(record_name, txt_value);

CREATE TABLE IF NOT EXISTS kv_config (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""


class Store:
    """每个进程持有一个 Store；连接设置 check_same_thread=False 并加锁串行化写入。"""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(f"PRAGMA busy_timeout={8000}")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        # autocommit 模式（isolation_level=None）下手动界定事务
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------ #
    # 申请单
    # ------------------------------------------------------------------ #
    def get_application(self, app_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM applications WHERE id=?", (app_id,)
            )
            return cur.fetchone()

    def insert_application(
        self,
        app_id: str,
        domain: str,
        record_name: str,
        txt_value: str,
        ttl_seconds: int,
        fingerprint: str,
        expires_at: int,
    ) -> bool:
        """返回 False 表示同 ID 已存在（调用方再做同内容/异内容判定）。"""
        with self.tx() as conn:
            exists = conn.execute(
                "SELECT 1 FROM applications WHERE id=?", (app_id,)
            ).fetchone()
            if exists:
                return False
            conn.execute(
                """INSERT INTO applications
                   (id, domain, record_name, txt_value, ttl_seconds, content_hash,
                    status, created_at, expires_at, version, attempts, next_retry_at)
                   VALUES (?,?,?,?,?,?,?,?,?,1,0,0)""",
                (
                    app_id, domain, record_name, txt_value, ttl_seconds, fingerprint,
                    STATUS_PENDING, now_ts(), expires_at,
                ),
            )
            return True

    def list_applications(self, limit: int = 200) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM applications ORDER BY created_at DESC, id ASC LIMIT ?",
                (limit,),
            )
            return cur.fetchall()

    def claim_due_publish(self) -> Optional[sqlite3.Row]:
        """认领一个到期待发布的申请（pending 且退避时间已到）。"""
        with self.tx() as conn:
            row = conn.execute(
                """SELECT * FROM applications
                   WHERE status=? AND next_retry_at<=?
                   ORDER BY created_at ASC, id ASC LIMIT 1""",
                (STATUS_PENDING, now_ts()),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE applications SET status=?, version=version+1 WHERE id=?",
                (STATUS_PUBLISHING, row["id"]),
            )
            return conn.execute(
                "SELECT * FROM applications WHERE id=?", (row["id"],)
            ).fetchone()

    def claim_due_withdraw(self) -> Optional[sqlite3.Row]:
        with self.tx() as conn:
            row = conn.execute(
                """SELECT * FROM applications
                   WHERE status=? AND next_retry_at<=?
                   ORDER BY expires_at ASC, id ASC LIMIT 1""",
                (STATUS_WITHDRAWING, now_ts()),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE applications SET version=version+1 WHERE id=?", (row["id"],)
            )
            return conn.execute(
                "SELECT * FROM applications WHERE id=?", (row["id"],)
            ).fetchone()

    def due_expirations(self) -> list[sqlite3.Row]:
        """把已到期但仍处于活动态（非撤回中/终态）的申请置为撤回中。"""
        flipped: list[sqlite3.Row] = []
        with self.tx() as conn:
            rows = conn.execute(
                """SELECT * FROM applications
                   WHERE expired_flag=0 AND expires_at<=?
                     AND status IN (?,?,?)""",
                (now_ts(), STATUS_PENDING, STATUS_PUBLISHING, STATUS_READY),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """UPDATE applications
                       SET status=?, expired_flag=1, version=version+1, next_retry_at=0
                       WHERE id=?""",
                    (STATUS_WITHDRAWING, row["id"]),
                )
                flipped.append(row)
        return flipped

    def request_cancel(self, app_id: str) -> tuple[bool, str]:
        """返回 (是否受理, 当前状态)。终态申请不可取消。"""
        with self.tx() as conn:
            row = conn.execute(
                "SELECT * FROM applications WHERE id=?", (app_id,)
            ).fetchone()
            if not row:
                return False, "not_found"
            status = row["status"]
            if status in TERMINAL_STATUSES:
                return False, status
            if status == STATUS_WITHDRAWING:
                # 已在撤回流程（到期或先前取消），幂等受理
                return True, status
            if status == STATUS_PENDING:
                # 尚未开始 DNS 操作：直接终态取消
                conn.execute(
                    "UPDATE applications SET status=?, version=version+1 WHERE id=?",
                    (STATUS_CANCELLED, app_id),
                )
                return True, STATUS_CANCELLED
            # publishing / ready：进入撤回，由 worker 清理 DNS
            conn.execute(
                "UPDATE applications SET status=?, version=version+1, next_retry_at=0 WHERE id=?",
                (STATUS_WITHDRAWING, app_id),
            )
            return True, STATUS_WITHDRAWING

    def mark_ready(self, app_id: str, expected_version: int) -> bool:
        """仅当版本未变（未被取消/到期）时才能置为 ready，防止迟到结果复活。

        接受 publishing（正常发布确认）与 pending（丢回执后由对账重查续办）。
        """
        with self.tx() as conn:
            row = conn.execute(
                "SELECT version, status FROM applications WHERE id=?", (app_id,)
            ).fetchone()
            if not row or row["version"] != expected_version:
                return False
            if row["status"] not in (STATUS_PUBLISHING, STATUS_PENDING):
                return False
            conn.execute(
                "UPDATE applications SET status=?, last_error=NULL WHERE id=?",
                (STATUS_READY, app_id),
            )
            return True

    def mark_terminal_withdrawn(self, app_id: str, expected_version: int) -> bool:
        with self.tx() as conn:
            row = conn.execute(
                "SELECT version, status FROM applications WHERE id=?", (app_id,)
            ).fetchone()
            if not row or row["version"] != expected_version:
                return False
            if row["status"] != STATUS_WITHDRAWING:
                return False
            conn.execute(
                "UPDATE applications SET status=? WHERE id=?",
                (STATUS_WITHDRAWN, app_id),
            )
            return True

    def mark_failed(self, app_id: str, expected_version: int, error: str,
                    retry_at: int) -> bool:
        """记录失败原因并安排自动重试；状态退回其阶段的起始可认领态。"""
        with self.tx() as conn:
            row = conn.execute(
                "SELECT version, status FROM applications WHERE id=?", (app_id,)
            ).fetchone()
            if not row or row["version"] != expected_version:
                return False
            fallback = (
                STATUS_PENDING if row["status"] == STATUS_PUBLISHING
                else STATUS_WITHDRAWING
            )
            conn.execute(
                """UPDATE applications
                   SET status=?, attempts=attempts+1, last_error=?, next_retry_at=?
                   WHERE id=?""",
                (fallback, error[:500], retry_at, app_id),
            )
            return True

    def active_applications(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM applications WHERE status IN (?,?,?,?)",
                ACTIVE_STATUSES,
            ).fetchall()

    def non_terminal_applications(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM applications WHERE status NOT IN (?,?)",
                TERMINAL_STATUSES,
            ).fetchall()

    # ------------------------------------------------------------------ #
    # DNS 发布注册表
    # ------------------------------------------------------------------ #
    def record_publication(self, record_name: str, txt_value: str,
                           owner_app_id: str) -> None:
        with self.tx() as conn:
            conn.execute(
                """INSERT INTO dns_publications(record_name, txt_value, published_at, owner_app_id)
                   VALUES (?,?,?,?)
                   ON CONFLICT(record_name, txt_value) DO UPDATE SET published_at=excluded.published_at""",
                (record_name, txt_value, now_ts(), owner_app_id),
            )

    def publication_exists(self, record_name: str, txt_value: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM dns_publications WHERE record_name=? AND txt_value=?",
                (record_name, txt_value),
            ).fetchone()
            return row is not None

    def value_still_referenced(self, record_name: str, txt_value: str,
                               exclude_app_id: str | None = None) -> bool:
        """该值是否仍被一条“有效申请”引用（pending/publishing/ready 且未到期）。

        撤回中的申请（withdrawing）不再算有效引用；可传 ``exclude_app_id``
        排除当前正在撤回的申请本身，避免自我引用导致永不删除。
        """
        with self._lock:
            if exclude_app_id is not None:
                row = self._conn.execute(
                    """SELECT 1 FROM applications
                       WHERE record_name=? AND txt_value=?
                         AND status IN (?,?,?) AND expires_at>?
                         AND id<>?
                       LIMIT 1""",
                    (record_name, txt_value, *EFFECTIVE_STATUSES, now_ts(),
                     exclude_app_id),
                ).fetchone()
            else:
                row = self._conn.execute(
                    """SELECT 1 FROM applications
                       WHERE record_name=? AND txt_value=?
                         AND status IN (?,?,?) AND expires_at>?
                       LIMIT 1""",
                    (record_name, txt_value, *EFFECTIVE_STATUSES, now_ts()),
                ).fetchone()
            return row is not None

    def remove_publication(self, record_name: str, txt_value: str) -> None:
        with self.tx() as conn:
            conn.execute(
                "DELETE FROM dns_publications WHERE record_name=? AND txt_value=?",
                (record_name, txt_value),
            )

    def all_publications(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM dns_publications ORDER BY published_at ASC"
            ).fetchall()

    # ------------------------------------------------------------------ #
    # 运行期故障开关（kv_config 覆盖环境变量默认值）
    # ------------------------------------------------------------------ #
    def get_config(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv_config WHERE key=?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def set_config(self, key: str, value: str) -> None:
        with self.tx() as conn:
            conn.execute(
                """INSERT INTO kv_config(key, value) VALUES(?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                (key, str(value)),
            )

    def get_fault_settings(self, defaults: dict[str, Any]) -> dict[str, Any]:
        result = dict(defaults)
        for key in defaults:
            stored = self.get_config(key)
            if stored is not None:
                result[key] = type(defaults[key])(stored)
        return result

    def row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)
