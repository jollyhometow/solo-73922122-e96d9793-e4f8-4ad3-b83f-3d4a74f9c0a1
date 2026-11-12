"""持久层状态机与引用计数测试（仅标准库 + 项目模块，使用临时 SQLite）。

覆盖：同 ID 幂等不延期、异内容冲突由调用方判定、取消不阻塞、到期翻转、
版本号防迟到结果、多申请引用计数、孤儿注册表清理等关键不变量。

运行：python3 -I tests/test_store.py
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.domain import acme_challenge_name, content_hash, now_ts  # noqa: E402
from app.store import (  # noqa: E402
    STATUS_CANCELLED,
    STATUS_PENDING,
    STATUS_PUBLISHING,
    STATUS_READY,
    STATUS_WITHDRAWING,
    STATUS_WITHDRAWN,
    Store,
)

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok - {name}")
    else:
        failures.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")


def make_store() -> Store:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return Store(path)


def insert(store: Store, app_id: str, domain="host1.acme.test",
           value="VAL", ttl=120, expires_in=120) -> bool:
    return store.insert_application(
        app_id=app_id,
        domain=domain,
        record_name=acme_challenge_name(domain),
        txt_value=value,
        ttl_seconds=ttl,
        fingerprint=content_hash(domain, value, ttl),
        expires_at=now_ts() + expires_in,
    )


print("test_idempotent_insert")
store = make_store()
check("首次插入成功", insert(store, "a1"))
check("重复插入返回 False", insert(store, "a1") is False)
row = store.get_application("a1")
first_expiry = row["expires_at"]
time.sleep(1.05)
insert(store, "a1")
row2 = store.get_application("a1")
check("同 ID 重试不改变 expires_at（不延期）", row2["expires_at"] == first_expiry)
check("初始状态 pending", row2["status"] == STATUS_PENDING)

print("test_content_conflict_detection")
fp_same = content_hash("host1.acme.test", "VAL", 120)
fp_diff = content_hash("host1.acme.test", "VAL2", 120)
check("同内容指纹一致", row2["content_hash"] == fp_same)
check("异内容指纹可区分", fp_same != fp_diff)

print("test_claim_publish_and_version_guard")
claimed = store.claim_due_publish()
check("认领 pending 申请", claimed is not None and claimed["id"] == "a1")
check("认领后进入 publishing", store.get_application("a1")["status"] == STATUS_PUBLISHING)
v = store.get_application("a1")["version"]
check("无更多待发布", store.claim_due_publish() is None)
# 模拟迟到结果：版本已被取消/到期翻转 -> mark_ready 必须失败
store.request_cancel("a1")  # publishing -> withdrawing，version+1
check("迟到 ready 被版本号拒绝", store.mark_ready("a1", v) is False)
check("申请未被复活", store.get_application("a1")["status"] == STATUS_WITHDRAWING)

print("test_cancel_pending_is_terminal_and_nonblocking")
store = make_store()
insert(store, "c1")
t0 = time.monotonic()
accepted, state = store.request_cancel("c1")
elapsed = time.monotonic() - t0
check("取消 pending 被受理", accepted and state == STATUS_CANCELLED)
check("取消是纯数据库操作（<50ms）", elapsed < 0.05, f"elapsed={elapsed}")
check("终态不可再取消", store.request_cancel("c1") == (False, STATUS_CANCELLED))
check("不存在的申请取消返回 not_found",
      store.request_cancel("nope") == (False, "not_found"))

print("test_expiration_flips_active_to_withdrawing")
store = make_store()
insert(store, "e1", expires_in=120)
claimed = store.claim_due_publish()
store.mark_ready("e1", claimed["version"])
check("就绪后状态 ready", store.get_application("e1")["status"] == STATUS_READY)
# 手工把到期时间调到过去
with store.tx() as conn:
    conn.execute("UPDATE applications SET expires_at=? WHERE id=?",
                 (now_ts() - 1, "e1"))
flipped = store.due_expirations()
check("到期申请被翻转", len(flipped) == 1 and flipped[0]["id"] == "e1")
r = store.get_application("e1")
check("到期进入 withdrawing 且置 expired 标记",
      r["status"] == STATUS_WITHDRAWING and r["expired_flag"] == 1)
check("到期翻转幂等（不重复）", len(store.due_expirations()) == 0)

print("test_reference_counting_coexistence")
store = make_store()
insert(store, "x1", value="SHARED")
insert(store, "x2", value="SHARED")     # 不同申请、同记录同值
insert(store, "x3", value="UNIQUE")
rec = acme_challenge_name("host1.acme.test")
store.record_publication(rec, "SHARED", "x1")
store.record_publication(rec, "UNIQUE", "x3")
check("注册表 upsert 幂等", len(store.all_publications()) == 2)
check("共享值仍被有效申请引用", store.value_still_referenced(rec, "SHARED"))
# x1 到期撤回，但 x2 仍有效 -> 值必须保留
with store.tx() as conn:
    conn.execute("UPDATE applications SET expires_at=? WHERE id=?",
                 (now_ts() - 1, "x1"))
store.due_expirations()
check("x1 撤回中", store.get_application("x1")["status"] == STATUS_WITHDRAWING)
check("共享值仍被 x2 引用", store.value_still_referenced(rec, "SHARED"))
check("唯一值被其所属有效申请 x3 引用", store.value_still_referenced(rec, "UNIQUE"))
check("无申请引用的值判定为 False", not store.value_still_referenced(rec, "NEVER"))
# x2 也到期后，共享值不再被引用
with store.tx() as conn:
    conn.execute("UPDATE applications SET expires_at=? WHERE id=?",
                 (now_ts() - 1, "x2"))
store.due_expirations()
check("x2 到期后共享值无引用", not store.value_still_referenced(rec, "SHARED"))

print("test_withdraw_terminal_and_failed_retry")
store = make_store()
insert(store, "w1")
claimed = store.claim_due_publish()
store.record_publication(rec, "VAL", "w1")
store.mark_ready("w1", claimed["version"])
with store.tx() as conn:
    conn.execute("UPDATE applications SET expires_at=? WHERE id=?",
                 (now_ts() - 1, "w1"))
store.due_expirations()
wrow = store.claim_due_withdraw()
check("认领撤回任务", wrow is not None and wrow["id"] == "w1")
wv = wrow["version"]
# 模拟撤回失败：保留待办 + 原因 + 退避重试时间
ok = store.mark_failed("w1", wv, "撤回失败: timeout", now_ts() + 5)
check("失败被记录并安排重试", ok)
r = store.get_application("w1")
check("失败后退回 withdrawing 待认领", r["status"] == STATUS_WITHDRAWING)
check("失败原因可见", "timeout" in (r["last_error"] or ""))
check("attempts 累加", r["attempts"] == 1)
check("重试时间在未来", r["next_retry_at"] > now_ts())
# 再次认领并成功终态
wrow2 = store.claim_due_withdraw()
check("退避时间未到不认领", wrow2 is None)
with store.tx() as conn:
    conn.execute("UPDATE applications SET next_retry_at=0 WHERE id=?", ("w1",))
wrow2 = store.claim_due_withdraw()
check("退避过后可再次认领", wrow2 is not None)
check("终态撤回成功", store.mark_terminal_withdrawn("w1", wrow2["version"]))
check("状态 withdrawn", store.get_application("w1")["status"] == STATUS_WITHDRAWN)

print("test_fault_config_override")
store = make_store()
check("未设置时读取默认", store.get_fault_settings({"k1": 0, "k2": 0.0}) == {"k1": 0, "k2": 0.0})
store.set_config("k1", "2")
cfg = store.get_fault_settings({"k1": 0, "k2": 0.0})
check("数据库覆盖默认且保留类型", cfg == {"k1": 2, "k2": 0.0})

print()
if failures:
    print(f"{len(failures)} 项失败")
    sys.exit(1)
print("全部持久层状态机测试通过")
