"""领域工具：域名规范化、_acme-challenge 记录名、内容指纹、时间与退避。

纯标准库，便于在无第三方依赖的离线环境下单测。
"""

from __future__ import annotations

import hashlib
import re
import time

# 域名标签：字母数字开头/结尾，中间可含连字符；总长 <=253，单标签 <=63。
# 放行下划线：_acme-challenge、_tcp 等 DNS 记录名合法含下划线（实践中广泛使用）。
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$|^[a-z0-9_]$")


class DomainError(ValueError):
    """域名或 TXT 值不合法。"""


def normalize_domain(raw: str) -> str:
    """规范化为不带尾点的小写域名，并做结构校验。"""
    if not isinstance(raw, str) or not raw.strip():
        raise DomainError("域名必须是非空字符串")
    domain = raw.strip().strip(".").lower()
    # 去掉 IDN 之外的非法字符风险；先按长度与标签结构校验
    if len(domain) > 253:
        raise DomainError(f"域名过长（>253 字符）: {raw!r}")
    labels = domain.split(".")
    if len(labels) < 2:
        raise DomainError(f"域名至少需要两级标签: {raw!r}")
    for label in labels:
        if not _LABEL.match(label):
            raise DomainError(f"非法域名标签 {label!r}（仅允许小写字母、数字、连字符）")
    return domain


def acme_challenge_name(domain: str) -> str:
    """返回该域名对应的 _acme-challenge 完整记录名（不带尾点）。"""
    base = normalize_domain(domain)
    return f"_acme-challenge.{base}"


def zone_of(domain: str) -> str:
    """取域名的最右两级作为动态更新区域名（演示用固定策略）。"""
    base = normalize_domain(domain)
    parts = base.split(".")
    return ".".join(parts[-2:])


def validate_txt_value(raw: str) -> str:
    """校验 ACME TXT 值：通常为 base64url，长度 1..255（单条 TXT RDATA 上限）。"""
    if not isinstance(raw, str) or not raw:
        raise DomainError("TXT 值必须是非空字符串")
    value = raw.strip()
    if len(value) > 255:
        raise DomainError("单条 TXT 值长度不能超过 255 字符")
    if not re.fullmatch(r"[A-Za-z0-9_=./+-]+", value):
        raise DomainError("TXT 值含非法字符（期望 base64url 风格的 ACME 令牌）")
    return value


def content_hash(domain: str, txt_value: str, ttl_seconds: int) -> str:
    """同 ID 重试是否“同内容”的判定指纹（域名 + TXT 值 + TTL）。"""
    digest = hashlib.sha256()
    digest.update(normalize_domain(domain).encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(validate_txt_value(txt_value).encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(str(int(ttl_seconds)).encode("ascii"))
    return digest.hexdigest()


def now_ts() -> int:
    return int(time.time())


def monotonic() -> float:
    return time.monotonic()


def retry_delay(attempts: int, base: float, cap: float) -> float:
    """指数退避：base * 2^(attempts-1)，封顶 cap。"""
    if attempts <= 0:
        return 0.0
    return min(cap, base * (2 ** (attempts - 1)))
