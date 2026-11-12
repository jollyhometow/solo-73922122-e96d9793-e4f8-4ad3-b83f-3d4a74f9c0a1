"""领域工具与状态判定的纯标准库测试（无需第三方依赖）。

运行：python3 -I tests/test_domain.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.domain import (  # noqa: E402
    DomainError,
    acme_challenge_name,
    content_hash,
    normalize_domain,
    retry_delay,
    validate_txt_value,
    zone_of,
)
from app.config import Settings  # noqa: E402

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok - {name}")
    else:
        failures.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")


print("test_normalize_domain")
check("小写与去尾点", normalize_domain("Host1.ACME.TEST.") == "host1.acme.test")
check("多级域", normalize_domain("a.b.c.acme.test") == "a.b.c.acme.test")
for bad in ("", "  ", "singlelabel", "bad label.acme.test",
            "exclam!.acme.test", "-lead.acme.test", "trail-.acme.test"):
    try:
        normalize_domain(bad)
        check(f"拒绝非法域名 {bad!r}", False)
    except DomainError:
        check(f"拒绝非法域名 {bad!r}", True)

print("test_acme_challenge_name")
check(
    "挑战记录名",
    acme_challenge_name("host1.acme.test") == "_acme-challenge.host1.acme.test",
)
check("zone 取最右两级", zone_of("_acme-challenge.host1.acme.test") == "acme.test")

print("test_txt_value")
check("合法令牌", validate_txt_value("Abc123_-+./=") == "Abc123_-+./=")
for bad in ("", "has space", "bad$char", "x" * 256):
    try:
        validate_txt_value(bad)
        check(f"拒绝非法 TXT {bad[:8]!r}", False)
    except DomainError:
        check(f"拒绝非法 TXT {bad[:8]!r}", True)

print("test_content_hash")
h1 = content_hash("host1.acme.test", "VAL", 120)
h2 = content_hash("HOST1.acme.test.", "VAL", 120)
check("规范化后同内容同指纹", h1 == h2)
h3 = content_hash("host1.acme.test", "VAL", 121)
check("TTL 不同指纹不同", h1 != h3)
h4 = content_hash("host1.acme.test", "OTHER", 120)
check("TXT 不同指纹不同", h1 != h4)
h5 = content_hash("host2.acme.test", "VAL", 120)
check("域名不同指纹不同", h1 != h5)

print("test_retry_backoff")
check("首次退避为 base", retry_delay(1, 2.0, 30.0) == 2.0)
check("指数增长", retry_delay(3, 2.0, 30.0) == 8.0)
check("封顶", retry_delay(10, 2.0, 30.0) == 30.0)
check("零次不退避", retry_delay(0, 2.0, 30.0) == 0.0)

print("test_whitelist")
s = Settings(allowed_domains=["acme.test", "*.acme.test"])
check("精确命中", s.domain_allowed("acme.test"))
check("大小写命中", s.domain_allowed("HOST1.ACME.TEST"))
check("通配命中子域", s.domain_allowed("a.b.acme.test"))
check("拒绝外部域", not s.domain_allowed("evil.com"))
check("拒绝伪造后缀", not s.domain_allowed("acme.test.evil.com"))
check("拒绝通配根自身以外的拼接", not s.domain_allowed("notacme.test"))
s2 = Settings(allowed_domains=["only.acme.test"])
check("白名单精确不匹配子域", not s2.domain_allowed("other.acme.test"))

print()
if failures:
    print(f"{len(failures)} 项失败")
    sys.exit(1)
print("全部领域逻辑测试通过")
