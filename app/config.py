"""运行配置：全部来自环境变量，12-factor 风格。

API 进程与独立的 worker 进程共享同一份环境变量与同一个 SQLite 数据库，
worker 独占对权威 DNS 的写操作，API 只读写数据库，保证网络等待不会阻塞取消。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    raw = _env(name, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_csv(name: str, default: list[str]) -> list[str]:
    raw = _env(name, "")
    if not raw:
        return list(default)
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _env_float(name: str, default: float) -> float:
    raw = _env(name, "")
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # 管理密钥：所有写接口必须携带（X-Management-Key 或 Authorization: Bearer）
    management_key: str = field(default_factory=lambda: _env("MANAGEMENT_KEY", "dev-management-key"))

    # SQLite 数据库路径（API 与 worker 共享；compose 中位于命名卷）
    database_path: str = field(default_factory=lambda: _env("DATABASE_PATH", "/data/challenges.db"))

    # 域名白名单（小写、逗号分隔）。支持精确域与通配符 "*.example.com"
    allowed_domains: list[str] = field(
        default_factory=lambda: _env_csv("ALLOWED_DOMAINS", ["acme.test", "*.acme.test"])
    )

    # 有效期边界（秒）
    min_ttl_seconds: int = field(default_factory=lambda: _env_int("MIN_TTL_SECONDS", 30))
    max_ttl_seconds: int = field(default_factory=lambda: _env_int("MAX_TTL_SECONDS", 300))

    # 权威 DNS（TSIG 动态更新目标）
    dns_server: str = field(default_factory=lambda: _env("DNS_SERVER", "bind"))
    dns_port: int = field(default_factory=lambda: _env_int("DNS_PORT", 53))
    tsig_key_name: str = field(default_factory=lambda: _env("TSIG_KEY_NAME", "acme-key."))
    tsig_secret: str = field(
        default_factory=lambda: _env(
            "TSIG_SECRET",
            "CSK3OtjVklBJ0yPyeDrLpOfBypbMLSITQNqNv17GEJ0=",
        )
    )
    tsig_algorithm: str = field(default_factory=lambda: _env("TSIG_ALGORITHM", "hmac-sha256"))
    dns_update_timeout: float = field(
        default_factory=lambda: _env_float("DNS_UPDATE_TIMEOUT", 5.0)
    )
    dns_query_timeout: float = field(
        default_factory=lambda: _env_float("DNS_QUERY_TIMEOUT", 4.0)
    )

    # worker 轮询节奏
    worker_poll_interval: float = field(
        default_factory=lambda: _env_float("WORKER_POLL_INTERVAL", 1.0)
    )
    # 发布就绪确认：单次查询之间的间隔
    ready_poll_interval: float = field(
        default_factory=lambda: _env_float("READY_POLL_INTERVAL", 1.0)
    )
    # 单次发布/撤回阶段内最多查询多少次（有界，防止无限等待；失败后整体自动重试）
    ready_poll_max: int = field(default_factory=lambda: _env_int("READY_POLL_MAX", 5))
    # 失败任务自动重试的基础退避（秒），实际间隔随失败次数指数增长并封顶
    retry_base_delay: float = field(default_factory=lambda: _env_float("RETRY_BASE_DELAY", 2.0))
    retry_max_delay: float = field(default_factory=lambda: _env_float("RETRY_MAX_DELAY", 30.0))

    # 故障注入开关（也可在运行期经 /admin/faults 覆盖，覆盖值存数据库）
    # 0=关；1=更新已被 DNS 接受但丢弃回执（不写库，模拟回执丢失）；
    # 2=在 1 的基础上直接退出进程（模拟进程崩溃，验证重启续办）
    fault_lost_receipt: int = field(default_factory=lambda: _env_int("FAULT_LOST_RECEIPT", 0))
    # DNS 调用前额外睡眠的秒数（模拟权威 DNS 延迟回复），0 表示关闭
    fault_delay_seconds: float = field(
        default_factory=lambda: _env_float("FAULT_DELAY_SECONDS", 0.0)
    )

    def domain_allowed(self, domain: str) -> bool:
        """组件感知的白名单匹配：精确域或 ``*.suffix`` 通配。"""
        target = domain.strip(".").lower()
        for pattern in self.allowed_domains:
            p = pattern.strip(".").lower()
            if p.startswith("*."):
                suffix = p[1:]  # ".acme.test"
                if target.endswith(suffix) and target != suffix[1:]:
                    return True
            elif target == p:
                return True
        return False


def get_settings() -> Settings:
    return Settings()
