"""HTTP 层请求/响应模型（pydantic v2）。"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .domain import DomainError, normalize_domain, validate_txt_value


class ChallengeCreateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    application_id: str = Field(
        alias="application_id",
        min_length=1,
        max_length=128,
        description="申请 ID（调用方唯一标识）。同 ID 同内容重试不延期，异内容拒绝。",
        examples=["cert-2026-0001"],
    )
    domain: str = Field(
        min_length=3,
        max_length=253,
        description="白名单内的域名，例如 host1.acme.test；实际记录为 _acme-challenge.<domain>",
        examples=["host1.acme.test"],
    )
    txt_value: str = Field(
        min_length=1,
        max_length=255,
        description="要写入的 ACME TXT 值（base64url 令牌）",
        examples=["KwrTq74fJq8xQ1pV2mN3lK9aBcDeFgHiJkLmNoPqRsTu"],
    )
    ttl_seconds: int = Field(
        ge=30,
        le=300,
        description="有效期秒数，闭区间 [30, 300]",
        examples=[120],
    )

    @field_validator("application_id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("application_id 不能为空")
        if any(ch.isspace() for ch in cleaned):
            raise ValueError("application_id 不能含空白字符")
        return cleaned

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, value: str) -> str:
        try:
            return normalize_domain(value)
        except DomainError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("txt_value")
    @classmethod
    def _check_txt(cls, value: str) -> str:
        try:
            return validate_txt_value(value)
        except DomainError as exc:
            raise ValueError(str(exc)) from exc


class CancelRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    reason: Optional[str] = Field(
        default=None,
        max_length=300,
        description="可选取消原因，仅用于审计展示",
    )


class FaultConfigRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    lost_receipt: Optional[Literal[0, 1, 2]] = Field(
        default=None,
        description="0=关闭；1=DNS 已接受更新但丢弃回执（不写库）；2=在 1 基础上退出进程",
    )
    delay_seconds: Optional[float] = Field(
        default=None, ge=0.0, le=60.0, description="DNS 调用前延迟秒数（模拟延迟回复），0 关闭"
    )


class ChallengeResponse(BaseModel):
    application_id: str
    domain: str
    record_name: str
    txt_value: str
    ttl_seconds: int
    status: str = Field(description="pending/publishing/ready/withdrawing/withdrawn/cancelled")
    created_at: int
    expires_at: int
    expired: bool
    version: int
    attempts: int
    last_error: Optional[str] = None
    ready: bool = Field(description="是否已在权威 DNS 查到本值（status=ready）")


class ChallengeListResponse(BaseModel):
    items: list[ChallengeResponse]
    total: int


class VerifyResponse(BaseModel):
    application_id: str
    record_name: str
    txt_value: str
    dns_present: bool = Field(description="权威 DNS 当前是否能查到本 TXT 值")
    live_txt_values: list[str] = Field(description="该记录名下当前全部 TXT 值（含他方值）")
    application_status: str
    ready: bool
    published_by_this_module: bool = Field(
        description="本值是否在本模块的发布注册表中"
    )


class FaultConfigResponse(BaseModel):
    lost_receipt: int
    delay_seconds: float
    note: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
