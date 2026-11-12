"""DNS-01 挑战托管 API。

单 API 进程 + 独立 worker 进程（见 ``app.worker``）。API 只读写 SQLite 并立即
返回，所有 DNS 网络等待都在 worker 中进行，因此取消请求不会被网络阻塞。

端点
====
* ``POST /api/v1/challenges``           提交/幂等重试申请（管理密钥）
* ``POST /api/v1/challenges/{id}/cancel`` 取消申请（管理密钥）
* ``GET  /api/v1/challenges/{id}``      状态查询
* ``GET  /api/v1/challenges``           列出全部申请
* ``GET  /api/v1/challenges/{id}/verify`` DNS 核对接口（直查权威 DNS）
* ``POST /api/v1/admin/faults``         运行期故障开关（管理密钥）
* ``GET  /health``                      健康检查（保留的原核对类接口）
"""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import RedirectResponse

from . import __version__
from .config import Settings, get_settings
from .domain import DomainError, acme_challenge_name, content_hash, normalize_domain, now_ts
from .dns_client import DnsClient, DnsError
from .schemas import (
    CancelRequest,
    ChallengeCreateRequest,
    ChallengeListResponse,
    ChallengeResponse,
    FaultConfigRequest,
    FaultConfigResponse,
    HealthResponse,
    VerifyResponse,
)
from .store import STATUS_READY, Store
from .worker import FAULT_DELAY_KEY, FAULT_LOST_KEY

app = FastAPI(
    title="DNS-01 挑战托管 API",
    version=__version__,
    description=(
        "为并行证书签发托管 ACME DNS-01 挑战：凭管理密钥提交申请 ID、白名单域名、"
        "TXT 值与 30~300 秒有效期；worker 经 TSIG 动态更新固定权威 DNS 的 "
        "_acme-challenge TXT 记录，到期/取消自动撤回。支持多值共存、同 ID 幂等、"
        "丢回执/崩溃后的重启续办，以及就绪/撤回的 DNS 实况核对。"
    ),
)

_settings = get_settings()
_store = Store(_settings.database_path)


def get_store() -> Store:
    return _store


def get_app_settings() -> Settings:
    return _settings


def require_key(
    x_management_key: str | None = Header(default=None, alias="X-Management-Key"),
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_app_settings),
) -> None:
    """管理密钥校验：恒定时间比较，支持专用头或 Bearer 方案。"""
    presented = x_management_key
    if not presented and authorization:
        if authorization.lower().startswith("bearer "):
            presented = authorization.split(" ", 1)[1].strip()
    if not presented or not hmac.compare_digest(presented, settings.management_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="管理密钥缺失或错误（X-Management-Key 或 Authorization: Bearer）",
        )


def _row_to_response(row: Any) -> ChallengeResponse:
    d = dict(row)
    return ChallengeResponse(
        application_id=d["id"],
        domain=d["domain"],
        record_name=d["record_name"],
        txt_value=d["txt_value"],
        ttl_seconds=d["ttl_seconds"],
        status=d["status"],
        created_at=d["created_at"],
        expires_at=d["expires_at"],
        expired=bool(d["expired_flag"]) or d["expires_at"] <= now_ts(),
        version=d["version"],
        attempts=d["attempts"],
        last_error=d["last_error"],
        ready=d["status"] == STATUS_READY,
    )


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, tags=["meta"],
         summary="健康检查（原核对接口保留）")
def health(settings: Settings = Depends(get_app_settings),
           store: Store = Depends(get_store)) -> HealthResponse:
    db_state = "ok"
    try:
        store.get_config("__probe__")
    except Exception:  # pragma: no cover - 仅兜底
        db_state = "error"
    return HealthResponse(
        status="ok" if db_state == "ok" else "degraded",
        service="dns01-challenge-manager",
        version=__version__,
        database=db_state,
    )


@app.post(
    "/api/v1/challenges",
    response_model=ChallengeResponse,
    tags=["challenges"],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_key)],
    summary="提交 DNS-01 挑战申请（同 ID 同内容幂等不延期，异内容拒绝）",
    responses={
        401: {"description": "管理密钥缺失或错误"},
        403: {"description": "域名不在白名单"},
        409: {"description": "同 ID 异内容冲突"},
        422: {"description": "字段校验失败（TTL 越界、域名/TXT 非法）"},
    },
)
def create_challenge(req: ChallengeCreateRequest,
                     settings: Settings = Depends(get_app_settings),
                     store: Store = Depends(get_store)) -> ChallengeResponse:
    if not settings.domain_allowed(req.domain):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"域名 {req.domain} 不在白名单 {settings.allowed_domains} 内",
        )
    if not (settings.min_ttl_seconds <= req.ttl_seconds <= settings.max_ttl_seconds):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"ttl_seconds 必须在 [{settings.min_ttl_seconds},"
                f"{settings.max_ttl_seconds}] 秒之间"
            ),
        )
    try:
        domain = normalize_domain(req.domain)
        record_name = acme_challenge_name(domain)
    except DomainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    fingerprint = content_hash(domain, req.txt_value, req.ttl_seconds)
    created = store.insert_application(
        app_id=req.application_id,
        domain=domain,
        record_name=record_name,
        txt_value=req.txt_value,
        ttl_seconds=req.ttl_seconds,
        fingerprint=fingerprint,
        expires_at=now_ts() + req.ttl_seconds,
    )
    if not created:
        existing = store.get_application(req.application_id)
        assert existing is not None
        if existing["content_hash"] != fingerprint:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"申请 ID {req.application_id} 已存在但内容不同"
                    "（域名/TXT 值/TTL 不一致），异内容重试被拒绝；"
                    "同 ID 同内容重试不会延长有效期"
                ),
            )
        # 同 ID 同内容：幂等返回当前状态，明确不延期
        return _row_to_response(existing)
    row = store.get_application(req.application_id)
    assert row is not None
    return _row_to_response(row)


@app.post(
    "/api/v1/challenges/{application_id}/cancel",
    response_model=ChallengeResponse,
    tags=["challenges"],
    dependencies=[Depends(require_key)],
    summary="取消申请（仅翻转数据库状态，不被 DNS 网络等待阻塞）",
    responses={401: {"description": "管理密钥缺失或错误"},
               404: {"description": "申请不存在"}},
)
def cancel_challenge(application_id: str,
                     body: CancelRequest | None = None,
                     store: Store = Depends(get_store)) -> ChallengeResponse:
    accepted, state = store.request_cancel(application_id)
    if not accepted and state == "not_found":
        raise HTTPException(status_code=404, detail=f"申请 {application_id} 不存在")
    row = store.get_application(application_id)
    assert row is not None
    return _row_to_response(row)


@app.get(
    "/api/v1/challenges/{application_id}",
    response_model=ChallengeResponse,
    tags=["challenges"],
    summary="查询单个申请状态",
    responses={404: {"description": "申请不存在"}},
)
def get_challenge(application_id: str,
                  store: Store = Depends(get_store)) -> ChallengeResponse:
    row = store.get_application(application_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"申请 {application_id} 不存在")
    return _row_to_response(row)


@app.get(
    "/api/v1/challenges",
    response_model=ChallengeListResponse,
    tags=["challenges"],
    summary="列出全部申请（状态总览）",
)
def list_challenges(store: Store = Depends(get_store)) -> ChallengeListResponse:
    rows = store.list_applications()
    items = [_row_to_response(r) for r in rows]
    return ChallengeListResponse(items=items, total=len(items))


@app.get(
    "/api/v1/challenges/{application_id}/verify",
    response_model=VerifyResponse,
    tags=["verify"],
    summary="DNS 核对接口：直查权威 DNS，确认本 TXT 值是否真实生效",
    responses={404: {"description": "申请不存在"},
               502: {"description": "权威 DNS 查询失败"},
    },
)
def verify_challenge(application_id: str,
                     settings: Settings = Depends(get_app_settings),
                     store: Store = Depends(get_store)) -> VerifyResponse:
    row = store.get_application(application_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"申请 {application_id} 不存在")
    fault = store.get_fault_settings(
        {FAULT_LOST_KEY: settings.fault_lost_receipt,
         FAULT_DELAY_KEY: settings.fault_delay_seconds}
    )
    delay = float(fault[FAULT_DELAY_KEY])
    client = DnsClient(
        server=settings.dns_server,
        port=settings.dns_port,
        tsig_key_name=settings.tsig_key_name,
        tsig_secret=settings.tsig_secret,
        tsig_algorithm=settings.tsig_algorithm,
        update_timeout=settings.dns_update_timeout,
        query_timeout=settings.dns_query_timeout,
    )
    try:
        live = client.query_txt(row["record_name"], delay_seconds=delay)
    except DnsError as exc:
        raise HTTPException(status_code=502, detail=f"权威 DNS 查询失败: {exc}") from exc
    return VerifyResponse(
        application_id=row["id"],
        record_name=row["record_name"],
        txt_value=row["txt_value"],
        dns_present=row["txt_value"] in live,
        live_txt_values=live,
        application_status=row["status"],
        ready=row["status"] == STATUS_READY,
        published_by_this_module=store.publication_exists(
            row["record_name"], row["txt_value"]
        ),
    )


@app.post(
    "/api/v1/admin/faults",
    response_model=FaultConfigResponse,
    tags=["admin"],
    dependencies=[Depends(require_key)],
    summary="运行期故障开关：丢回执模式与 DNS 延迟回复（演示用）",
)
def set_faults(body: FaultConfigRequest,
               settings: Settings = Depends(get_app_settings),
               store: Store = Depends(get_store)) -> FaultConfigResponse:
    if body.lost_receipt is not None:
        store.set_config(FAULT_LOST_KEY, str(body.lost_receipt))
    if body.delay_seconds is not None:
        store.set_config(FAULT_DELAY_KEY, str(body.delay_seconds))
    lost = int(store.get_config(FAULT_LOST_KEY) or settings.fault_lost_receipt)
    delay = float(store.get_config(FAULT_DELAY_KEY) or settings.fault_delay_seconds)
    note = {
        0: "丢回执关闭",
        1: "DNS 接受更新但 worker 丢弃回执，下轮/重启重查续办",
        2: "丢回执并退出 worker 进程，依赖容器重启后续办",
    }[lost]
    return FaultConfigResponse(lost_receipt=lost, delay_seconds=delay, note=note)


@app.get(
    "/api/v1/admin/faults",
    response_model=FaultConfigResponse,
    tags=["admin"],
    summary="读取当前故障开关",
)
def get_faults(settings: Settings = Depends(get_app_settings),
               store: Store = Depends(get_store)) -> FaultConfigResponse:
    lost = int(store.get_config(FAULT_LOST_KEY) or settings.fault_lost_receipt)
    delay = float(store.get_config(FAULT_DELAY_KEY) or settings.fault_delay_seconds)
    note = {
        0: "丢回执关闭",
        1: "DNS 接受更新但 worker 丢弃回执，下轮/重启重查续办",
        2: "丢回执并退出 worker 进程，依赖容器重启后续办",
    }[lost]
    return FaultConfigResponse(lost_receipt=lost, delay_seconds=delay, note=note)
