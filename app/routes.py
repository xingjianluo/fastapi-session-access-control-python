"""FastAPI 路由：会话签发/轮换/撤销 + 受保护资源访问 + 审计/状态查询。

失败链路：限流检查 -> 凭据校验 -> 授权判定，任一环节失败都会
按来源计入限流器；成功访问清零该来源的失败计数。
每一次访问判定（无论放行或拒绝）都写入本地审计存储，可按条件查询。
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app.audit import AuditQuery, AuditStore
from app.authz import Authorizer
from app.errors import AccessDeniedError, RejectionReason
from app.models import Session
from app.rate_limit import RateLimiter
from app.session_store import SessionStore
from app.tracing import trace_id_of

log = logging.getLogger(__name__)


class IssueRequest(BaseModel):
    subject: str
    roles: list[str] = ["user"]
    scopes: list[str] = ["doc:read"]


class TokenRequest(BaseModel):
    token: str


def _source_of(request: Request) -> str:
    """限流来源标识：优先客户端 IP，缺省为 unknown。"""
    return request.client.host if request.client else "unknown"


def create_router(
    store: SessionStore,
    authorizer: Authorizer,
    limiter: RateLimiter,
    audit: AuditStore,
) -> APIRouter:
    router = APIRouter()

    def _audit(request: Request, **kwargs) -> None:
        """写一条审计记录：自动带上当前请求的 trace_id 与来源。"""
        audit.append(
            trace_id=trace_id_of(request),
            source=_source_of(request),
            **kwargs,
        )

    def get_session(request: Request) -> Session:
        """依赖：限流检查 -> 凭据校验。失败计入限流器并写审计。"""
        source = _source_of(request)
        if limiter.is_locked(source):
            log.info("来源=%s 判定=锁定中 结果=拒绝", source)
            _audit(request, action="resource_access", outcome="denied",
                   reason=RejectionReason.RATE_LIMITED.value, detail="来源锁定中")
            raise AccessDeniedError(RejectionReason.RATE_LIMITED, 429, "失败次数过多，来源已被临时锁定")
        token = request.headers.get("X-Session-Token", "")
        try:
            session = store.validate(token)
        except AccessDeniedError as exc:
            locked = limiter.record_failure(source)
            log.info("来源=%s 判定=凭据拒绝(%s) 结果=计入失败 locked=%s", source, exc.reason.value, locked)
            _audit(request, action="resource_access", outcome="denied",
                   reason=exc.reason.value, detail=f"locked={locked}")
            raise
        return session

    @router.post("/sessions", status_code=201)
    def issue_session(body: IssueRequest, request: Request):
        session = store.issue(body.subject, set(body.roles), set(body.scopes))
        _audit(request, subject=session.subject, action="issue",
               outcome="allowed", reason="issued")
        return {
            "session_id": session.session_id,
            "token": session.token,
            "subject": session.subject,
            "expires_at": session.expires_at,
        }

    @router.post("/sessions/rotate")
    def rotate_session(body: TokenRequest, request: Request):
        source = _source_of(request)
        if limiter.is_locked(source):
            _audit(request, action="rotate", outcome="denied",
                   reason=RejectionReason.RATE_LIMITED.value, detail="来源锁定中")
            raise AccessDeniedError(RejectionReason.RATE_LIMITED, 429, "失败次数过多，来源已被临时锁定")
        try:
            session = store.rotate(body.token)
        except AccessDeniedError as exc:
            limiter.record_failure(source)
            _audit(request, action="rotate", outcome="denied", reason=exc.reason.value)
            raise
        _audit(request, subject=session.subject, action="rotate",
               outcome="allowed", reason="rotated")
        return {
            "session_id": session.session_id,
            "token": session.token,
            "subject": session.subject,
            "expires_at": session.expires_at,
        }

    @router.post("/sessions/revoke", status_code=204)
    def revoke_session(body: TokenRequest, request: Request):
        store.revoke(body.token)
        _audit(request, action="revoke", outcome="allowed", reason="revoked")
        return None

    @router.get("/resources/{resource_id}")
    def get_resource(resource_id: str, request: Request, session: Session = Depends(get_session)):
        source = _source_of(request)
        decision = authorizer.decide(session, resource_id)
        if not decision.allowed:
            locked = limiter.record_failure(source)
            log.info("来源=%s 判定=授权拒绝(%s) 结果=计入失败 locked=%s", source, decision.reason, locked)
            _audit(request, subject=decision.subject, action="resource_access",
                   resource_id=resource_id, outcome="denied", reason=decision.reason,
                   detail=f"matched_scope={decision.matched_scope} matched_owner={decision.matched_owner} locked={locked}")
            reason = RejectionReason(decision.reason)
            # 越权与不存在使用相同状态码与结构，避免泄露资源是否存在
            status = 404 if reason == RejectionReason.RESOURCE_NOT_FOUND else 403
            raise AccessDeniedError(reason, status, f"subject={decision.subject} resource={resource_id}")
        limiter.record_success(source)
        _audit(request, subject=decision.subject, action="resource_access",
               resource_id=resource_id, outcome="allowed", reason="allowed",
               detail=f"matched_scope={decision.matched_scope} matched_owner={decision.matched_owner}")
        resource = authorizer.get_resource(resource_id)
        return {
            "resource_id": resource.resource_id,
            "owner": resource.owner,
            "subject": session.subject,
        }

    @router.get("/audit")
    def query_audit(
        start_ts: float | None = Query(default=None),
        end_ts: float | None = Query(default=None),
        subject: str | None = Query(default=None),
        outcome: str | None = Query(default=None),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=1000),
    ):
        """本地审计查询：按时间范围/主体/结果筛选，分页返回。"""
        page = audit.query(AuditQuery(
            start_ts=start_ts, end_ts=end_ts, subject=subject,
            outcome=outcome, offset=offset, limit=limit,
        ))
        return {"total": page.total, "records": [asdict(r) for r in page.records]}

    @router.get("/status")
    def get_status(request: Request, source: str | None = Query(default=None)):
        """只读运行状态：来源锁定情况、有效会话数、审计存储占用。不暴露凭据。"""
        src = source or _source_of(request)
        locked_until = limiter.locked_until(src)
        return {
            "source": src,
            "locked": locked_until is not None,
            "locked_until": locked_until,
            "active_sessions": store.active_count(),
            "audit": audit.stats(),
        }

    return router
