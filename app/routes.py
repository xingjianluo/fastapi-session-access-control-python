"""FastAPI 路由：会话签发/轮换/撤销 + 受保护资源访问。

失败链路：限流检查 -> 凭据校验 -> 授权判定，任一环节失败都会
按来源计入限流器；成功访问清零该来源的失败计数。
每一次判定（放行或拒绝）都会写入本地审计日志，并携带当前请求的追踪标识。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.audit import AuditLog
from app.authz import Authorizer
from app.errors import AccessDeniedError, RejectionReason
from app.models import Session
from app.rate_limit import RateLimiter
from app.session_store import SessionStore
from app.tracing import current_trace_id

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
    audit: AuditLog,
) -> APIRouter:
    router = APIRouter()

    def get_session(request: Request) -> Session:
        """依赖：限流检查 -> 凭据校验。失败计入限流器并写审计。"""
        source = _source_of(request)
        if limiter.is_locked(source):
            log.info("来源=%s 判定=锁定中 结果=拒绝", source)
            audit.record(
                trace_id=current_trace_id(),
                source=source,
                action="resource:read",
                outcome=RejectionReason.RATE_LIMITED.value,
                detail="来源处于锁定期",
            )
            raise AccessDeniedError(RejectionReason.RATE_LIMITED, 429, "失败次数过多，来源已被临时锁定")
        token = request.headers.get("X-Session-Token", "")
        try:
            session = store.validate(token)
        except AccessDeniedError as exc:
            locked = limiter.record_failure(source)
            log.info("来源=%s 判定=凭据拒绝(%s) 结果=计入失败 locked=%s", source, exc.reason.value, locked)
            audit.record(
                trace_id=current_trace_id(),
                source=source,
                action="resource:read",
                outcome=exc.reason.value,
                detail=f"凭据校验失败 locked={locked}",
            )
            raise
        return session

    @router.post("/sessions", status_code=201)
    def issue_session(body: IssueRequest, request: Request):
        session = store.issue(body.subject, set(body.roles), set(body.scopes))
        audit.record(
            trace_id=current_trace_id(),
            source=_source_of(request),
            subject=session.subject,
            action="session:issue",
            outcome="allowed",
            detail=f"session_id={session.session_id}",
        )
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
            audit.record(
                trace_id=current_trace_id(),
                source=source,
                action="session:rotate",
                outcome=RejectionReason.RATE_LIMITED.value,
                detail="来源处于锁定期",
            )
            raise AccessDeniedError(RejectionReason.RATE_LIMITED, 429, "失败次数过多，来源已被临时锁定")
        try:
            session = store.rotate(body.token)
        except AccessDeniedError as exc:
            locked = limiter.record_failure(source)
            audit.record(
                trace_id=current_trace_id(),
                source=source,
                action="session:rotate",
                outcome=exc.reason.value,
                detail=f"轮换失败 locked={locked}",
            )
            raise
        audit.record(
            trace_id=current_trace_id(),
            source=source,
            subject=session.subject,
            action="session:rotate",
            outcome="allowed",
            detail=f"session_id={session.session_id}",
        )
        return {
            "session_id": session.session_id,
            "token": session.token,
            "subject": session.subject,
            "expires_at": session.expires_at,
        }

    @router.post("/sessions/revoke", status_code=204)
    def revoke_session(body: TokenRequest, request: Request):
        store.revoke(body.token)
        audit.record(
            trace_id=current_trace_id(),
            source=_source_of(request),
            action="session:revoke",
            outcome="allowed",
        )
        return None

    @router.get("/resources/{resource_id}")
    def get_resource(resource_id: str, request: Request, session: Session = Depends(get_session)):
        source = _source_of(request)
        try:
            resource = authorizer.authorize(session, resource_id)
        except AccessDeniedError as exc:
            locked = limiter.record_failure(source)
            log.info("来源=%s 判定=授权拒绝(%s) 结果=计入失败 locked=%s", source, exc.reason.value, locked)
            audit.record(
                trace_id=current_trace_id(),
                source=source,
                subject=session.subject,
                action="resource:read",
                resource_id=resource_id,
                outcome=exc.reason.value,
                detail=f"授权拒绝 locked={locked}",
            )
            raise
        limiter.record_success(source)
        audit.record(
            trace_id=current_trace_id(),
            source=source,
            subject=session.subject,
            action="resource:read",
            resource_id=resource_id,
            outcome="allowed",
            detail="作用域与归属均满足",
        )
        return {
            "resource_id": resource.resource_id,
            "owner": resource.owner,
            "subject": session.subject,
        }

    return router


def create_ops_router(store: SessionStore, limiter: RateLimiter, audit: AuditLog) -> APIRouter:
    """只读运维端点：审计查询 + 运行状态观测。不暴露任何凭据。"""
    from app.audit import AuditQuery

    router = APIRouter()

    @router.get("/ops/audit")
    def query_audit(
        since: float | None = None,
        until: float | None = None,
        subject: str | None = None,
        outcome: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ):
        page = audit.query(AuditQuery(
            since=since, until=until, subject=subject, outcome=outcome,
            offset=offset, limit=min(limit, 500),
        ))
        return {
            "total": page.total,
            "offset": page.offset,
            "limit": page.limit,
            "records": [
                {
                    "seq": r.seq,
                    "trace_id": r.trace_id,
                    "timestamp": r.timestamp,
                    "source": r.source,
                    "subject": r.subject,
                    "action": r.action,
                    "resource_id": r.resource_id,
                    "outcome": r.outcome,
                    "detail": r.detail,
                }
                for r in page.records
            ],
        }

    @router.get("/ops/status")
    def get_status(source: str | None = None):
        """运行状态：指定来源的锁定情况、有效会话数、审计存储占用。"""
        lock_info = None
        if source is not None:
            lock_info = {
                "source": source,
                "locked": limiter.is_locked(source),
                "locked_until": limiter.locked_until(source),
            }
        return {
            "lock": lock_info,
            "active_sessions": store.active_count(),
            "audit": audit.stats(),
        }

    return router
