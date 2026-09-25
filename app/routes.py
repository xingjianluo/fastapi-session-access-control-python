"""FastAPI 路由：会话签发/轮换/撤销 + 受保护资源访问。

失败链路：限流检查 -> 凭据校验 -> 授权判定，任一环节失败都会
按来源计入限流器；成功访问清零该来源的失败计数。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.authz import Authorizer
from app.errors import AccessDeniedError, RejectionReason
from app.models import Session
from app.rate_limit import RateLimiter
from app.session_store import SessionStore

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


def create_router(store: SessionStore, authorizer: Authorizer, limiter: RateLimiter) -> APIRouter:
    router = APIRouter()

    def get_session(request: Request) -> Session:
        """依赖：限流检查 -> 凭据校验。失败计入限流器。"""
        source = _source_of(request)
        if limiter.is_locked(source):
            log.info("来源=%s 判定=锁定中 结果=拒绝", source)
            raise AccessDeniedError(RejectionReason.RATE_LIMITED, 429, "失败次数过多，来源已被临时锁定")
        token = request.headers.get("X-Session-Token", "")
        try:
            session = store.validate(token)
        except AccessDeniedError as exc:
            locked = limiter.record_failure(source)
            log.info("来源=%s 判定=凭据拒绝(%s) 结果=计入失败 locked=%s", source, exc.reason.value, locked)
            raise
        return session

    @router.post("/sessions", status_code=201)
    def issue_session(body: IssueRequest):
        session = store.issue(body.subject, set(body.roles), set(body.scopes))
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
            raise AccessDeniedError(RejectionReason.RATE_LIMITED, 429, "失败次数过多，来源已被临时锁定")
        try:
            session = store.rotate(body.token)
        except AccessDeniedError:
            limiter.record_failure(source)
            raise
        return {
            "session_id": session.session_id,
            "token": session.token,
            "subject": session.subject,
            "expires_at": session.expires_at,
        }

    @router.post("/sessions/revoke", status_code=204)
    def revoke_session(body: TokenRequest):
        store.revoke(body.token)
        return None

    @router.get("/resources/{resource_id}")
    def get_resource(resource_id: str, request: Request, session: Session = Depends(get_session)):
        source = _source_of(request)
        try:
            resource = authorizer.authorize(session, resource_id)
        except AccessDeniedError as exc:
            locked = limiter.record_failure(source)
            log.info("来源=%s 判定=授权拒绝(%s) 结果=计入失败 locked=%s", source, exc.reason.value, locked)
            raise
        limiter.record_success(source)
        return {
            "resource_id": resource.resource_id,
            "owner": resource.owner,
            "subject": session.subject,
        }

    return router
