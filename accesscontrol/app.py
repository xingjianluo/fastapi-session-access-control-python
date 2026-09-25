"""FastAPI 应用装配。

请求处理链路（受保护资源）：
  request_id 中间件
    -> 来源识别（X-Source-ID 或客户端 IP）
    -> 限流检查（锁定中则 429 source_locked）
    -> 凭据认证（缺失/过期/撤销/已轮换 -> 401，原因可区分）
    -> 授权判定（角色/作用域 + 资源归属，默认拒绝）
    -> 任一环节拒绝都计入该来源连续失败数；成功则清零

所有 AccessControlError 经统一异常处理器输出
{error: {request_id, reason, message}}，与审计记录一一对应。
"""

import logging
import time
import uuid
from collections.abc import Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from accesscontrol.audit import AuditLog, DecisionRecord
from accesscontrol.authz import Principal, Resource, ResourceRegistry, authorize
from accesscontrol.config import Settings, get_settings
from accesscontrol.errors import AccessControlError, Reason
from accesscontrol.ratelimit import RateLimiter
from accesscontrol.sessions import SessionService
from accesscontrol.store import Session, SessionStore

logger = logging.getLogger("accesscontrol")


class IssueRequest(BaseModel):
    subject: str
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)


class TokenRequest(BaseModel):
    token: str


def _seed_demo_resources(registry: ResourceRegistry) -> None:
    """本地演示资源（进程内），便于直接验证归属与作用域规则。"""
    registry.add(Resource("doc-alice", owner="alice", required_scope="doc:read"))
    registry.add(Resource("doc-bob", owner="bob", required_scope="doc:read"))
    registry.add(
        Resource(
            "doc-admin",
            owner="alice",
            required_role="admin",
            required_scope="doc:write",
        )
    )


def create_app(
    settings: Settings | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    settings = settings or get_settings()
    audit = AuditLog(capacity=settings.audit_capacity, logger=logger)
    store = SessionStore()
    sessions = SessionService(store, settings, audit, clock=clock)
    limiter = RateLimiter(settings, audit, clock=clock)
    resources = ResourceRegistry()
    _seed_demo_resources(resources)

    app = FastAPI(title="Session & Scope Access Control (local)")
    app.state.settings = settings
    app.state.audit = audit
    app.state.sessions = sessions
    app.state.limiter = limiter
    app.state.resources = resources
    app.state.clock = clock

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        request.state.source = request.headers.get(settings.source_header) or (
            request.client.host if request.client else "unknown"
        )
        try:
            response = await call_next(request)
        except Exception:  # 未预期异常也不泄露内部信息
            logger.exception("unhandled error request_id=%s", request.state.request_id)
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "request_id": request.state.request_id,
                        "reason": "internal_error",
                        "message": "服务器内部错误",
                    }
                },
            )
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(AccessControlError)
    async def access_control_error_handler(request: Request, exc: AccessControlError):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "request_id": request.state.request_id,
                    "reason": exc.reason.value,
                    "message": exc.message,
                }
            },
        )

    def _bearer(request: Request) -> str:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[len("Bearer ") :].strip()
        return ""

    def _deny_and_count(
        request: Request, exc: AccessControlError, stage_ok: bool
    ) -> None:
        # 认证/授权类失败计入连续失败；锁定拒绝本身不再累加
        if exc.reason != Reason.SOURCE_LOCKED:
            app.state.limiter.record_failure(
                request.state.source, request_id=request.state.request_id
            )

    def _authenticate(request: Request) -> Session:
        """限流检查 + 认证；失败抛出 AccessControlError 并登记失败计数。"""
        rid = request.state.request_id
        source = request.state.source
        app.state.limiter.check(source, request_id=rid)
        token = _bearer(request)
        try:
            session = app.state.sessions.authenticate(token, request_id=rid, source=source)
        except AccessControlError as exc:
            _deny_and_count(request, exc, False)
            raise
        app.state.limiter.record_success(source, request_id=rid)
        return session

    @app.post("/auth/sessions")
    async def issue_session(body: IssueRequest, request: Request):
        session = app.state.sessions.issue(
            body.subject,
            tuple(body.roles),
            tuple(body.scopes),
            request_id=request.state.request_id,
            source=request.state.source,
        )
        return {
            "token": session.token,
            "subject": session.subject,
            "roles": list(session.roles),
            "scopes": list(session.scopes),
            "issued_at": session.issued_at,
            "expires_at": session.expires_at,
            "version": session.version,
        }

    @app.post("/auth/rotate")
    async def rotate_session(request: Request):
        rid = request.state.request_id
        source = request.state.source
        app.state.limiter.check(source, request_id=rid)
        token = _bearer(request)
        try:
            session = app.state.sessions.rotate(token, request_id=rid, source=source)
        except AccessControlError as exc:
            _deny_and_count(request, exc, False)
            raise
        app.state.limiter.record_success(source, request_id=rid)
        return {
            "token": session.token,
            "subject": session.subject,
            "roles": list(session.roles),
            "scopes": list(session.scopes),
            "issued_at": session.issued_at,
            "expires_at": session.expires_at,
            "version": session.version,
            "previous_token_prefix": token[:8],
        }

    @app.post("/auth/revoke")
    async def revoke_session(body: TokenRequest | None = None, request: Request = None):  # type: ignore[assignment]
        rid = request.state.request_id
        source = request.state.source
        token = _bearer(request)
        if body is not None and body.token:
            token = body.token
        app.state.limiter.check(source, request_id=rid)
        ok = app.state.sessions.revoke(token, request_id=rid, source=source)
        if not ok:
            exc = AccessControlError(Reason.CREDENTIAL_UNKNOWN, "凭据不存在")
            _deny_and_count(request, exc, False)
            raise exc
        app.state.limiter.record_success(source, request_id=rid)
        return {"revoked": True, "token_prefix": token[:8]}

    @app.get("/resources/{resource_id}")
    async def read_resource(resource_id: str, request: Request):
        rid = request.state.request_id
        source = request.state.source
        session = _authenticate(request)
        principal = Principal.from_session(session)
        resource = app.state.resources.get(resource_id)
        try:
            resource = authorize(
                principal, resource, audit, request_id=rid, source=source, action="read"
            )
        except AccessControlError as exc:
            _deny_and_count(request, exc, False)
            raise
        return {
            "request_id": rid,
            "resource_id": resource.resource_id,
            "owner": resource.owner,
            "data": f"content-of-{resource.resource_id}",
        }

    @app.get("/_local/audit")
    async def read_audit(request: Request, request_id: str | None = None, source: str | None = None):
        """本地验证辅助：查看判定依据（不部署到真实环境）。"""
        records: list[DecisionRecord] = app.state.audit.all()
        if request_id is not None:
            records = [r for r in records if r.request_id == request_id]
        if source is not None:
            records = [r for r in records if r.source == source]
        return [
            {
                "request_id": r.request_id,
                "stage": r.stage,
                "source": r.source,
                "decision": r.decision.value,
                "reason": r.reason,
                "subject": r.subject,
                "action": r.action,
                "resource_id": r.resource_id,
                "evidence": r.evidence,
                "at": r.at,
            }
            for r in records
        ]

    @app.get("/_local/status/{source}")
    async def source_status(source: str):
        """本地验证辅助：查看来源连续失败计数与锁定状态。"""
        return app.state.limiter.status(source)

    return app


app = create_app()
