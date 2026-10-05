import json
import logging

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.audit import AuditLog
from app.authz import Authorizer
from app.config import Settings, load_settings
from app.errors import AccessDeniedError, RejectionReason
from app.models import Resource
from app.rate_limit import RateLimiter
from app.routes import create_ops_router, create_router
from app.session_store import SessionStore
from app.tracing import TRACE_HEADER, current_trace_id, resolve_trace_id, set_trace_id

log = logging.getLogger(__name__)

DEFAULT_RESOURCES = {
    "doc-1": Resource(resource_id="doc-1", owner="alice", required_scope="doc:read"),
    "doc-2": Resource(resource_id="doc-2", owner="bob", required_scope="doc:read"),
}


class TraceMiddleware:
    """纯 ASGI 中间件：为每个请求解析/生成追踪标识。

    - 标识写入 contextvar，路由与异常处理器中可通过 current_trace_id() 读取；
    - 所有响应（成功/拒绝/异常）都带 X-Trace-Id 响应头；
    - 与下游应用在同一任务中执行，contextvar 天然向下游传播。
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = None
        for name, value in scope.get("headers", []):
            if name.lower() == TRACE_HEADER.lower().encode():
                incoming = value.decode()
                break
        trace_id = resolve_trace_id(incoming)
        set_trace_id(trace_id)

        async def send_with_trace(message):
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                headers.append((TRACE_HEADER.lower().encode(), trace_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_with_trace)
        except Exception:
            # 未预期异常：统一 500 结构兜底（不暴露堆栈与内部细节），
            # 堆栈只进服务端日志，并挂到同一 trace_id 下可查。
            # 必须在中间件内捕获：FastAPI 的 Exception 处理器运行在更外层，
            # 拿不到本请求的 contextvar，也无法补 X-Trace-Id 响应头。
            log.exception("未预期异常 trace_id=%s path=%s", trace_id, scope.get("path", ""))
            body = json.dumps({
                "error": RejectionReason.INTERNAL_ERROR.value,
                "detail": "服务内部错误",
                "trace_id": trace_id,
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"application/json"),
                    (TRACE_HEADER.lower().encode(), trace_id.encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})


def _error_body(reason: RejectionReason, detail: str) -> dict:
    """统一错误响应结构：所有拒绝分支与兜底异常同构。"""
    return {"error": reason.value, "detail": detail, "trace_id": current_trace_id()}


def create_app(
    ttl_seconds: float | None = None,
    max_failures: int | None = None,
    lockout_seconds: float | None = None,
    audit_capacity: int | None = None,
    resources: dict[str, Resource] | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """应用工厂：便于测试用不同 TTL/限流/审计参数构造实例。

    参数优先级：显式入参 > settings（默认取自环境变量）> 内置默认值。
    全部缺省时行为与既有版本一致。
    """
    cfg = settings if settings is not None else load_settings()
    ttl = ttl_seconds if ttl_seconds is not None else cfg.ttl_seconds
    max_fail = max_failures if max_failures is not None else cfg.max_failures
    lockout = lockout_seconds if lockout_seconds is not None else cfg.lockout_seconds
    capacity = audit_capacity if audit_capacity is not None else cfg.audit_capacity

    app = FastAPI(title="session-access-control")
    store = SessionStore(ttl_seconds=ttl)
    authorizer = Authorizer(resources if resources is not None else DEFAULT_RESOURCES)
    limiter = RateLimiter(max_failures=max_fail, lockout_seconds=lockout)
    audit = AuditLog(capacity=capacity)

    @app.exception_handler(AccessDeniedError)
    async def access_denied_handler(request: Request, exc: AccessDeniedError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.reason, exc.detail),
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        # 未预期异常：统一结构兜底，不暴露堆栈与内部细节；堆栈只进服务端日志并挂到同一 trace_id
        log.exception("未预期异常 trace_id=%s path=%s", current_trace_id(), request.url.path)
        return JSONResponse(
            status_code=500,
            content=_error_body(RejectionReason.INTERNAL_ERROR, "服务内部错误"),
        )

    app.add_middleware(TraceMiddleware)

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    app.include_router(create_router(store, authorizer, limiter, audit))
    app.include_router(create_ops_router(store, limiter, audit))
    app.state.store = store
    app.state.limiter = limiter
    app.state.audit = audit
    app.state.settings = Settings(
        ttl_seconds=ttl, max_failures=max_fail,
        lockout_seconds=lockout, audit_capacity=capacity,
    )
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
