import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.audit import AuditStore
from app.authz import Authorizer
from app.config import Settings, load_settings
from app.errors import AccessDeniedError
from app.models import Resource
from app.rate_limit import RateLimiter
from app.routes import create_router
from app.session_store import SessionStore
from app.tracing import (
    TraceMiddleware,
    error_envelope,
    trace_id_of,
    unhandled_exception_handler,
)

DEFAULT_RESOURCES = {
    "doc-1": Resource(resource_id="doc-1", owner="alice", required_scope="doc:read"),
    "doc-2": Resource(resource_id="doc-2", owner="bob", required_scope="doc:read"),
}


def create_app(
    ttl_seconds: float | None = None,
    max_failures: int | None = None,
    lockout_seconds: float | None = None,
    audit_capacity: int | None = None,
    resources: dict[str, Resource] | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """应用工厂：便于测试用不同 TTL/限流参数构造实例。

    显式传入的参数优先；未传入的取 settings（缺省为环境变量配置，
    环境变量也未设置时保持既有默认行为）。
    """
    cfg = settings or load_settings()
    ttl = ttl_seconds if ttl_seconds is not None else cfg.session_ttl_seconds
    max_fail = max_failures if max_failures is not None else cfg.max_failures
    lockout = lockout_seconds if lockout_seconds is not None else cfg.lockout_seconds
    capacity = audit_capacity if audit_capacity is not None else cfg.audit_capacity

    app = FastAPI(title="session-access-control")
    store = SessionStore(ttl_seconds=ttl)
    authorizer = Authorizer(resources if resources is not None else DEFAULT_RESOURCES)
    limiter = RateLimiter(max_failures=max_fail, lockout_seconds=lockout)
    audit = AuditStore(capacity=capacity)

    app.add_middleware(TraceMiddleware)

    @app.exception_handler(AccessDeniedError)
    async def access_denied_handler(request: Request, exc: AccessDeniedError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(trace_id_of(request), exc.reason.value, exc.detail),
        )

    app.add_exception_handler(Exception, unhandled_exception_handler)

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    app.include_router(create_router(store, authorizer, limiter, audit))
    app.state.store = store
    app.state.limiter = limiter
    app.state.audit = audit
    app.state.settings = cfg
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
