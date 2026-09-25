import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.authz import Authorizer
from app.errors import AccessDeniedError
from app.models import Resource
from app.rate_limit import RateLimiter
from app.routes import create_router
from app.session_store import SessionStore

DEFAULT_RESOURCES = {
    "doc-1": Resource(resource_id="doc-1", owner="alice", required_scope="doc:read"),
    "doc-2": Resource(resource_id="doc-2", owner="bob", required_scope="doc:read"),
}


def create_app(
    ttl_seconds: float = 3600.0,
    max_failures: int = 5,
    lockout_seconds: float = 30.0,
    resources: dict[str, Resource] | None = None,
) -> FastAPI:
    """应用工厂：便于测试用不同 TTL/限流参数构造实例。"""
    app = FastAPI(title="session-access-control")
    store = SessionStore(ttl_seconds=ttl_seconds)
    authorizer = Authorizer(resources if resources is not None else DEFAULT_RESOURCES)
    limiter = RateLimiter(max_failures=max_failures, lockout_seconds=lockout_seconds)

    @app.exception_handler(AccessDeniedError)
    async def access_denied_handler(request: Request, exc: AccessDeniedError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.reason.value, "detail": exc.detail},
        )

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    app.include_router(create_router(store, authorizer, limiter))
    app.state.store = store
    app.state.limiter = limiter
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
