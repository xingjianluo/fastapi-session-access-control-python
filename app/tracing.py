"""请求追踪：为每个请求分配稳定追踪标识，统一异常响应结构。

- 每个进入服务的请求（无论成功、拒绝还是未预期异常）都分配一个 trace_id，
  通过响应头 X-Trace-Id 返回；错误响应体中也携带 trace_id，结构各分支一致。
- 未预期异常由统一处理器兜底：对外只返回固定结构（不泄露堆栈/内部细节），
  完整堆栈连同 trace_id 记入服务端日志，可按标识回查。
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

log = logging.getLogger(__name__)

TRACE_HEADER = "X-Trace-Id"


def new_trace_id() -> str:
    """生成新的追踪标识。"""
    return uuid.uuid4().hex


def error_envelope(trace_id: str, error: str, detail: str) -> dict:
    """统一的错误响应结构：所有拒绝分支与内部异常兜底共用。"""
    return {"error": error, "detail": detail, "trace_id": trace_id}


class TraceMiddleware(BaseHTTPMiddleware):
    """为每个请求分配 trace_id，存入 request.state 并写入响应头。"""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        trace_id = new_trace_id()
        request.state.trace_id = trace_id
        response = await call_next(request)
        response.headers[TRACE_HEADER] = trace_id
        return response


def trace_id_of(request: Request) -> str:
    """取当前请求的 trace_id；中间件未生效时兜底生成。"""
    return getattr(request.state, "trace_id", None) or new_trace_id()


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """未预期异常兜底：对外固定结构，堆栈只进服务端日志并挂到同一 trace_id。

    该处理器由最外层 ServerErrorMiddleware 调用，响应不再经过 TraceMiddleware，
    因此这里显式补上追踪响应头，保证 500 分支也能拿到标识。
    """
    trace_id = trace_id_of(request)
    log.error("未预期异常 trace_id=%s path=%s", trace_id, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content=error_envelope(trace_id, "internal_error", "服务内部错误"),
        headers={TRACE_HEADER: trace_id},
    )
