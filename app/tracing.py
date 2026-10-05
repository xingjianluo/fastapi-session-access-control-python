"""请求追踪：为每个请求分配稳定追踪标识，贯穿成功/失败/异常响应。"""

from __future__ import annotations

import contextvars
import uuid

TRACE_HEADER = "X-Trace-Id"

# 当前请求的追踪标识（中间件设置，路由/异常处理器读取）
_current_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "trace_id", default=""
)


def new_trace_id() -> str:
    """生成新的追踪标识。"""
    return uuid.uuid4().hex


def current_trace_id() -> str:
    """读取当前请求的追踪标识；无上下文时返回空串。"""
    return _current_trace_id.get()


def set_trace_id(trace_id: str) -> None:
    """设置当前请求的追踪标识。"""
    _current_trace_id.set(trace_id)


def resolve_trace_id(incoming: str | None) -> str:
    """决定本次请求的追踪标识：优先采用请求方传入的合法值，否则新生成。"""
    if incoming and incoming.strip():
        return incoming.strip()
    return new_trace_id()
