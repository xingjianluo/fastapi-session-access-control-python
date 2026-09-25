"""会话与授权领域模型（进程内状态）。"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field


def _new_token() -> str:
    return uuid.uuid4().hex


@dataclass
class Session:
    """一条会话记录。token 即凭据；轮换时生成新 Session 并把旧的标记为 rotated。"""

    session_id: str
    subject: str                 # 用户标识
    roles: frozenset[str]        # 角色集合，如 {"user", "admin"}
    scopes: frozenset[str]       # 作用域集合，如 {"doc:read", "doc:write"}
    token: str = field(default_factory=_new_token)
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    revoked: bool = False
    rotated_to: str | None = None  # 若已被轮换，指向新 session_id

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at


@dataclass
class Resource:
    """受保护资源，带归属者。"""

    resource_id: str
    owner: str
    required_scope: str  # 访问该资源所需作用域


@dataclass
class AuthzDecision:
    """一次授权判定的可复现依据。"""

    allowed: bool
    reason: str
    subject: str
    resource_id: str
    matched_scope: bool
    matched_owner: bool
