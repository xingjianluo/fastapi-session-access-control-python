"""进程内凭据与会话存储（线程安全）。

仅使用本地内存，不持久化、不依赖外部服务。
所有变更都在同一把锁内完成，保证“检查-修改”操作的原子性，
从而支撑“同一凭据并发轮换只有一次成功”。
"""

import threading
import time
import secrets
from dataclasses import dataclass, field, replace


@dataclass
class Session:
    token: str
    subject: str
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()
    issued_at: float = 0.0
    expires_at: float = 0.0
    revoked: bool = False
    # 该凭据是否已被新凭据轮换取代
    superseded: bool = False
    # 轮换链：上一代凭据（便于审计追溯）
    previous_token: str | None = None
    # 该会话的当前有效凭据（轮换过程中只有一个胜出者）
    version: int = 0


def new_token() -> str:
    """生成不透明本地凭据（非真实生产凭据，仅用于本地验证）。"""
    return "tok_" + secrets.token_urlsafe(24)


class SessionStore:
    def __init__(self) -> None:
        # token -> Session
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def put(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.token] = session

    def get(self, token: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(token)
            return replace(session) if session is not None else None

    def update(self, token: str, **changes: object) -> Session | None:
        """在锁内读取并原子更新，返回更新后的副本；不存在返回 None。"""
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            updated = replace(session, **changes)
            self._sessions[token] = updated
            return replace(updated)

    def now(self) -> float:
        return time.time()
