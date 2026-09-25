"""进程内会话存储：签发、轮换、撤销、校验。线程安全。"""

from __future__ import annotations

import threading
import time
import uuid

from app.errors import AccessDeniedError, RejectionReason
from app.models import Session


class SessionStore:
    """内存会话仓库。所有可变操作在同一把锁下完成，保证并发轮换仅一次成功。"""

    def __init__(self, ttl_seconds: float = 3600.0):
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._by_id: dict[str, Session] = {}
        self._by_token: dict[str, Session] = {}

    def issue(self, subject: str, roles: set[str], scopes: set[str]) -> Session:
        """签发新会话。"""
        now = time.time()
        session = Session(
            session_id=uuid.uuid4().hex,
            subject=subject,
            roles=frozenset(roles),
            scopes=frozenset(scopes),
            issued_at=now,
            expires_at=now + self._ttl,
        )
        with self._lock:
            self._by_id[session.session_id] = session
            self._by_token[session.token] = session
        return session

    def validate(self, token: str) -> Session:
        """校验凭据；未知/过期/撤销/已轮换分别抛出可区分原因。"""
        if not token:
            raise AccessDeniedError(RejectionReason.CREDENTIAL_MISSING, 401, "未提供会话凭据")
        with self._lock:
            session = self._by_token.get(token)
        if session is None:
            raise AccessDeniedError(RejectionReason.CREDENTIAL_UNKNOWN, 401, "凭据不存在")
        if session.revoked:
            raise AccessDeniedError(RejectionReason.CREDENTIAL_REVOKED, 401, "凭据已被撤销")
        if session.rotated_to is not None:
            raise AccessDeniedError(RejectionReason.CREDENTIAL_ROTATED, 401, "凭据已被轮换，请使用新凭据")
        if session.is_expired():
            raise AccessDeniedError(RejectionReason.CREDENTIAL_EXPIRED, 401, "凭据已过期")
        return session

    def rotate(self, old_token: str) -> Session:
        """轮换凭据：旧凭据失效，返回新会话。并发下仅一个调用成功。

        整个"校验旧凭据 + 标记轮换 + 登记新凭据"在同一把锁内完成，
        因此并发 rotate 中只有一个能看到旧凭据尚未轮换，其余调用
        会拿到 CREDENTIAL_ROTATED 拒绝，且不会获得任何新凭据。
        """
        now = time.time()
        with self._lock:
            old = self._by_token.get(old_token)
            if old is None:
                raise AccessDeniedError(RejectionReason.CREDENTIAL_UNKNOWN, 401, "凭据不存在")
            if old.revoked:
                raise AccessDeniedError(RejectionReason.CREDENTIAL_REVOKED, 401, "凭据已被撤销")
            if old.rotated_to is not None:
                raise AccessDeniedError(RejectionReason.CREDENTIAL_ROTATED, 401, "凭据已被轮换")
            if old.is_expired(now):
                raise AccessDeniedError(RejectionReason.CREDENTIAL_EXPIRED, 401, "凭据已过期")

            new_session = Session(
                session_id=uuid.uuid4().hex,
                subject=old.subject,
                roles=old.roles,
                scopes=old.scopes,
                issued_at=now,
                expires_at=now + self._ttl,
            )
            old.rotated_to = new_session.session_id
            self._by_id[new_session.session_id] = new_session
            self._by_token[new_session.token] = new_session
            return new_session

    def revoke(self, token: str) -> None:
        """撤销凭据。未知凭据视为幂等成功（不泄露存在性之外的语义差异由 validate 区分）。"""
        with self._lock:
            session = self._by_token.get(token)
            if session is not None:
                session.revoked = True
