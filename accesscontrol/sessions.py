"""凭据签发、轮换与失效。

拒绝原因可区分：unknown / revoked / expired / rotated。
并发轮换安全性：轮换过程在 SessionStore 的同一把锁内完成
“校验旧凭据 -> 旧凭据标记 superseded -> 写入新凭据”，
因此同一凭据的并发轮换恰好一次成功，失败方拿不到任何新凭据。
"""

import time
from collections.abc import Callable

from accesscontrol.audit import AuditLog, Decision, DecisionRecord
from accesscontrol.config import Settings
from accesscontrol.errors import AccessControlError, Reason
from accesscontrol.store import Session, SessionStore, new_token


class SessionService:
    def __init__(
        self,
        store: SessionStore,
        settings: Settings,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._settings = settings
        self._audit = audit
        self._clock = clock

    def _deny(
        self,
        request_id: str,
        source: str,
        stage: str,
        reason: Reason,
        message: str,
        evidence: dict,
        subject: str | None = None,
    ) -> AccessControlError:
        self._audit.record(
            DecisionRecord(
                request_id=request_id,
                stage=stage,
                source=source,
                decision=Decision.DENY,
                reason=reason.value,
                subject=subject,
                evidence=evidence,
            )
        )
        return AccessControlError(reason, message)

    def issue(
        self,
        subject: str,
        roles: tuple[str, ...] = (),
        scopes: tuple[str, ...] = (),
        *,
        request_id: str = "-",
        source: str = "-",
        previous_token: str | None = None,
    ) -> Session:
        now = self._clock()
        session = Session(
            token=new_token(),
            subject=subject,
            roles=tuple(roles),
            scopes=tuple(scopes),
            issued_at=now,
            expires_at=now + self._settings.session_ttl_seconds,
            previous_token=previous_token,
            version=1,
        )
        self._store.put(session)
        self._audit.record(
            DecisionRecord(
                request_id=request_id,
                stage="issue",
                source=source,
                decision=Decision.ALLOW,
                subject=subject,
                evidence={
                    "ttl_seconds": self._settings.session_ttl_seconds,
                    "issued_at": now,
                    "expires_at": session.expires_at,
                    "previous_token_present": previous_token is not None,
                },
            )
        )
        return session

    def _live_session_or_raise(
        self, token: str, *, request_id: str, source: str, stage: str
    ) -> Session:
        """返回有效会话，否则以可区分原因拒绝。"""
        session = self._store.get(token)
        now = self._clock()
        if session is None:
            raise self._deny(
                request_id, source, stage, Reason.CREDENTIAL_UNKNOWN,
                "凭据不存在", {"token_prefix": token[:8]},
            )
        evidence = {
            "subject": session.subject,
            "now": now,
            "expires_at": session.expires_at,
            "revoked": session.revoked,
            "superseded": session.superseded,
            "version": session.version,
        }
        # 原因优先级：撤销 > 过期 > 已轮换，保证每类失效可区分
        if session.revoked:
            raise self._deny(
                request_id, source, stage, Reason.CREDENTIAL_REVOKED,
                "凭据已被撤销", evidence, subject=session.subject,
            )
        if now >= session.expires_at:
            raise self._deny(
                request_id, source, stage, Reason.CREDENTIAL_EXPIRED,
                "凭据已过期", evidence, subject=session.subject,
            )
        if session.superseded:
            raise self._deny(
                request_id, source, stage, Reason.CREDENTIAL_ROTATED,
                "凭据已被轮换，请使用新凭据", evidence, subject=session.subject,
            )
        return session

    def authenticate(
        self, token: str, *, request_id: str = "-", source: str = "-"
    ) -> Session:
        if not token:
            raise self._deny(
                request_id, source, "authenticate", Reason.MISSING_CREDENTIAL,
                "缺少凭据", {},
            )
        session = self._live_session_or_raise(
            token, request_id=request_id, source=source, stage="authenticate"
        )
        self._audit.record(
            DecisionRecord(
                request_id=request_id,
                stage="authenticate",
                source=source,
                decision=Decision.ALLOW,
                subject=session.subject,
                evidence={"token_version": session.version, "expires_at": session.expires_at},
            )
        )
        return session

    def rotate(self, token: str, *, request_id: str = "-", source: str = "-") -> Session:
        """轮换凭据：原子地校验-作废-签发。并发调用恰好一次成功。"""
        if not token:
            raise self._deny(
                request_id, source, "rotate", Reason.MISSING_CREDENTIAL,
                "缺少凭据", {},
            )
        with self._store._lock:  # noqa: SLF001 - 校验与替换必须在同一临界区
            session = self._live_session_or_raise(
                token, request_id=request_id, source=source, stage="rotate"
            )
            # 旧凭据立即作废（原子更新在同一把锁内）
            self._store.update(token, superseded=True)
            rotated = self.issue(
                session.subject,
                session.roles,
                session.scopes,
                request_id=request_id,
                source=source,
                previous_token=token,
            )
            # 新版本号沿轮换链递增，便于复现轮换顺序；
            # 重新读取以返回更新后的对象（避免调用方拿到过期副本）
            self._store.update(
                rotated.token, version=session.version + 1
            )
            rotated = self._store.get(rotated.token)
        self._audit.record(
            DecisionRecord(
                request_id=request_id,
                stage="rotate",
                source=source,
                decision=Decision.ALLOW,
                subject=session.subject,
                evidence={
                    "old_token_prefix": token[:8],
                    "new_token_prefix": rotated.token[:8],
                    "new_version": session.version + 1,
                },
            )
        )
        return rotated

    def revoke(self, token: str, *, request_id: str = "-", source: str = "-") -> bool:
        """撤销凭据；不存在返回 False。已过期/已轮换也允许撤销（幂等标记）。"""
        with self._store._lock:  # noqa: SLF001
            session = self._store.get(token)
            if session is None:
                self._audit.record(
                    DecisionRecord(
                        request_id=request_id, stage="revoke", source=source,
                        decision=Decision.DENY, reason=Reason.CREDENTIAL_UNKNOWN.value,
                        evidence={"token_prefix": token[:8]},
                    )
                )
                return False
            self._store.update(token, revoked=True)
        self._audit.record(
            DecisionRecord(
                request_id=request_id, stage="revoke", source=source,
                decision=Decision.ALLOW, subject=session.subject,
                evidence={"token_prefix": token[:8], "superseded": session.superseded},
            )
        )
        return True
