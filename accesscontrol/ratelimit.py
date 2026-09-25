"""针对失败访问的限流与临时锁定。

策略：
- 每个来源独立计数，连续失败达到阈值 failure_threshold 后立即锁定
  lockout_seconds 秒；锁定期间所有请求以 source_locked 拒绝（429）。
- 锁定期满后自动解除，失败计数清零，重新开始计数（恢复时机可解释）。
- 任一未锁定请求完成一次成功认证判定即清零连续失败计数。

并发安全：
- 计数器保存在每个来源自己的锁保护下（_locks 注册表由一把全局锁保护），
  并发失败计数不会重复或丢失；
- 不同来源使用不同锁，单来源异常不阻塞其他来源。
"""

import threading
import time
from collections import defaultdict
from collections.abc import Callable

from accesscontrol.audit import AuditLog, Decision, DecisionRecord
from accesscontrol.config import Settings
from accesscontrol.errors import AccessControlError, Reason


class _Counters:
    __slots__ = ("failures", "locked_until")

    def __init__(self) -> None:
        self.failures: int = 0
        self.locked_until: float | None = None


class RateLimiter:
    def __init__(
        self,
        settings: Settings,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings
        self._audit = audit
        self._clock = clock
        self._counters: dict[str, _Counters] = defaultdict(_Counters)
        self._locks: dict[str, threading.Lock] = {}
        self._registry_lock = threading.Lock()

    def _lock_for(self, source: str) -> threading.Lock:
        # 注册表查找/创建很快；每来源独立锁保证彼此不互相阻塞
        with self._registry_lock:
            lock = self._locks.get(source)
            if lock is None:
                lock = threading.Lock()
                self._locks[source] = lock
            return lock

    def status(self, source: str) -> dict[str, object]:
        """返回某来源当前计数与锁定状态（便于测试与解释恢复时机）。"""
        now = self._clock()
        with self._lock_for(source):
            c = self._counters[source]
            locked = c.locked_until is not None and now < c.locked_until
            return {
                "failures": c.failures,
                "locked": locked,
                "locked_until": c.locked_until if locked else None,
                "now": now,
            }

    def check(self, source: str, *, request_id: str = "-") -> None:
        """请求入口检查：若来源处于锁定期则拒绝。"""
        now = self._clock()
        with self._lock_for(source):
            c = self._counters[source]
            if c.locked_until is not None:
                if now < c.locked_until:
                    evidence = {
                        "failures": c.failures,
                        "locked_until": c.locked_until,
                        "now": now,
                        "remaining_seconds": round(c.locked_until - now, 3),
                    }
                    self._audit.record(
                        DecisionRecord(
                            request_id=request_id, stage="rate_limit", source=source,
                            decision=Decision.DENY, reason=Reason.SOURCE_LOCKED.value,
                            evidence=evidence,
                        )
                    )
                    raise AccessControlError(
                        Reason.SOURCE_LOCKED,
                        f"来源已被临时锁定，请 {round(c.locked_until - now, 1)} 秒后重试",
                    )
                # 锁定期满：自动解除并清零，恢复正常
                c.locked_until = None
                c.failures = 0
                self._audit.record(
                    DecisionRecord(
                        request_id=request_id, stage="rate_limit", source=source,
                        decision=Decision.ALLOW, reason="lock_expired_reset",
                        evidence={"now": now},
                    )
                )
            else:
                # 正常放行：同样记录依据（failures=0 表示当前无连续失败）
                self._audit.record(
                    DecisionRecord(
                        request_id=request_id, stage="rate_limit", source=source,
                        decision=Decision.ALLOW, reason="not_locked",
                        evidence={"now": now, "failures": c.failures},
                    )
                )

    def record_failure(self, source: str, *, request_id: str = "-") -> int:
        """登记一次失败；达到阈值则置锁定。返回当前连续失败数。"""
        now = self._clock()
        with self._lock_for(source):
            c = self._counters[source]
            c.failures += 1
            locked_now = False
            if c.failures >= self._settings.failure_threshold:
                c.locked_until = now + self._settings.lockout_seconds
                locked_now = True
            evidence = {
                "failures": c.failures,
                "threshold": self._settings.failure_threshold,
                "lockout_seconds": self._settings.lockout_seconds,
                "locked_now": locked_now,
                "locked_until": c.locked_until,
            }
            self._audit.record(
                DecisionRecord(
                    request_id=request_id, stage="rate_limit", source=source,
                    decision=Decision.DENY,
                    reason=Reason.SOURCE_LOCKED.value if locked_now else "failure_counted",
                    evidence=evidence,
                )
            )
            return c.failures

    def record_success(self, source: str, *, request_id: str = "-") -> None:
        """成功请求清零连续失败计数（不会解除已生效的锁定，锁定由 check 负责）。"""
        with self._lock_for(source):
            c = self._counters[source]
            reset = c.failures
            c.failures = 0
        if reset:
            self._audit.record(
                DecisionRecord(
                    request_id=request_id, stage="rate_limit", source=source,
                    decision=Decision.ALLOW, reason="success_reset",
                    evidence={"cleared_failures": reset},
                )
            )
