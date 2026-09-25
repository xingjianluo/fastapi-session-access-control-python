"""按来源的失败计数、限流与临时锁定（进程内、线程安全）。"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """同一来源连续失败达到阈值后临时锁定；成功访问清零计数。

    - max_failures: 连续失败阈值，达到即锁定
    - lockout_seconds: 锁定时长，过期自动恢复
    所有计数读写在同一把锁内完成，并发下不重复、不丢失。
    """

    def __init__(self, max_failures: int = 5, lockout_seconds: float = 30.0):
        self._max_failures = max_failures
        self._lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._locked_until: dict[str, float] = {}

    def _purge_if_expired(self, source: str, now: float) -> None:
        """锁内调用：锁定已过期则清除锁定与计数（恢复时机 = 锁定截止时刻）。"""
        until = self._locked_until.get(source)
        if until is not None and now >= until:
            del self._locked_until[source]
            self._failures.pop(source, None)

    def is_locked(self, source: str, now: float | None = None) -> bool:
        """来源当前是否处于锁定状态（过期锁自动清除）。"""
        now = time.time() if now is None else now
        with self._lock:
            self._purge_if_expired(source, now)
            return source in self._locked_until

    def locked_until(self, source: str) -> float | None:
        """返回锁定截止时刻，未锁定返回 None。"""
        now = time.time()
        with self._lock:
            self._purge_if_expired(source, now)
            return self._locked_until.get(source)

    def record_failure(self, source: str, now: float | None = None) -> bool:
        """记录一次失败；若因此进入锁定返回 True。计数在锁内完成，并发不丢不重。"""
        now = time.time() if now is None else now
        with self._lock:
            self._purge_if_expired(source, now)
            if source in self._locked_until:
                return True  # 已锁定，保持锁定状态
            count = self._failures.get(source, 0) + 1
            self._failures[source] = count
            if count >= self._max_failures:
                self._locked_until[source] = now + self._lockout_seconds
                return True
            return False

    def record_success(self, source: str) -> None:
        """成功访问，清零该来源的失败计数。"""
        with self._lock:
            self._failures.pop(source, None)
