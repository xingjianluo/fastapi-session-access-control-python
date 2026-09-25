"""失败限流与临时锁定测试（含并发计数与来源隔离）。"""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from accesscontrol.audit import AuditLog
from accesscontrol.config import Settings
from accesscontrol.errors import AccessControlError, Reason
from accesscontrol.ratelimit import RateLimiter


@pytest.fixture
def limiter(clock):
    return RateLimiter(
        Settings(failure_threshold=3, lockout_seconds=30), AuditLog(), clock=clock
    )


def test_threshold_triggers_lock(limiter):
    limiter.record_failure("src1")
    limiter.record_failure("src1")
    limiter.check("src1")  # 尚未到阈值
    limiter.record_failure("src1")  # 第 3 次 -> 锁定
    with pytest.raises(AccessControlError) as ei:
        limiter.check("src1")
    assert ei.value.reason is Reason.SOURCE_LOCKED and ei.value.status_code == 429
    st = limiter.status("src1")
    assert st["locked"] is True and st["failures"] == 3
    print(f"输入: 3 次连续失败 -> 依据: failures>=3 -> 结果: deny/source_locked，{st}")


def test_lock_expiry_resets_count(limiter, clock):
    for _ in range(3):
        limiter.record_failure("src1")
    with pytest.raises(AccessControlError):
        limiter.check("src1")
    # 锁定期内时间推进但未到期，仍锁定
    clock.advance(29)
    with pytest.raises(AccessControlError):
        limiter.check("src1")
    # 到期后下一次 check 自动解除并清零
    clock.advance(1.1)
    limiter.check("src1")
    st = limiter.status("src1")
    assert st["locked"] is False and st["failures"] == 0
    print(f"输入: 锁定后推进 30.1s -> 依据: now>=locked_until -> 结果: allow/计数清零 {st}")


def test_success_resets_failures(limiter):
    limiter.record_failure("src1")
    limiter.record_failure("src1")
    limiter.record_success("src1")
    assert limiter.status("src1")["failures"] == 0
    # 再失败两次也不会触发锁定
    limiter.record_failure("src1")
    limiter.record_failure("src1")
    limiter.check("src1")


def test_sources_are_isolated(limiter):
    for _ in range(3):
        limiter.record_failure("bad")
    with pytest.raises(AccessControlError):
        limiter.check("bad")
    # 另一个来源完全不受影响
    limiter.check("good")
    limiter.record_failure("good")
    assert limiter.status("good")["failures"] == 1
    assert limiter.status("good")["locked"] is False


def test_locked_source_does_not_block_other_source(limiter):
    for _ in range(3):
        limiter.record_failure("bad")
    # 并发混合请求：bad 被拒，good 始终放行
    outcomes = []

    def hit(source):
        try:
            limiter.check(source)
            outcomes.append((source, "allow"))
        except AccessControlError as exc:
            outcomes.append((source, exc.reason.value))

    with ThreadPoolExecutor(max_workers=8) as pool:
        for i in range(20):
            pool.submit(hit, "bad" if i % 2 == 0 else "good")

    assert all(o != ("good", "source_locked") for o in outcomes)
    assert any(o == ("bad", "source_locked") for o in outcomes)


def test_concurrent_failures_counted_exactly(limiter):
    """并发失败计数不得重复或丢失：N 次登记后计数恰为 N。"""
    n = 50
    barrier = threading.Barrier(n)

    def fail():
        barrier.wait()
        limiter.record_failure("srcX")

    with ThreadPoolExecutor(max_workers=n) as pool:
        list(pool.map(lambda _: fail(), range(n)))

    st = limiter.status("srcX")
    assert st["failures"] == n, f"并发计数丢失或重复: {st['failures']} != {n}"
    assert st["locked"] is True
    # 锁定时间点固定为第 threshold 次失败时刻（计数 >= 3 即锁定，不重复加锁时间被刷新说明...）
    print(f"输入: {n} 个并发失败 -> 依据: 每来源独立锁 -> 结果: failures={st['failures']}, locked={st['locked']}")


def test_lock_time_stable_during_lock_window(limiter, clock):
    for _ in range(3):
        limiter.record_failure("src1")
    locked_until_first = limiter.status("src1")["locked_until"]
    # 锁定期内再登记失败不会把解锁时间向后推（恢复时机确定、可解释）
    for _ in range(3):
        limiter.record_failure("src1")
    assert limiter.status("src1")["locked_until"] == locked_until_first
