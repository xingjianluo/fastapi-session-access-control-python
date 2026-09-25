"""限流与临时锁定：阈值、并发计数、恢复时机、来源隔离。"""

import concurrent.futures
import logging

from app.rate_limit import RateLimiter

log = logging.getLogger(__name__)


def test_lock_after_threshold_and_recover():
    limiter = RateLimiter(max_failures=3, lockout_seconds=10.0)
    src = "ip-1"
    base = 1_000.0
    assert limiter.record_failure(src, now=base) is False
    assert limiter.record_failure(src, now=base) is False
    locked = limiter.record_failure(src, now=base)
    log.info("输入: 连续 3 次失败 | 判定: 达到阈值 3 | 结果: locked=%s", locked)
    assert locked is True
    assert limiter.is_locked(src, now=base + 5) is True
    # 锁定到期自动恢复
    assert limiter.is_locked(src, now=base + 10.0) is False
    log.info("输入: 锁定期满后检查 | 判定: 超过 until | 结果: 已恢复")


def test_success_resets_counter():
    limiter = RateLimiter(max_failures=3, lockout_seconds=10.0)
    src = "ip-2"
    limiter.record_failure(src)
    limiter.record_failure(src)
    limiter.record_success(src)
    # 清零后还需再满 3 次才锁定
    assert limiter.record_failure(src) is False
    assert limiter.record_failure(src) is False
    assert limiter.record_failure(src) is True
    log.info("输入: 2 失败+成功+3 失败 | 判定: 成功清零计数 | 结果: 第 3 次新失败才锁定")


def test_concurrent_failures_counted_exactly():
    """并发失败计数不重复、不丢失：N 次并发失败恰好计 N 次。"""
    n = 50
    limiter = RateLimiter(max_failures=n, lockout_seconds=60.0)
    src = "ip-3"
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: limiter.record_failure(src), range(n)))
    log.info("输入: %d 路并发失败 | 判定: 锁内串行计数 | 结果: 触发锁定次数=%d", n, sum(results))
    assert sum(results) == 1  # 恰好第 n 次触发锁定
    assert limiter.is_locked(src) is True


def test_sources_isolated():
    limiter = RateLimiter(max_failures=2, lockout_seconds=10.0)
    limiter.record_failure("ip-a")
    limiter.record_failure("ip-a")
    assert limiter.is_locked("ip-a") is True
    assert limiter.is_locked("ip-b") is False
    log.info("输入: ip-a 锁定后检查 ip-b | 判定: 按来源独立计数 | 结果: ip-b 不受影响")
