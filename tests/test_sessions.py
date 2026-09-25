"""会话凭据：签发、过期、撤销、轮换、并发轮换。"""

import concurrent.futures
import logging
import time

import pytest

from app.errors import AccessDeniedError, RejectionReason
from app.session_store import SessionStore

log = logging.getLogger(__name__)


def make_store(ttl: float = 3600.0) -> SessionStore:
    return SessionStore(ttl_seconds=ttl)


def test_issue_and_validate():
    store = make_store()
    s = store.issue("alice", {"user"}, {"doc:read"})
    got = store.validate(s.token)
    log.info("输入: token=%s | 判定: 有效会话 | 结果: subject=%s", s.token, got.subject)
    assert got.subject == "alice"
    assert got.roles == frozenset({"user"})


def test_validate_unknown_token():
    store = make_store()
    with pytest.raises(AccessDeniedError) as ei:
        store.validate("no-such-token")
    log.info("输入: 未知 token | 判定: 不存在 | 结果: %s", ei.value.reason)
    assert ei.value.reason == RejectionReason.CREDENTIAL_UNKNOWN


def test_validate_expired_token():
    store = make_store(ttl=0.05)
    s = store.issue("alice", {"user"}, {"doc:read"})
    time.sleep(0.1)
    with pytest.raises(AccessDeniedError) as ei:
        store.validate(s.token)
    log.info("输入: 过期 token | 判定: 已过期 | 结果: %s", ei.value.reason)
    assert ei.value.reason == RejectionReason.CREDENTIAL_EXPIRED


def test_validate_revoked_token():
    store = make_store()
    s = store.issue("alice", {"user"}, {"doc:read"})
    store.revoke(s.token)
    with pytest.raises(AccessDeniedError) as ei:
        store.validate(s.token)
    log.info("输入: 已撤销 token | 判定: 已撤销 | 结果: %s", ei.value.reason)
    assert ei.value.reason == RejectionReason.CREDENTIAL_REVOKED


def test_rotate_invalidates_old_and_issues_new():
    store = make_store()
    s = store.issue("alice", {"user"}, {"doc:read"})
    new = store.rotate(s.token)
    assert new.token != s.token
    # 旧凭据被拒绝，原因可区分为 rotated
    with pytest.raises(AccessDeniedError) as ei:
        store.validate(s.token)
    log.info("输入: 已轮换旧 token | 判定: 已被新凭据取代 | 结果: %s", ei.value.reason)
    assert ei.value.reason == RejectionReason.CREDENTIAL_ROTATED
    # 新凭据可用
    assert store.validate(new.token).subject == "alice"


def test_rotate_reuse_old_token_rejected():
    """重复使用旧凭据再次轮换：不得获得任何可用凭据。"""
    store = make_store()
    s = store.issue("alice", {"user"}, {"doc:read"})
    store.rotate(s.token)
    with pytest.raises(AccessDeniedError) as ei:
        store.rotate(s.token)
    log.info("输入: 重复使用旧 token 轮换 | 判定: 已轮换 | 结果: %s", ei.value.reason)
    assert ei.value.reason == RejectionReason.CREDENTIAL_ROTATED


def test_concurrent_rotation_only_one_succeeds():
    """同一凭据并发轮换：恰好一次成功，其余全部以 ROTATED 失败。"""
    store = make_store()
    s = store.issue("alice", {"user"}, {"doc:read"})

    def attempt(_):
        try:
            return ("ok", store.rotate(s.token))
        except AccessDeniedError as e:
            return ("fail", e.reason)

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))

    oks = [r for r in results if r[0] == "ok"]
    fails = [r for r in results if r[0] == "fail"]
    log.info("输入: 16 路并发轮换同一 token | 判定: 锁内串行 | 结果: 成功=%d 失败=%d", len(oks), len(fails))
    assert len(oks) == 1
    assert len(fails) == 15
    assert all(reason == RejectionReason.CREDENTIAL_ROTATED for _, reason in fails)
    # 唯一的新凭据可用，旧凭据不可用
    new_session = oks[0][1]
    assert store.validate(new_session.token).subject == "alice"
    with pytest.raises(AccessDeniedError):
        store.validate(s.token)
