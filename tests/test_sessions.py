"""凭据签发、过期、撤销、轮换与重复使用的拒绝原因测试。"""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from accesscontrol.audit import AuditLog
from accesscontrol.config import Settings
from accesscontrol.errors import AccessControlError, Reason
from accesscontrol.sessions import SessionService
from accesscontrol.store import SessionStore


@pytest.fixture
def services(clock):
    audit = AuditLog()
    settings = Settings(session_ttl_seconds=100)
    service = SessionService(SessionStore(), settings, audit, clock=clock)
    return service, audit


def _expect_deny(fn, reason: Reason):
    with pytest.raises(AccessControlError) as ei:
        fn()
    assert ei.value.reason is reason
    return ei.value


def test_issue_and_authenticate(services):
    service, audit = services
    session = service.issue("alice", ("reader",), ("doc:read",))
    authed = service.authenticate(session.token)
    assert authed.subject == "alice"
    assert authed.scopes == ("doc:read",)
    rec = audit.records_for("-")
    assert rec[-1].decision.value == "allow"
    print("输入: alice/reader/doc:read -> 依据: 未过期未撤销 -> 结果: allow")


def test_expired_credential_denied(services, clock):
    service, audit = services
    session = service.issue("alice")
    clock.advance(101)
    err = _expect_deny(lambda: service.authenticate(session.token), Reason.CREDENTIAL_EXPIRED)
    assert err.status_code == 401
    last = audit.all()[-1]
    assert last.evidence["now"] >= last.evidence["expires_at"]
    print(f"输入: 过期凭据 -> 依据: now>={last.evidence['expires_at']} -> 结果: deny/{err.reason.value}")


def test_revoked_credential_denied(services):
    service, audit = services
    session = service.issue("alice")
    assert service.revoke(session.token) is True
    err = _expect_deny(lambda: service.authenticate(session.token), Reason.CREDENTIAL_REVOKED)
    assert err.status_code == 401
    assert audit.all()[-1].evidence["revoked"] is True
    print(f"输入: 已撤销凭据 -> 依据: revoked=True -> 结果: deny/{err.reason.value}")


def test_revoked_takes_precedence_over_expired(services, clock):
    service, _ = services
    session = service.issue("alice")
    service.revoke(session.token)
    clock.advance(200)
    # 既撤销又过期时原因稳定为 revoked，结论可解释、可复现
    _expect_deny(lambda: service.authenticate(session.token), Reason.CREDENTIAL_REVOKED)


def test_unknown_and_missing_credential(services):
    service, _ = services
    _expect_deny(lambda: service.authenticate("tok_notexist"), Reason.CREDENTIAL_UNKNOWN)
    _expect_deny(lambda: service.authenticate(""), Reason.MISSING_CREDENTIAL)
    assert service.revoke("tok_notexist") is False


def test_rotate_replaces_old_credential(services):
    service, audit = services
    old = service.issue("alice", scopes=("doc:read",))
    new = service.rotate(old.token)
    assert new.token != old.token
    # 新凭据可用，版本递增
    assert service.authenticate(new.token).version == 2
    # 旧凭据已被轮换，拒绝原因可区分
    err = _expect_deny(lambda: service.authenticate(old.token), Reason.CREDENTIAL_ROTATED)
    assert err.status_code == 401
    assert audit.all()[-1].evidence["superseded"] is True
    print(f"输入: 旧凭据 -> 依据: superseded=True -> 结果: deny/{err.reason.value}")


def test_rotated_credential_cannot_rotate_again(services):
    service, _ = services
    first = service.issue("alice")
    second = service.rotate(first.token)
    # 重复使用旧凭据发起轮换：失败且拿不到任何新凭据
    _expect_deny(lambda: service.rotate(first.token), Reason.CREDENTIAL_ROTATED)
    # 新凭据仍然正常
    assert service.authenticate(second.token).subject == "alice"


def test_revoked_credential_cannot_rotate(services):
    service, _ = services
    token = service.issue("alice").token
    service.revoke(token)
    _expect_deny(lambda: service.rotate(token), Reason.CREDENTIAL_REVOKED)


def test_expired_credential_cannot_rotate(services, clock):
    service, _ = services
    token = service.issue("alice").token
    clock.advance(101)
    _expect_deny(lambda: service.rotate(token), Reason.CREDENTIAL_EXPIRED)


def test_concurrent_rotate_only_one_wins(services):
    """同一凭据并发轮换：恰好一次成功；所有失败方都不得获得可用凭据。"""
    service, audit = services
    token = service.issue("alice", ("reader",), ("doc:read",)).token

    results: list[object] = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()  # 尽量同时进入临界区
        try:
            results.append(("ok", service.rotate(token).token))
        except AccessControlError as exc:
            results.append(("deny", exc.reason))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: worker(), range(8)))

    successes = [r for r in results if r[0] == "ok"]
    denies = [r for r in results if r[0] == "deny"]
    assert len(successes) == 1, f"并发轮换成功次数应为 1，实际 {results}"
    assert len(denies) == 7
    assert all(reason is Reason.CREDENTIAL_ROTATED for _, reason in denies)

    winner = successes[0][1]
    # 唯一胜出的新凭据可用
    assert service.authenticate(winner).version == 2
    # 旧凭据不可用
    _expect_deny(lambda: service.authenticate(token), Reason.CREDENTIAL_ROTATED)
    # 失败方没有任何凭据泄露：审计中只有一次 rotate allow
    rotate_allows = [
        r for r in audit.all() if r.stage == "rotate" and r.decision.value == "allow"
    ]
    assert len(rotate_allows) == 1
    print(
        f"输入: 8 个并发轮换同一凭据 -> 依据: 临界区内 superseded 检查 -> "
        f"结果: 成功 {len(successes)} / 拒绝 {len(denies)}（全部 credential_rotated）"
    )


def test_concurrent_rotates_of_a_chain_stay_consistent(services):
    """轮换后的新凭据再并发轮换，同样恰好一次成功，链上每个旧凭据都作废。"""
    service, _ = services
    t1 = service.issue("alice").token
    t2 = service.rotate(t1).token

    results = []
    barrier = threading.Barrier(4)

    def worker():
        barrier.wait()
        try:
            results.append(("ok", service.rotate(t2).token))
        except AccessControlError as exc:
            results.append(("deny", exc.reason))

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda _: worker(), range(4)))

    assert len([r for r in results if r[0] == "ok"]) == 1
    _expect_deny(lambda: service.authenticate(t1), Reason.CREDENTIAL_ROTATED)
    _expect_deny(lambda: service.authenticate(t2), Reason.CREDENTIAL_ROTATED)
