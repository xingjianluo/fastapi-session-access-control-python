"""授权判定：默认拒绝、作用域、归属、存在性不泄露。"""

import logging

import pytest

from app.authz import Authorizer
from app.errors import AccessDeniedError, RejectionReason
from app.models import Resource, Session

log = logging.getLogger(__name__)


def make_session(subject: str, roles=(), scopes=()) -> Session:
    return Session(
        session_id="s-" + subject,
        subject=subject,
        roles=frozenset(roles),
        scopes=frozenset(scopes),
        expires_at=9_999_999_999.0,
    )


@pytest.fixture
def authorizer() -> Authorizer:
    return Authorizer(
        {
            "doc-1": Resource(resource_id="doc-1", owner="alice", required_scope="doc:read"),
        }
    )


def test_owner_with_scope_allowed(authorizer):
    s = make_session("alice", roles={"user"}, scopes={"doc:read"})
    d = authorizer.decide(s, "doc-1")
    log.info("输入: alice/doc:read 访问自有 doc-1 | 判定: scope=%s owner=%s | 结果: %s",
             d.matched_scope, d.matched_owner, d.reason)
    assert d.allowed and d.reason == "allowed"
    assert authorizer.authorize(s, "doc-1").resource_id == "doc-1"


def test_missing_scope_denied(authorizer):
    s = make_session("alice", roles={"user"}, scopes=set())
    d = authorizer.decide(s, "doc-1")
    log.info("输入: alice 无作用域访问 doc-1 | 判定: scope=%s | 结果: %s", d.matched_scope, d.reason)
    assert not d.allowed and d.reason == RejectionReason.FORBIDDEN_ROLE.value
    with pytest.raises(AccessDeniedError) as ei:
        authorizer.authorize(s, "doc-1")
    assert ei.value.reason == RejectionReason.FORBIDDEN_ROLE


def test_cross_ownership_denied(authorizer):
    """bob 有作用域但访问 alice 的资源：归属拒绝。"""
    s = make_session("bob", roles={"user"}, scopes={"doc:read"})
    d = authorizer.decide(s, "doc-1")
    log.info("输入: bob 访问 alice 的 doc-1 | 判定: scope=%s owner=%s | 结果: %s",
             d.matched_scope, d.matched_owner, d.reason)
    assert not d.allowed and d.reason == RejectionReason.FORBIDDEN_OWNERSHIP.value
    with pytest.raises(AccessDeniedError) as ei:
        authorizer.authorize(s, "doc-1")
    assert ei.value.reason == RejectionReason.FORBIDDEN_OWNERSHIP


def test_nonexistent_resource_does_not_leak(authorizer):
    """不存在的资源与越权访问：都不暴露资源是否存在。"""
    s = make_session("alice", roles={"user"}, scopes={"doc:read"})
    with pytest.raises(AccessDeniedError) as ei:
        authorizer.authorize(s, "doc-ghost")
    log.info("输入: 访问不存在资源 | 判定: 默认拒绝 | 结果: %s", ei.value.reason)
    assert ei.value.reason == RejectionReason.RESOURCE_NOT_FOUND
    # 不存在与越权均不返回资源内容，且响应结构一致（error+detail）
    assert isinstance(ei.value.detail, str)


def test_admin_role_bypasses_scope_and_ownership(authorizer):
    s = make_session("carol", roles={"admin"}, scopes=set())
    d = authorizer.decide(s, "doc-1")
    log.info("输入: admin carol 访问 doc-1 | 判定: admin 隐含全部 | 结果: %s", d.reason)
    assert d.allowed
