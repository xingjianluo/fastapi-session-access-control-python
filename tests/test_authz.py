"""默认拒绝授权判定测试：角色/作用域 + 资源归属。"""

import pytest

from accesscontrol.audit import AuditLog, Decision
from accesscontrol.authz import Principal, Resource, ResourceRegistry, authorize
from accesscontrol.errors import AccessControlError, Reason


@pytest.fixture
def audit():
    return AuditLog()


@pytest.fixture
def registry():
    reg = ResourceRegistry()
    reg.add(Resource("doc-alice", owner="alice", required_scope="doc:read"))
    reg.add(Resource("doc-bob", owner="bob", required_scope="doc:read"))
    reg.add(Resource("doc-public", owner="alice"))
    reg.add(
        Resource(
            "doc-admin",
            owner="alice",
            required_role="admin",
            required_scope="doc:write",
        )
    )
    return reg


def _deny(fn, reason):
    with pytest.raises(AccessControlError) as ei:
        fn()
    assert ei.value.reason is reason
    return ei.value


def test_owner_with_scope_allowed(audit, registry):
    p = Principal("alice", scopes=("doc:read",))
    res = authorize(p, registry.get("doc-alice"), audit, request_id="r1", source="s")
    assert res.resource_id == "doc-alice"
    rec = audit.records_for("r1")[-1]
    assert rec.decision is Decision.ALLOW
    assert rec.evidence["role_ok"] and rec.evidence["scope_ok"]
    print("输入: alice/doc:read -> 依据: 归属一致+scope命中 -> 结果: allow")


def test_cross_owner_denied_as_not_found(audit, registry):
    bob = Principal("bob", scopes=("doc:read",))
    err = _deny(
        lambda: authorize(bob, registry.get("doc-alice"), audit, request_id="r2", source="s"),
        Reason.RESOURCE_NOT_FOUND,
    )
    # 对外 404，不泄露资源存在
    assert err.status_code == 404
    # 但审计保留真实原因，可复现
    rec = audit.records_for("r2")[-1]
    assert rec.reason == Reason.FORBIDDEN_OWNERSHIP.value
    assert rec.evidence["resource_owner"] == "alice"
    print(f"输入: bob 访问 doc-alice -> 依据: owner!=subject -> 结果: 对外 deny/{err.reason.value}(404)，审计 forbidden_ownership")


def test_missing_resource_indistinguishable_from_cross_owner(audit, registry):
    alice = Principal("alice", scopes=("doc:read",))
    e1 = _deny(lambda: authorize(alice, None, audit, request_id="r3"), Reason.RESOURCE_NOT_FOUND)
    bob = Principal("bob", scopes=("doc:read",))
    e2 = _deny(
        lambda: authorize(bob, registry.get("doc-alice"), audit, request_id="r4"),
        Reason.RESOURCE_NOT_FOUND,
    )
    assert e1.status_code == e2.status_code == 404
    assert e1.message == e2.message


def test_missing_scope_denied(audit, registry):
    alice = Principal("alice", scopes=())
    err = _deny(
        lambda: authorize(alice, registry.get("doc-alice"), audit, request_id="r5"),
        Reason.FORBIDDEN_ROLE_OR_SCOPE,
    )
    assert err.status_code == 403
    rec = audit.records_for("r5")[-1]
    assert rec.evidence["scope_ok"] is False
    print(f"输入: alice 无 doc:read -> 依据: scope_ok=False -> 结果: deny/{err.reason.value}")


def test_role_and_scope_both_required(audit, registry):
    # 只有角色没有作用域
    p_role = Principal("alice", roles=("admin",), scopes=())
    _deny(
        lambda: authorize(p_role, registry.get("doc-admin"), audit, request_id="r6"),
        Reason.FORBIDDEN_ROLE_OR_SCOPE,
    )
    # 只有作用域没有角色
    p_scope = Principal("alice", roles=(), scopes=("doc:write",))
    _deny(
        lambda: authorize(p_scope, registry.get("doc-admin"), audit, request_id="r7"),
        Reason.FORBIDDEN_ROLE_OR_SCOPE,
    )
    # 两者齐备且归属一致才放行
    p_both = Principal("alice", roles=("admin",), scopes=("doc:write",))
    assert authorize(p_both, registry.get("doc-admin"), audit, request_id="r8").owner == "alice"


def test_other_owner_admin_still_denied_by_ownership(audit, registry):
    # bob 即使权限齐备，也不能访问 alice 的资源，归属判定不可绕过
    bob = Principal("bob", roles=("admin",), scopes=("doc:write",))
    err = _deny(
        lambda: authorize(bob, registry.get("doc-admin"), audit, request_id="r9"),
        Reason.RESOURCE_NOT_FOUND,
    )
    assert err.status_code == 404
    assert audit.records_for("r9")[-1].reason == Reason.FORBIDDEN_OWNERSHIP.value


def test_no_requirements_resource_still_enforces_ownership(audit, registry):
    assert authorize(Principal("alice"), registry.get("doc-public"), audit, request_id="r10").resource_id
    _deny(
        lambda: authorize(Principal("bob"), registry.get("doc-public"), audit, request_id="r11"),
        Reason.RESOURCE_NOT_FOUND,
    )
