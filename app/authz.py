"""默认拒绝的授权判定：角色/作用域 + 资源归属，双条件同时满足才放行。"""

from __future__ import annotations

from app.errors import AccessDeniedError, RejectionReason
from app.models import AuthzDecision, Resource, Session

# 角色 -> 隐含作用域：admin 角色视为拥有全部作用域
_ADMIN_ROLE = "admin"


class Authorizer:
    """授权器。资源不存在与越权返回一致的拒绝，避免存在性泄露。"""

    def __init__(self, resources: dict[str, Resource] | None = None):
        self._resources: dict[str, Resource] = dict(resources or {})

    def add_resource(self, resource: Resource) -> None:
        self._resources[resource.resource_id] = resource

    def decide(self, session: Session, resource_id: str) -> AuthzDecision:
        """返回判定依据（不抛异常），便于测试与日志复现。

        规则（默认拒绝）：
        1. 资源不存在 -> 拒绝，原因与越权一致（RESOURCE_NOT_FOUND），不泄露存在性；
        2. 作用域不满足（且无 admin 角色）-> 拒绝 FORBIDDEN_ROLE；
        3. 归属不匹配（且非 admin）-> 拒绝 FORBIDDEN_OWNERSHIP；
        4. 两者同时满足 -> 放行。
        """
        resource = self._resources.get(resource_id)
        if resource is None:
            return AuthzDecision(
                allowed=False,
                reason=RejectionReason.RESOURCE_NOT_FOUND.value,
                subject=session.subject,
                resource_id=resource_id,
                matched_scope=False,
                matched_owner=False,
            )
        is_admin = _ADMIN_ROLE in session.roles
        matched_scope = is_admin or resource.required_scope in session.scopes
        matched_owner = is_admin or resource.owner == session.subject
        if not matched_scope:
            reason = RejectionReason.FORBIDDEN_ROLE.value
        elif not matched_owner:
            reason = RejectionReason.FORBIDDEN_OWNERSHIP.value
        else:
            reason = "allowed"
        return AuthzDecision(
            allowed=matched_scope and matched_owner,
            reason=reason,
            subject=session.subject,
            resource_id=resource_id,
            matched_scope=matched_scope,
            matched_owner=matched_owner,
        )

    def authorize(self, session: Session, resource_id: str) -> Resource:
        """判定失败时抛出 AccessDeniedError；成功返回资源。"""
        decision = self.decide(session, resource_id)
        if not decision.allowed:
            reason = RejectionReason(decision.reason)
            # 越权与不存在使用相同状态码与结构，避免泄露资源是否存在
            status = 404 if reason == RejectionReason.RESOURCE_NOT_FOUND else 403
            raise AccessDeniedError(reason, status, f"subject={decision.subject} resource={resource_id}")
        return self._resources[resource_id]
