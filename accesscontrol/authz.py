"""默认拒绝的授权判定。

放行必须同时满足：
1. 资源存在；
2. 主体拥有资源要求的角色（required_role 为空表示不要求角色）
   或作用域（required_scope 为空表示不要求作用域）；
   ——当资源同时声明角色与作用域要求时，二者均需满足（AND 语义）；
3. 资源归属与主体一致（owner == principal.subject）。

任何不满足都拒绝：
- 角色/作用域不足 -> forbidden_role_or_scope（403，内部原因可解释）；
- 跨归属访问或资源不存在 -> 对外统一 resource_not_found（404），
  但审计记录中保留 forbidden_ownership 的真实原因，避免泄露资源是否存在。

每次判定都向 AuditLog 写入输入、命中条件与结论，可复现。
"""

from dataclasses import dataclass

from accesscontrol.audit import AuditLog, Decision, DecisionRecord
from accesscontrol.errors import AccessControlError, Reason
from accesscontrol.store import Session


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: tuple[str, ...] = ()
    scopes: tuple[str, ...] = ()

    @classmethod
    def from_session(cls, session: Session) -> "Principal":
        return cls(
            subject=session.subject, roles=session.roles, scopes=session.scopes
        )


@dataclass(frozen=True)
class Resource:
    resource_id: str
    owner: str
    # 空字符串表示该项不做要求
    required_role: str = ""
    required_scope: str = ""


class ResourceRegistry:
    """进程内资源目录（本地存储）。"""

    def __init__(self) -> None:
        self._resources: dict[str, Resource] = {}

    def add(self, resource: Resource) -> None:
        self._resources[resource.resource_id] = resource

    def get(self, resource_id: str) -> Resource | None:
        return self._resources.get(resource_id)


def _evidence(principal: Principal, resource: Resource | None) -> dict:
    return {
        "subject": principal.subject,
        "principal_roles": list(principal.roles),
        "principal_scopes": list(principal.scopes),
        "resource_id": resource.resource_id if resource else None,
        "resource_owner": resource.owner if resource else None,
        "required_role": resource.required_role if resource else None,
        "required_scope": resource.required_scope if resource else None,
    }


def authorize(
    principal: Principal,
    resource: Resource | None,
    audit: AuditLog,
    *,
    request_id: str = "-",
    source: str = "-",
    action: str = "read",
) -> Resource:
    """满足全部策略条件才返回资源，否则抛出 AccessControlError。"""
    ev = _evidence(principal, resource)
    ev["action"] = action

    # 1) 归属/存在性：对外统一 404，真实原因只进审计
    if resource is None:
        audit.record(DecisionRecord(
            request_id=request_id, stage="authorize", source=source,
            decision=Decision.DENY, reason=Reason.RESOURCE_NOT_FOUND.value,
            subject=principal.subject, action=action, evidence=ev,
        ))
        raise AccessControlError(Reason.RESOURCE_NOT_FOUND, "资源不存在或无权访问")

    if resource.owner != principal.subject:
        audit.record(DecisionRecord(
            request_id=request_id, stage="authorize", source=source,
            decision=Decision.DENY, reason=Reason.FORBIDDEN_OWNERSHIP.value,
            subject=principal.subject, action=action,
            resource_id=resource.resource_id, evidence=ev,
        ))
        # 对外与“不存在”完全一致，防止枚举资源
        raise AccessControlError(Reason.RESOURCE_NOT_FOUND, "资源不存在或无权访问")

    # 2) 角色/作用域（AND 语义；声明了就必须满足）
    role_ok = (not resource.required_role) or (resource.required_role in principal.roles)
    scope_ok = (not resource.required_scope) or (resource.required_scope in principal.scopes)
    ev["role_ok"] = role_ok
    ev["scope_ok"] = scope_ok
    if not (role_ok and scope_ok):
        audit.record(DecisionRecord(
            request_id=request_id, stage="authorize", source=source,
            decision=Decision.DENY, reason=Reason.FORBIDDEN_ROLE_OR_SCOPE.value,
            subject=principal.subject, action=action,
            resource_id=resource.resource_id, evidence=ev,
        ))
        raise AccessControlError(
            Reason.FORBIDDEN_ROLE_OR_SCOPE, "角色或作用域不满足资源要求"
        )

    # 3) 全部满足 -> 默认拒绝策略下放行
    audit.record(DecisionRecord(
        request_id=request_id, stage="authorize", source=source,
        decision=Decision.ALLOW, subject=principal.subject, action=action,
        resource_id=resource.resource_id, evidence=ev,
    ))
    return resource
