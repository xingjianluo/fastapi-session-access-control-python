"""统一拒绝原因与错误类型。

拒绝原因（reason）必须可区分，便于审计与测试断言：
- missing_credential   未提供凭据
- credential_expired   凭据已过期
- credential_revoked   凭据已撤销
- credential_rotated   凭据已被轮换（旧凭据作废）
- credential_unknown   凭据不存在
- source_locked        来源已被临时锁定
- forbidden_role_or_scope  角色/作用域不满足
- forbidden_ownership  跨资源归属访问
- resource_not_found   资源不存在（对外与越权合并，避免探测）

状态码约定：401 凭据问题；429 锁定/节流；403 角色作用域问题
（内部记录）；404 归属/不存在（对外统一）；409 轮换冲突。
"""

from enum import Enum


class Reason(str, Enum):
    MISSING_CREDENTIAL = "missing_credential"
    CREDENTIAL_EXPIRED = "credential_expired"
    CREDENTIAL_REVOKED = "credential_revoked"
    CREDENTIAL_ROTATED = "credential_rotated"
    CREDENTIAL_UNKNOWN = "credential_unknown"
    SOURCE_LOCKED = "source_locked"
    FORBIDDEN_ROLE_OR_SCOPE = "forbidden_role_or_scope"
    FORBIDDEN_OWNERSHIP = "forbidden_ownership"
    RESOURCE_NOT_FOUND = "resource_not_found"
    CONFLICT = "conflict"


# 各原因对应的 HTTP 状态码
STATUS_BY_REASON: dict[Reason, int] = {
    Reason.MISSING_CREDENTIAL: 401,
    Reason.CREDENTIAL_EXPIRED: 401,
    Reason.CREDENTIAL_REVOKED: 401,
    Reason.CREDENTIAL_ROTATED: 401,
    Reason.CREDENTIAL_UNKNOWN: 401,
    Reason.SOURCE_LOCKED: 429,
    # 角色/作用域不足属于已认证但未授权，对内可解释
    Reason.FORBIDDEN_ROLE_OR_SCOPE: 403,
    # 跨归属访问对外统一表现为 404（不泄露资源是否存在）
    Reason.FORBIDDEN_OWNERSHIP: 404,
    Reason.RESOURCE_NOT_FOUND: 404,
    Reason.CONFLICT: 409,
}


class AccessControlError(Exception):
    """携带可区分拒绝原因的授权异常，贯穿统一异常链路。"""

    def __init__(self, reason: Reason, message: str, *, status_code: int | None = None):
        self.reason = reason
        self.status_code = (
            status_code if status_code is not None else STATUS_BY_REASON[reason]
        )
        self.message = message
        super().__init__(f"[{reason.value}] {message}")
