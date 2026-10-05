"""错误类型与可区分的拒绝原因定义。"""

from __future__ import annotations

import enum


class RejectionReason(str, enum.Enum):
    """会话/授权/限流的可区分拒绝原因。"""

    # 会话凭据相关
    CREDENTIAL_MISSING = "credential_missing"
    CREDENTIAL_UNKNOWN = "credential_unknown"
    CREDENTIAL_EXPIRED = "credential_expired"
    CREDENTIAL_REVOKED = "credential_revoked"
    CREDENTIAL_ROTATED = "credential_rotated"  # 旧凭据已被轮换取代

    # 授权相关
    FORBIDDEN_ROLE = "forbidden_role"        # 角色/作用域不足
    FORBIDDEN_OWNERSHIP = "forbidden_ownership"  # 跨归属访问（不泄露资源是否存在）
    RESOURCE_NOT_FOUND = "resource_not_found"    # 与越权返回一致，避免存在性泄露

    # 限流相关
    RATE_LIMITED = "rate_limited"  # 来源被临时锁定/节流

    # 未预期异常（统一兜底，不暴露内部细节）
    INTERNAL_ERROR = "internal_error"


class AccessDeniedError(Exception):
    """授权链路统一异常，携带可区分原因与 HTTP 状态码。"""

    def __init__(self, reason: RejectionReason, status_code: int = 403, detail: str = ""):
        self.reason = reason
        self.status_code = status_code
        self.detail = detail or reason.value
        super().__init__(f"{reason.value}: {self.detail}")
