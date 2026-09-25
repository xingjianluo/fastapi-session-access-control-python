"""本地策略配置（会话 TTL、限流阈值、锁定时长等）。

全部参数可通过环境变量覆盖，方便本地验证，不依赖任何外部服务。
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # 凭据有效期（秒）
    session_ttl_seconds: int = 300
    # 同一来源连续失败多少次后锁定
    failure_threshold: int = 5
    # 锁定时长（秒）
    lockout_seconds: int = 30
    # 来源标识请求头（便于本地测试区分来源；缺省回退到客户端 IP）
    source_header: str = "X-Source-ID"
    # 进程内审计环形缓冲容量
    audit_capacity: int = 1024


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def get_settings() -> Settings:
    """从环境变量读取配置；非法值直接抛出 ValueError，避免静默降级。"""
    return Settings(
        session_ttl_seconds=_env_int("SESSION_TTL_SECONDS", 300),
        failure_threshold=_env_int("FAILURE_THRESHOLD", 5),
        lockout_seconds=_env_int("LOCKOUT_SECONDS", 30),
        source_header=os.environ.get("SOURCE_HEADER", "X-Source-ID"),
        audit_capacity=_env_int("AUDIT_CAPACITY", 1024),
    )
