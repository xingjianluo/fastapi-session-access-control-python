"""运行参数配置：从环境变量读取，缺省保持既有默认值。"""

from __future__ import annotations

import os
from dataclasses import dataclass

# 环境变量名
ENV_TTL_SECONDS = "SESSION_TTL_SECONDS"
ENV_MAX_FAILURES = "RATE_LIMIT_MAX_FAILURES"
ENV_LOCKOUT_SECONDS = "RATE_LIMIT_LOCKOUT_SECONDS"
ENV_AUDIT_CAPACITY = "AUDIT_CAPACITY"

# 既有默认值（未配置环境变量时保持现状）
DEFAULT_TTL_SECONDS = 3600.0
DEFAULT_MAX_FAILURES = 5
DEFAULT_LOCKOUT_SECONDS = 30.0
DEFAULT_AUDIT_CAPACITY = 10_000


@dataclass(frozen=True)
class Settings:
    """运行参数快照。所有字段都有默认值，与既有行为一致。"""

    ttl_seconds: float = DEFAULT_TTL_SECONDS
    max_failures: int = DEFAULT_MAX_FAILURES
    lockout_seconds: float = DEFAULT_LOCKOUT_SECONDS
    audit_capacity: int = DEFAULT_AUDIT_CAPACITY


def _float_env(source: dict[str, str], name: str, default: float) -> float:
    raw = source.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _int_env(source: dict[str, str], name: str, default: int) -> int:
    raw = source.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """从环境变量（或显式传入的映射）加载配置。

    缺省、空串、非法值（非数字、非正数）都回退到默认值，
    保证未配置时行为与既有版本完全一致。
    """
    source = os.environ if env is None else env
    return Settings(
        ttl_seconds=_float_env(source, ENV_TTL_SECONDS, DEFAULT_TTL_SECONDS),
        max_failures=_int_env(source, ENV_MAX_FAILURES, DEFAULT_MAX_FAILURES),
        lockout_seconds=_float_env(source, ENV_LOCKOUT_SECONDS, DEFAULT_LOCKOUT_SECONDS),
        audit_capacity=_int_env(source, ENV_AUDIT_CAPACITY, DEFAULT_AUDIT_CAPACITY),
    )
