"""运行参数配置：环境变量可覆盖，缺省保持既有默认行为。

环境变量（均为可选，未设置时使用默认值，与既有硬编码行为一致）：
- SAC_SESSION_TTL_SECONDS  会话有效期（秒），默认 3600
- SAC_MAX_FAILURES         连续失败锁定阈值，默认 5
- SAC_LOCKOUT_SECONDS      锁定时长（秒），默认 30
- SAC_AUDIT_CAPACITY       审计记录容量上限，默认 10000
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_ENV_TTL = "SAC_SESSION_TTL_SECONDS"
_ENV_MAX_FAILURES = "SAC_MAX_FAILURES"
_ENV_LOCKOUT = "SAC_LOCKOUT_SECONDS"
_ENV_AUDIT_CAPACITY = "SAC_AUDIT_CAPACITY"


@dataclass(frozen=True)
class Settings:
    """运行参数集合。默认值与既有硬编码行为一致。"""

    session_ttl_seconds: float = 3600.0
    max_failures: int = 5
    lockout_seconds: float = 30.0
    audit_capacity: int = 10000


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return float(raw)


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """从环境变量加载配置；未设置的项保持默认值。

    env 参数仅供测试注入；缺省读取 os.environ。
    """
    if env is None:
        return Settings(
            session_ttl_seconds=_float_env(_ENV_TTL, Settings.session_ttl_seconds),
            max_failures=_int_env(_ENV_MAX_FAILURES, Settings.max_failures),
            lockout_seconds=_float_env(_ENV_LOCKOUT, Settings.lockout_seconds),
            audit_capacity=_int_env(_ENV_AUDIT_CAPACITY, Settings.audit_capacity),
        )
    return Settings(
        session_ttl_seconds=float(env.get(_ENV_TTL, Settings.session_ttl_seconds)),
        max_failures=int(env.get(_ENV_MAX_FAILURES, Settings.max_failures)),
        lockout_seconds=float(env.get(_ENV_LOCKOUT, Settings.lockout_seconds)),
        audit_capacity=int(env.get(_ENV_AUDIT_CAPACITY, Settings.audit_capacity)),
    )
