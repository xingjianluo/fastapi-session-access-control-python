"""测试夹具与判定日志。

每个测试的决策记录都通过标准 logging 打印：
输入（来源/主体/资源/动作）、判定依据（evidence）与结果（allow/deny + 原因）。
"""

import logging
import sys
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from accesscontrol.app import create_app
from accesscontrol.config import Settings

# 打开 accesscontrol 命名空间日志，确保“输入-依据-结果”始终输出
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
)
_ac_logger = logging.getLogger("accesscontrol")
if not _ac_logger.handlers:
    _ac_logger.addHandler(_handler)
_ac_logger.setLevel(logging.INFO)
_ac_logger.propagate = False


class MutableClock:
    """测试用可控时钟，默认从固定时刻开始。"""

    def __init__(self, start: float = 1_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        session_ttl_seconds=100,
        failure_threshold=3,
        lockout_seconds=30,
        audit_capacity=2048,
    )


@pytest.fixture
def client(settings: Settings, clock: MutableClock) -> TestClient:
    app = create_app(settings=settings, clock=clock)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def issue() -> Callable[..., str]:
    def _issue(
        client: TestClient,
        subject: str,
        roles: list[str] | None = None,
        scopes: list[str] | None = None,
        source: str = "test-source",
    ) -> str:
        r = client.post(
            "/auth/sessions",
            json={"subject": subject, "roles": roles or [], "scopes": scopes or []},
            headers={"X-Source-ID": source},
        )
        assert r.status_code == 200, r.text
        return r.json()["token"]

    return _issue
