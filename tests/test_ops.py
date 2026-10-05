"""运行期观测与可配置：状态端点、环境变量配置、默认值兼容。"""

import logging
import time

from fastapi.testclient import TestClient

from app.config import Settings, load_settings
from main import create_app

log = logging.getLogger(__name__)


def issue(client, subject="alice") -> str:
    resp = client.post("/sessions", json={"subject": subject, "roles": ["user"], "scopes": ["doc:read"]})
    assert resp.status_code == 201
    return resp.json()["token"]


def test_status_reports_lock_state_and_recovery_time():
    client = TestClient(create_app(max_failures=2, lockout_seconds=60))
    before = client.get("/ops/status", params={"source": "testclient"}).json()
    assert before["lock"] == {"source": "testclient", "locked": False, "locked_until": None}

    for _ in range(2):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    after = client.get("/ops/status", params={"source": "testclient"}).json()
    log.info("场景=锁定状态观测 | locked=%s locked_until=%s | 结果=通过",
             after["lock"]["locked"], after["lock"]["locked_until"])
    assert after["lock"]["locked"] is True
    assert after["lock"]["locked_until"] > time.time() + 50  # 约 60s 后恢复


def test_status_reports_active_sessions_and_audit_usage():
    client = TestClient(create_app())
    t1 = issue(client, "alice")
    issue(client, "bob")
    client.get("/resources/doc-1", headers={"X-Session-Token": t1})
    st = client.get("/ops/status").json()
    log.info("场景=会话与审计占用 | active=%d audit=%s | 结果=通过",
             st["active_sessions"], st["audit"])
    assert st["active_sessions"] == 2
    assert st["audit"]["size"] == 3 and st["audit"]["capacity"] == 10_000
    assert st["lock"] is None  # 未指定 source 时不返回锁定信息
    # 不暴露凭据
    assert t1 not in str(st) and "token" not in str(st)


def test_status_does_not_count_revoked_or_rotated_sessions():
    client = TestClient(create_app())
    t1 = issue(client, "alice")
    t2 = issue(client, "alice")
    client.post("/sessions/revoke", json={"token": t1})
    client.post("/sessions/rotate", json={"token": t2})
    st = client.get("/ops/status").json()
    log.info("场景=撤销/轮换后计数 | active=%d | 结果=通过", st["active_sessions"])
    assert st["active_sessions"] == 1  # 只有轮换出的新会话有效


def test_env_config_overrides(monkeypatch):
    monkeypatch.setenv("SESSION_TTL_SECONDS", "120")
    monkeypatch.setenv("RATE_LIMIT_MAX_FAILURES", "2")
    monkeypatch.setenv("RATE_LIMIT_LOCKOUT_SECONDS", "45")
    monkeypatch.setenv("AUDIT_CAPACITY", "500")
    settings = load_settings()
    log.info("场景=环境变量覆盖 | settings=%s | 结果=通过", settings)
    assert settings == Settings(ttl_seconds=120.0, max_failures=2,
                                lockout_seconds=45.0, audit_capacity=500)
    # 应用工厂消费环境变量：阈值 2 即锁定
    client = TestClient(create_app(settings=settings))
    for _ in range(2):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    assert resp.status_code == 429


def test_env_defaults_unchanged(monkeypatch):
    for name in ("SESSION_TTL_SECONDS", "RATE_LIMIT_MAX_FAILURES",
                 "RATE_LIMIT_LOCKOUT_SECONDS", "AUDIT_CAPACITY"):
        monkeypatch.delenv(name, raising=False)
    settings = load_settings()
    log.info("场景=缺省回退默认 | settings=%s | 结果=通过", settings)
    assert settings == Settings()  # 3600s / 5 次 / 30s / 10000 条
    # 非法值同样回退默认
    bad = load_settings({"SESSION_TTL_SECONDS": "abc", "RATE_LIMIT_MAX_FAILURES": "-1",
                         "AUDIT_CAPACITY": ""})
    assert bad == Settings()
