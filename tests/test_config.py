"""运行参数：环境变量可配置，缺省保持既有默认行为。"""

import logging
import time

from fastapi.testclient import TestClient

from app.config import Settings, load_settings
from main import create_app

log = logging.getLogger(__name__)


def test_defaults_match_legacy_behavior(monkeypatch):
    for var in ("SAC_SESSION_TTL_SECONDS", "SAC_MAX_FAILURES", "SAC_LOCKOUT_SECONDS", "SAC_AUDIT_CAPACITY"):
        monkeypatch.delenv(var, raising=False)
    s = load_settings()
    log.info("场景: 无环境变量 | 结果: %s", s)
    assert s == Settings(session_ttl_seconds=3600.0, max_failures=5,
                         lockout_seconds=30.0, audit_capacity=10000)


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("SAC_SESSION_TTL_SECONDS", "0.05")
    monkeypatch.setenv("SAC_MAX_FAILURES", "2")
    monkeypatch.setenv("SAC_LOCKOUT_SECONDS", "0.2")
    monkeypatch.setenv("SAC_AUDIT_CAPACITY", "7")
    s = load_settings()
    log.info("场景: 环境变量覆盖 | 结果: %s", s)
    assert s.session_ttl_seconds == 0.05
    assert s.max_failures == 2
    assert s.lockout_seconds == 0.2
    assert s.audit_capacity == 7


def test_app_uses_env_settings(monkeypatch):
    monkeypatch.setenv("SAC_SESSION_TTL_SECONDS", "0.05")
    monkeypatch.setenv("SAC_MAX_FAILURES", "2")
    monkeypatch.setenv("SAC_AUDIT_CAPACITY", "3")
    client = TestClient(create_app())
    # TTL 来自环境变量：0.05s 后凭据过期
    tok = client.post("/sessions", json={"subject": "alice"}).json()["token"]
    time.sleep(0.1)
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": tok})
    assert resp.status_code == 401 and resp.json()["error"] == "credential_expired"
    # 审计容量来自环境变量
    for i in range(5):
        client.post("/sessions", json={"subject": f"u{i}"})
    audit = client.get("/status").json()["audit"]
    log.info("场景: 环境变量生效 | 结果: audit=%s", audit)
    assert audit["capacity"] == 3 and audit["size"] == 3 and audit["evicted"] > 0


def test_explicit_args_still_win_over_env(monkeypatch):
    monkeypatch.setenv("SAC_MAX_FAILURES", "100")
    client = TestClient(create_app(max_failures=2, lockout_seconds=5))
    for _ in range(2):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    log.info("场景: 显式参数优先于环境变量 | 结果: %d", resp.status_code)
    assert resp.status_code == 429  # 显式 max_failures=2 生效而非环境变量的 100
