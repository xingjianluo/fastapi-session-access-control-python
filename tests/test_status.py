"""运行期状态观测：锁定状态、有效会话数、审计占用；不暴露凭据。"""

import logging
import time

from fastapi.testclient import TestClient

from main import create_app

log = logging.getLogger(__name__)


def test_status_reports_active_sessions_and_audit_usage():
    client = TestClient(create_app())
    r0 = client.get("/status").json()
    assert r0["active_sessions"] == 0
    client.post("/sessions", json={"subject": "alice"})
    client.post("/sessions", json={"subject": "bob"})
    r1 = client.get("/status").json()
    log.info("场景: 签发 2 个会话后查询状态 | 结果: %s", r1)
    assert r1["active_sessions"] == 2
    assert r1["locked"] is False and r1["locked_until"] is None
    assert r1["audit"]["size"] >= 2 and r1["audit"]["capacity"] == 10000
    assert "token" not in str(r1)  # 不暴露凭据


def test_status_reflects_rotation_and_revocation():
    client = TestClient(create_app())
    tok = client.post("/sessions", json={"subject": "alice"}).json()["token"]
    new_tok = client.post("/sessions/rotate", json={"token": tok}).json()["token"]
    assert client.get("/status").json()["active_sessions"] == 1  # 轮换后旧会话不计入
    client.post("/sessions/revoke", json={"token": new_tok})
    r = client.get("/status").json()
    log.info("场景: 轮换+撤销后 | 结果: active=%d", r["active_sessions"])
    assert r["active_sessions"] == 0


def test_status_reports_lockout_and_recovery_time():
    client = TestClient(create_app(max_failures=2, lockout_seconds=0.2))
    for _ in range(2):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    locked = client.get("/status").json()
    log.info("场景: 锁定中查询 | 结果: %s", locked)
    assert locked["locked"] is True
    assert locked["locked_until"] > time.time()  # 可看出何时恢复
    time.sleep(0.25)
    recovered = client.get("/status").json()
    log.info("场景: 锁定期满查询 | 结果: %s", recovered)
    assert recovered["locked"] is False and recovered["locked_until"] is None


def test_status_source_param():
    client = TestClient(create_app())
    r = client.get("/status", params={"source": "10.0.0.9"}).json()
    log.info("场景: 指定来源查询 | 结果: %s", r)
    assert r["source"] == "10.0.0.9" and r["locked"] is False
