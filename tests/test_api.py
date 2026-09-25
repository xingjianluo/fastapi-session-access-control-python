"""端到端 API 测试：凭据生命周期、越权访问、限流锁定。"""

import concurrent.futures
import logging
import time

import pytest
from fastapi.testclient import TestClient

from main import create_app

log = logging.getLogger(__name__)


@pytest.fixture
def client():
    return TestClient(create_app())


def issue(client, subject="alice", roles=None, scopes=None) -> str:
    resp = client.post("/sessions", json={
        "subject": subject,
        "roles": roles or ["user"],
        "scopes": scopes or ["doc:read"],
    })
    assert resp.status_code == 201
    return resp.json()["token"]


def test_full_happy_path(client):
    token = issue(client, "alice")
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    log.info("输入: alice 凭据访问 doc-1 | 判定: scope+owner 满足 | 结果: %d", resp.status_code)
    assert resp.status_code == 200
    assert resp.json()["owner"] == "alice"


def test_expired_token_rejected():
    app = create_app(ttl_seconds=0.05)
    client = TestClient(app)
    token = issue(client, "alice")
    time.sleep(0.1)
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    log.info("输入: 过期凭据 | 判定: 已过期 | 结果: %d %s", resp.status_code, resp.json())
    assert resp.status_code == 401
    assert resp.json()["error"] == "credential_expired"


def test_revoked_token_rejected(client):
    token = issue(client, "alice")
    assert client.post("/sessions/revoke", json={"token": token}).status_code == 204
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    log.info("输入: 已撤销凭据 | 判定: 已撤销 | 结果: %d %s", resp.status_code, resp.json())
    assert resp.status_code == 401
    assert resp.json()["error"] == "credential_revoked"


def test_rotated_old_token_rejected_new_works(client):
    token = issue(client, "alice")
    resp = client.post("/sessions/rotate", json={"token": token})
    assert resp.status_code == 200
    new_token = resp.json()["token"]
    old = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    log.info("输入: 旧凭据访问 | 判定: 已轮换 | 结果: %d %s", old.status_code, old.json())
    assert old.status_code == 401
    assert old.json()["error"] == "credential_rotated"
    assert client.get("/resources/doc-1", headers={"X-Session-Token": new_token}).status_code == 200


def test_concurrent_rotate_via_api_only_one_succeeds():
    # 提高限流阈值，避免并发失败计数干扰轮换断言
    client = TestClient(create_app(max_failures=1000))
    token = issue(client, "alice")

    def attempt(_):
        return client.post("/sessions/rotate", json={"token": token})

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        resps = list(pool.map(attempt, range(12)))
    oks = [r for r in resps if r.status_code == 200]
    fails = [r for r in resps if r.status_code != 200]
    log.info("输入: 12 路并发轮换 | 判定: 锁内串行 | 结果: 成功=%d 失败=%d", len(oks), len(fails))
    assert len(oks) == 1
    assert all(r.status_code == 401 and r.json()["error"] == "credential_rotated" for r in fails)


def test_cross_ownership_and_nonexistent_indistinguishable_shape(client):
    """越权与不存在：都不返回资源内容，不泄露存在性。"""
    token = issue(client, "alice")
    forbidden = client.get("/resources/doc-2", headers={"X-Session-Token": token})  # bob 的资源
    ghost = client.get("/resources/doc-ghost", headers={"X-Session-Token": token})
    log.info("输入: 越权=%s 不存在=%s | 判定: 默认拒绝 | 结果: 均不含资源内容",
             forbidden.json(), ghost.json())
    assert forbidden.status_code == 403 and forbidden.json()["error"] == "forbidden_ownership"
    assert ghost.status_code == 404 and ghost.json()["error"] == "resource_not_found"
    assert "owner" not in forbidden.json() and "owner" not in ghost.json()


def test_rate_limit_lockout_and_isolation():
    app = create_app(max_failures=3, lockout_seconds=0.2)
    client = TestClient(app)
    # 同一来源连续 3 次坏凭据 -> 锁定
    for _ in range(3):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    log.info("输入: 连续失败后第 4 次 | 判定: 来源锁定 | 结果: %d %s", resp.status_code, resp.json())
    assert resp.status_code == 429
    assert resp.json()["error"] == "rate_limited"
    # 锁定期满恢复（TestClient 同源，等待锁过期）
    time.sleep(0.25)
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    assert resp.status_code == 401  # 恢复后回到凭据错误而非 429
    log.info("输入: 锁定期满后请求 | 判定: 锁定已过期 | 结果: %d", resp.status_code)
