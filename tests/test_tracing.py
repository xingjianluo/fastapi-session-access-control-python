"""请求追踪：成功/各类拒绝/未预期异常下，响应都能拿到一致结构的追踪标识。"""

import logging

import pytest
from fastapi.testclient import TestClient

from main import create_app

log = logging.getLogger(__name__)


@pytest.fixture
def client():
    return TestClient(create_app())


def issue(client, subject="alice") -> str:
    resp = client.post("/sessions", json={"subject": subject, "roles": ["user"], "scopes": ["doc:read"]})
    assert resp.status_code == 201
    return resp.json()["token"]


def _assert_trace_consistent(resp):
    """响应头与响应体（若有）中的 trace_id 一致且非空。"""
    tid = resp.headers.get("x-trace-id")
    assert tid, f"缺少 X-Trace-Id 响应头: {resp.status_code}"
    body = resp.json() if resp.content else None
    if body and "trace_id" in body:
        assert body["trace_id"] == tid
    return tid


def test_trace_id_on_success(client):
    token = issue(client)
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    tid = _assert_trace_consistent(resp)
    log.info("场景=成功访问 | 状态=%d | trace_id=%s | 结果=通过", resp.status_code, tid)
    assert resp.status_code == 200


def test_trace_id_on_credential_failures(client):
    token = issue(client)
    client.post("/sessions/revoke", json={"token": token})
    cases = {
        "缺失": {},
        "未知": {"X-Session-Token": "nope"},
        "已撤销": {"X-Session-Token": token},
    }
    for label, headers in cases.items():
        resp = client.get("/resources/doc-1", headers=headers)
        tid = _assert_trace_consistent(resp)
        body = resp.json()
        log.info("场景=凭据拒绝(%s) | 状态=%d | error=%s | trace_id=%s | 结果=通过",
                 label, resp.status_code, body["error"], tid)
        assert resp.status_code == 401
        assert set(body) == {"error", "detail", "trace_id"}


def test_trace_id_on_authz_and_not_found(client):
    token = issue(client)
    for path, expect in [("/resources/doc-2", 403), ("/resources/doc-ghost", 404)]:
        resp = client.get(path, headers={"X-Session-Token": token})
        tid = _assert_trace_consistent(resp)
        log.info("场景=授权拒绝(%s) | 状态=%d | error=%s | trace_id=%s | 结果=通过",
                 path, resp.status_code, resp.json()["error"], tid)
        assert resp.status_code == expect


def test_trace_id_on_rate_limited():
    client = TestClient(create_app(max_failures=2, lockout_seconds=60))
    for _ in range(2):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    tid = _assert_trace_consistent(resp)
    log.info("场景=限流锁定 | 状态=%d | error=%s | trace_id=%s | 结果=通过",
             resp.status_code, resp.json()["error"], tid)
    assert resp.status_code == 429
    assert resp.json()["error"] == "rate_limited"


def test_trace_id_on_unexpected_exception():
    """未预期异常：统一 500 结构，不暴露堆栈，trace_id 可关联。"""
    app = create_app()

    @app.get("/boom")
    def boom():
        raise RuntimeError("secret internal detail")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    tid = _assert_trace_consistent(resp)
    body = resp.json()
    log.info("场景=未预期异常 | 状态=%d | body=%s | trace_id=%s | 结果=通过",
             resp.status_code, body, tid)
    assert resp.status_code == 500
    assert body == {"error": "internal_error", "detail": "服务内部错误", "trace_id": tid}
    assert "secret" not in resp.text and "Traceback" not in resp.text


def test_client_supplied_trace_id_is_honored(client):
    resp = client.get("/resources/doc-1", headers={"X-Trace-Id": "caller-trace-42"})
    assert resp.headers["x-trace-id"] == "caller-trace-42"
    assert resp.json()["trace_id"] == "caller-trace-42"
    log.info("场景=调用方传入追踪标识 | trace_id=%s | 结果=通过", "caller-trace-42")


def test_trace_id_links_to_audit_record(client):
    """响应中的 trace_id 能在审计记录中查到同一次判定。"""
    token = issue(client)
    resp = client.get("/resources/doc-2", headers={"X-Session-Token": token})
    tid = resp.headers["x-trace-id"]
    page = client.get("/ops/audit", params={"outcome": "forbidden_ownership"}).json()
    matched = [r for r in page["records"] if r["trace_id"] == tid]
    log.info("场景=追踪标识关联审计 | trace_id=%s | 命中=%d | 结果=通过", tid, len(matched))
    assert len(matched) == 1
    assert matched[0]["resource_id"] == "doc-2"
