"""请求追踪：成功与各类失败分支都能拿到一致结构的追踪标识；未预期异常统一兜底。"""

import logging

import pytest
from fastapi.testclient import TestClient

from main import create_app

log = logging.getLogger(__name__)


@pytest.fixture
def client():
    return TestClient(create_app())


def _issue(client, subject="alice") -> str:
    resp = client.post("/sessions", json={"subject": subject, "roles": ["user"], "scopes": ["doc:read"]})
    assert resp.status_code == 201
    return resp.json()["token"]


def _assert_trace(resp):
    """响应头与（错误分支的）响应体 trace_id 一致且非空。"""
    header = resp.headers.get("X-Trace-Id")
    assert header, f"缺少 X-Trace-Id 响应头: {resp.status_code}"
    body = resp.json()
    if "trace_id" in body:
        assert body["trace_id"] == header
    return header


def test_success_response_has_trace_header(client):
    token = _issue(client)
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    log.info("场景: 成功访问 | 结果: %d trace=%s", resp.status_code, resp.headers.get("X-Trace-Id"))
    assert resp.status_code == 200
    _assert_trace(resp)


def test_each_request_gets_distinct_trace_id(client):
    token = _issue(client)
    ids = {
        client.get("/resources/doc-1", headers={"X-Session-Token": token}).headers["X-Trace-Id"]
        for _ in range(3)
    }
    log.info("场景: 连续 3 次请求 | 结果: trace_id 各不相同=%s", ids)
    assert len(ids) == 3


def test_credential_failures_share_consistent_envelope(client):
    cases = {
        "missing": {},
        "unknown": {"X-Session-Token": "nope"},
    }
    token = _issue(client)
    client.post("/sessions/revoke", json={"token": token})
    cases["revoked"] = {"X-Session-Token": token}
    for name, headers in cases.items():
        resp = client.get("/resources/doc-1", headers=headers)
        body = resp.json()
        log.info("场景: 凭据失败(%s) | 结果: %d %s", name, resp.status_code, body)
        assert resp.status_code == 401
        assert set(body) == {"error", "detail", "trace_id"}  # 各分支结构一致
        _assert_trace(resp)


def test_authz_denied_and_not_found_have_trace(client):
    token = _issue(client)
    for path, code in (("/resources/doc-2", 403), ("/resources/doc-ghost", 404)):
        resp = client.get(path, headers={"X-Session-Token": token})
        body = resp.json()
        log.info("场景: 授权拒绝(%s) | 结果: %d %s", path, resp.status_code, body)
        assert resp.status_code == code
        assert set(body) == {"error", "detail", "trace_id"}
        _assert_trace(resp)


def test_rate_limited_response_has_trace():
    client = TestClient(create_app(max_failures=2, lockout_seconds=5))
    for _ in range(2):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    body = resp.json()
    log.info("场景: 限流锁定 | 结果: %d %s", resp.status_code, body)
    assert resp.status_code == 429
    assert body["error"] == "rate_limited"
    assert set(body) == {"error", "detail", "trace_id"}
    _assert_trace(resp)


def test_unexpected_exception_uniform_shape_and_no_leak():
    app = create_app()

    @app.get("/boom")
    def boom():
        raise RuntimeError("db password=hunter2")  # 内部细节不得外泄

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/boom")
    body = resp.json()
    log.info("场景: 未预期异常 | 结果: %d %s", resp.status_code, body)
    assert resp.status_code == 500
    assert set(body) == {"error", "detail", "trace_id"}  # 与拒绝分支同一结构
    assert body["error"] == "internal_error"
    assert "hunter2" not in str(body) and "Traceback" not in str(body)
    _assert_trace(resp)


def test_unexpected_exception_logged_with_same_trace_id(caplog):
    app = create_app()

    @app.get("/boom")
    def boom():
        raise RuntimeError("boom")

    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR):
        resp = client.get("/boom")
    trace_id = resp.json()["trace_id"]
    matched = [r for r in caplog.records if trace_id in r.getMessage()]
    log.info("场景: 异常日志回查 | 结果: 命中日志=%d 条", len(matched))
    assert matched, "服务端日志应能用同一 trace_id 查到这次异常"
