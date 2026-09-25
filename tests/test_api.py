"""HTTP 链路集成测试。

覆盖：凭据过期、撤销、轮换后重复使用、并发轮换唯一成功、
越权/跨归属访问、连续失败锁定与恢复、审计依据可复现。
"""

import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient


def _err(r) -> dict:
    assert "error" in r.json(), r.text
    return r.json()["error"]


def _auth(token: str, source: str = "test-source") -> dict:
    return {"Authorization": f"Bearer {token}", "X-Source-ID": source}


def test_missing_and_unknown_credential_distinguishable(client):
    r = client.get("/resources/doc-alice", headers={"X-Source-ID": "s1"})
    assert r.status_code == 401 and _err(r)["reason"] == "missing_credential"
    r = client.get("/resources/doc-alice", headers=_auth("tok_nope", "s1"))
    assert r.status_code == 401 and _err(r)["reason"] == "credential_unknown"


def test_expired_credential_via_http(client, clock, issue):
    token = issue(client, "alice", scopes=["doc:read"], source="s2")
    clock.advance(101)
    r = client.get("/resources/doc-alice", headers=_auth(token, "s2"))
    assert r.status_code == 401 and _err(r)["reason"] == "credential_expired"
    rid = _err(r)["request_id"]
    audit = client.get(f"/_local/audit?request_id={rid}").json()
    rec = [a for a in audit if a["stage"] == "authenticate"][-1]
    assert rec["reason"] == "credential_expired"
    assert rec["evidence"]["now"] >= rec["evidence"]["expires_at"]


def test_revoked_credential_via_http(client, issue):
    token = issue(client, "alice", scopes=["doc:read"], source="s3")
    r = client.post("/auth/revoke", json={"token": token}, headers={"X-Source-ID": "s3"})
    assert r.status_code == 200 and r.json()["revoked"] is True
    r = client.get("/resources/doc-alice", headers=_auth(token, "s3"))
    assert r.status_code == 401 and _err(r)["reason"] == "credential_revoked"
    # 撤销幂等：再次撤销仍成功
    assert client.post("/auth/revoke", json={"token": token}, headers={"X-Source-ID": "s3"}).status_code == 200


def test_rotate_and_reuse_old_credential(client, issue):
    token = issue(client, "alice", scopes=["doc:read"], source="s4")
    r = client.post("/auth/rotate", headers=_auth(token, "s4"))
    assert r.status_code == 200
    new_token = r.json()["token"]
    assert new_token != token and r.json()["version"] == 2
    # 旧凭据重复使用：明确拒绝
    r = client.get("/resources/doc-alice", headers=_auth(token, "s4"))
    assert r.status_code == 401 and _err(r)["reason"] == "credential_rotated"
    # 旧凭据再次轮换也失败
    r = client.post("/auth/rotate", headers=_auth(token, "s4"))
    assert r.status_code == 401 and _err(r)["reason"] == "credential_rotated"
    # 新凭据正常
    assert client.get("/resources/doc-alice", headers=_auth(new_token, "s4")).status_code == 200


def test_concurrent_rotate_http_only_one_success(client, issue):
    """HTTP 层并发轮换：唯一成功，失败方拿不到任何可用凭据。"""
    token = issue(client, "alice", scopes=["doc:read"], source="s5")
    responses = []
    barrier = threading.Barrier(6)

    def rotate():
        barrier.wait()
        return client.post("/auth/rotate", headers=_auth(token, "s5"))

    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(lambda _: rotate(), range(6)))

    codes = [r.status_code for r in responses]
    assert codes.count(200) == 1, codes
    denied = [r for r in responses if r.status_code != 200]
    # 先到达临界区的失败者得到 401 credential_rotated；
    # 后到达者可能已触发连续失败节流而得到 429 source_locked——二者都未获得凭据
    assert {r.status_code for r in denied} <= {401, 429}
    reasons = {_err(r)["reason"] for r in denied}
    assert reasons <= {"credential_rotated", "source_locked"}
    assert "credential_rotated" in reasons
    # 401 拒绝的请求不会颁发任何新凭据（响应体不含 token 字段）
    for r in denied:
        assert "token" not in r.json()

    winner = [r for r in responses if r.status_code == 200][0].json()["token"]
    # 仅胜出凭据可用；原来源可能已因累计失败被锁定，用独立来源验证凭据本身有效
    assert client.get("/resources/doc-alice", headers=_auth(winner, "s5-verify")).status_code == 200
    assert client.get("/resources/doc-alice", headers=_auth(token, "s5-verify")).status_code == 401


def test_cross_owner_access_indistinguishable(client, issue):
    token = issue(client, "alice", scopes=["doc:read"], source="s6")
    # 跨归属
    r1 = client.get("/resources/doc-bob", headers=_auth(token, "s6"))
    # 不存在
    r2 = client.get("/resources/doc-missing", headers=_auth(token, "s6"))
    assert r1.status_code == r2.status_code == 404
    e1, e2 = _err(r1), _err(r2)
    assert e1["reason"] == e2["reason"] == "resource_not_found"
    assert e1["message"] == e2["message"]
    # 审计中真实原因仍可复现
    rid = e1["request_id"]
    rec = [
        a
        for a in client.get(f"/_local/audit?request_id={rid}").json()
        if a["stage"] == "authorize"
    ][-1]
    assert rec["reason"] == "forbidden_ownership"
    assert rec["evidence"]["resource_owner"] == "bob"


def test_scope_insufficient_is_403(client, issue):
    token = issue(client, "alice", roles=["reader"], scopes=["doc:read"], source="s7")
    r = client.get("/resources/doc-admin", headers=_auth(token, "s7"))
    assert r.status_code == 403 and _err(r)["reason"] == "forbidden_role_or_scope"


def test_failures_trigger_lock_then_recover(client, clock):
    # 阈值为 3（见 conftest settings），连续错误凭据 -> 第 3 次失败后锁定
    headers = {"X-Source-ID": "locked-src"}
    r1 = client.get("/resources/doc-alice", headers={**headers, "Authorization": "Bearer bad1"})
    r2 = client.get("/resources/doc-alice", headers={**headers, "Authorization": "Bearer bad2"})
    assert r1.status_code == r2.status_code == 401
    r3 = client.get("/resources/doc-alice", headers={**headers, "Authorization": "Bearer bad3"})
    assert r3.status_code == 401  # 第三次失败本身完成计数
    # 此后即使携带正确凭据也被节流
    tok = client.post(
        "/auth/sessions", json={"subject": "alice", "scopes": ["doc:read"]}, headers=headers
    ).json()["token"]
    r4 = client.get("/resources/doc-alice", headers=_auth(tok, "locked-src"))
    assert r4.status_code == 429 and _err(r4)["reason"] == "source_locked"
    # 状态端点可解释锁定与恢复时机
    st = client.get("/_local/status/locked-src").json()
    assert st["locked"] is True and st["failures"] == 3
    # 其它来源不受影响
    other = client.post(
        "/auth/sessions",
        json={"subject": "alice", "scopes": ["doc:read"]},
        headers={"X-Source-ID": "other-src"},
    ).json()["token"]
    assert client.get("/resources/doc-alice", headers=_auth(other, "other-src")).status_code == 200
    # 锁定期满自动恢复并清零
    clock.advance(31)
    r5 = client.get("/resources/doc-alice", headers=_auth(tok, "locked-src"))
    assert r5.status_code == 200
    assert client.get("/_local/status/locked-src").json()["failures"] == 0


def test_concurrent_failures_counted_once_each(client):
    """并发失败请求：计数不重不漏，锁定只在阈值处生效。"""
    n = 10
    barrier = threading.Barrier(n)

    def hit(_):
        barrier.wait()
        return client.get(
            "/resources/doc-alice",
            headers={"X-Source-ID": "race-src", "Authorization": "Bearer bad"},
        )

    with ThreadPoolExecutor(max_workers=n) as pool:
        responses = list(pool.map(hit, range(n)))
    # 前 3 个完成计数的请求得到 401，其余撞上锁定得 429；总数守恒
    codes = sorted(r.status_code for r in responses)
    assert codes.count(401) == 3, codes
    assert codes.count(429) == n - 3, codes
    st = client.get("/_local/status/race-src").json()
    assert st["failures"] == 3 and st["locked"] is True


def test_audit_records_input_evidence_and_result(client, issue):
    token = issue(client, "alice", scopes=["doc:read"], source="audit-src")
    r = client.get("/resources/doc-alice", headers=_auth(token, "audit-src"))
    rid = r.json()["request_id"]
    records = client.get(f"/_local/audit?request_id={rid}").json()
    stages = {rec["stage"] for rec in records}
    assert {"rate_limit", "authenticate", "authorize"} <= stages
    authz = [rec for rec in records if rec["stage"] == "authorize"][0]
    assert authz["decision"] == "allow"
    assert authz["evidence"]["subject"] == "alice"
    assert authz["evidence"]["scope_ok"] is True
