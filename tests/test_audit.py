"""审计：记录写入、筛选分页、容量淘汰不影响会话/限流状态、并发计数准确。"""

import concurrent.futures
import logging

import pytest
from fastapi.testclient import TestClient

from app.audit import AuditQuery, AuditStore
from main import create_app

log = logging.getLogger(__name__)


# ---------- AuditStore 单元级 ----------

def test_append_assigns_monotonic_seq_and_is_queryable():
    store = AuditStore(capacity=10)
    r1 = store.append(trace_id="t1", source="s", subject="alice", action="resource_access",
                      resource_id="doc-1", outcome="allowed", reason="allowed", ts=100.0)
    r2 = store.append(trace_id="t2", source="s", subject="bob", action="resource_access",
                      resource_id="doc-2", outcome="denied", reason="forbidden_ownership", ts=200.0)
    log.info("场景: 顺序写入 | 结果: seq=%d,%d", r1.seq, r2.seq)
    assert r1.seq < r2.seq  # 顺序可解释
    page = store.query(AuditQuery())
    assert page.total == 2 and [r.seq for r in page.records] == [r1.seq, r2.seq]


def test_query_filters_by_time_subject_outcome():
    store = AuditStore(capacity=10)
    store.append(trace_id="t", source="s", subject="alice", action="a", outcome="allowed", reason="r", ts=100.0)
    store.append(trace_id="t", source="s", subject="bob", action="a", outcome="denied", reason="r", ts=200.0)
    store.append(trace_id="t", source="s", subject="alice", action="a", outcome="denied", reason="r", ts=300.0)
    by_subject = store.query(AuditQuery(subject="alice"))
    by_outcome = store.query(AuditQuery(outcome="denied"))
    by_time = store.query(AuditQuery(start_ts=150.0, end_ts=250.0))
    log.info("场景: 组合筛选 | 结果: subject=%d outcome=%d time=%d",
             by_subject.total, by_outcome.total, by_time.total)
    assert by_subject.total == 2
    assert by_outcome.total == 2
    assert by_time.total == 1 and by_time.records[0].ts == 200.0


def test_query_pagination():
    store = AuditStore(capacity=100)
    for i in range(25):
        store.append(trace_id="t", source="s", action="a", outcome="allowed", reason="r", ts=float(i))
    p1 = store.query(AuditQuery(offset=0, limit=10))
    p2 = store.query(AuditQuery(offset=10, limit=10))
    p3 = store.query(AuditQuery(offset=20, limit=10))
    log.info("场景: 分页 | 结果: total=%d 页大小=%d/%d/%d", p1.total, len(p1.records), len(p2.records), len(p3.records))
    assert p1.total == p2.total == p3.total == 25
    assert (len(p1.records), len(p2.records), len(p3.records)) == (10, 10, 5)
    seqs = [r.seq for r in p1.records + p2.records + p3.records]
    assert seqs == sorted(seqs) and len(set(seqs)) == 25  # 不重不漏


def test_capacity_eviction_drops_oldest_and_counts():
    store = AuditStore(capacity=5)
    for i in range(8):
        store.append(trace_id=f"t{i}", source="s", action="a", outcome="allowed", reason="r")
    stats = store.stats()
    page = store.query(AuditQuery())
    log.info("场景: 容量淘汰 | 结果: %s 剩余seq=%s", stats, [r.seq for r in page.records])
    assert stats == {"size": 5, "capacity": 5, "evicted": 3, "total_appended": 8}
    assert [r.seq for r in page.records] == [4, 5, 6, 7, 8]  # 最旧的被淘汰


def test_concurrent_appends_no_loss_no_dup():
    store = AuditStore(capacity=10000)

    def worker(_):
        for _ in range(250):
            store.append(trace_id="t", source="s", action="a", outcome="allowed", reason="r")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(worker, range(8)))
    stats = store.stats()
    seqs = [r.seq for r in store.query(AuditQuery(limit=5000)).records]
    log.info("场景: 8 线程 x 250 次并发写入 | 结果: %s", stats)
    assert stats["size"] == 2000 and stats["total_appended"] == 2000  # 不丢
    assert len(set(seqs)) == 2000 and seqs == sorted(seqs)            # 不重、顺序可解释


# ---------- 端到端：审计随请求写入 + 查询端点 ----------

@pytest.fixture
def client():
    return TestClient(create_app())


def _issue(client, subject="alice") -> str:
    resp = client.post("/sessions", json={"subject": subject, "roles": ["user"], "scopes": ["doc:read"]})
    assert resp.status_code == 201
    return resp.json()["token"]


def test_access_decisions_are_audited_with_inputs_and_basis(client):
    token = _issue(client, "alice")
    ok = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    denied = client.get("/resources/doc-2", headers={"X-Session-Token": token})
    bad = client.get("/resources/doc-1", headers={"X-Session-Token": "nope"})
    page = client.get("/audit").json()
    records = [r for r in page["records"] if r["action"] == "resource_access"]
    log.info("场景: 放行/越权/坏凭据各一次 | 结果: 审计=%s",
             [(r["outcome"], r["reason"]) for r in records])
    assert len(records) == 3
    allowed = next(r for r in records if r["outcome"] == "allowed")
    assert allowed["subject"] == "alice" and allowed["resource_id"] == "doc-1"
    assert allowed["source"] and allowed["trace_id"] == ok.headers["X-Trace-Id"]
    authz = next(r for r in records if r["reason"] == "forbidden_ownership")
    assert authz["resource_id"] == "doc-2" and "matched_owner=False" in authz["detail"]
    assert authz["trace_id"] == denied.headers["X-Trace-Id"]
    cred = next(r for r in records if r["reason"] == "credential_unknown")
    assert cred["trace_id"] == bad.headers["X-Trace-Id"]


def test_audit_endpoint_filters_and_paginates(client):
    token = _issue(client, "alice")
    client.get("/resources/doc-1", headers={"X-Session-Token": token})   # allowed
    client.get("/resources/doc-2", headers={"X-Session-Token": token})   # denied
    denied_page = client.get("/audit", params={"outcome": "denied"}).json()
    alice_page = client.get("/audit", params={"subject": "alice"}).json()
    paged = client.get("/audit", params={"limit": 1, "offset": 1}).json()
    log.info("场景: 端点筛选分页 | 结果: denied=%d alice=%d 分页total=%d",
             denied_page["total"], alice_page["total"], paged["total"])
    assert denied_page["total"] == 1
    assert all(r["outcome"] == "denied" for r in denied_page["records"])
    assert alice_page["total"] >= 2 and all(r["subject"] == "alice" for r in alice_page["records"])
    assert paged["total"] >= 3 and len(paged["records"]) == 1


def test_audit_eviction_does_not_affect_sessions_or_rate_limit():
    app = create_app(audit_capacity=4, max_failures=3, lockout_seconds=60)
    client = TestClient(app)
    token = _issue(client, "alice")
    # 2 次失败（阈值 3，未锁定）
    client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    # 用签发请求制造审计写入（不触碰限流计数），把前面的记录全部淘汰
    for i in range(10):
        assert client.post("/sessions", json={"subject": f"u{i}"}).status_code == 201
    stats = client.get("/status").json()["audit"]
    log.info("场景: 审计淘汰后状态 | 结果: %s", stats)
    assert stats["size"] == 4 and stats["evicted"] > 0
    # 会话仍然有效
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    assert resp.status_code == 200
    # 成功访问清零计数后，重新累计：恰好第 3 次失败触发锁定，证明计数语义未被审计淘汰干扰
    client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    third = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    assert third.status_code == 401  # 第 3 次失败本身仍是凭据错误（此次触发锁定）
    fourth = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    assert fourth.status_code == 429  # 下一次起被锁定
    log.info("场景: 淘汰后会话/限流 | 结果: 会话=200 第3次=%d 第4次=%d", third.status_code, fourth.status_code)
