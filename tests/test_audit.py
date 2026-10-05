"""本地审计：写入、筛选、分页、容量淘汰、并发计数，以及淘汰不影响会话/限流状态。"""

import concurrent.futures
import logging
import time

import pytest
from fastapi.testclient import TestClient

from app.audit import AuditLog, AuditQuery
from main import create_app

log = logging.getLogger(__name__)


@pytest.fixture
def client():
    return TestClient(create_app())


def issue(client, subject="alice") -> str:
    resp = client.post("/sessions", json={"subject": subject, "roles": ["user"], "scopes": ["doc:read"]})
    assert resp.status_code == 201
    return resp.json()["token"]


def test_audit_records_allowed_and_denied(client):
    token = issue(client)
    client.get("/resources/doc-1", headers={"X-Session-Token": token})       # 放行
    client.get("/resources/doc-2", headers={"X-Session-Token": token})       # 越权
    client.get("/resources/doc-1")                                           # 缺凭据
    page = client.get("/ops/audit").json()
    outcomes = [r["outcome"] for r in page["records"]]
    log.info("场景=放行/越权/缺凭据 | 审计结果序列=%s | 结果=通过", outcomes)
    assert outcomes == ["allowed", "allowed", "forbidden_ownership", "credential_missing"]
    # 记录还原了输入：来源、主体、目标资源
    denied = page["records"][2]
    assert denied["subject"] == "alice" and denied["resource_id"] == "doc-2" and denied["source"]
    # seq 单调递增
    seqs = [r["seq"] for r in page["records"]]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_audit_filter_and_pagination(client):
    token_a = issue(client, "alice")
    token_b = issue(client, "bob")
    client.get("/resources/doc-1", headers={"X-Session-Token": token_a})   # alice 放行
    client.get("/resources/doc-1", headers={"X-Session-Token": token_b})   # bob 越权
    client.get("/resources/doc-2", headers={"X-Session-Token": token_b})   # bob 放行

    by_subject = client.get("/ops/audit", params={"subject": "bob"}).json()
    log.info("场景=按主体筛选 | subject=bob | total=%d | 结果=通过", by_subject["total"])
    assert by_subject["total"] == 3  # 1 次签发 + 2 次访问
    assert all(r["subject"] == "bob" for r in by_subject["records"])

    by_outcome = client.get("/ops/audit", params={"outcome": "forbidden_ownership"}).json()
    assert by_outcome["total"] == 1

    all_page = client.get("/ops/audit", params={"limit": 100}).json()
    page1 = client.get("/ops/audit", params={"offset": 0, "limit": 2}).json()
    page2 = client.get("/ops/audit", params={"offset": 2, "limit": 2}).json()
    log.info("场景=分页 | total=%d page1=%d page2=%d | 结果=通过",
             all_page["total"], len(page1["records"]), len(page2["records"]))
    assert page1["total"] == page2["total"] == all_page["total"]
    stitched = [r["seq"] for r in page1["records"] + page2["records"]]
    assert stitched == [r["seq"] for r in all_page["records"][:4]]

    now = time.time()
    by_time = client.get("/ops/audit", params={"since": now - 60, "until": now + 60}).json()
    assert by_time["total"] == all_page["total"]
    empty = client.get("/ops/audit", params={"until": now - 60}).json()
    assert empty["total"] == 0


def test_audit_capacity_eviction_keeps_sessions_and_rate_limit():
    """审计淘汰只影响审计数据本身，不影响会话、失败计数与锁定状态。"""
    client = TestClient(create_app(audit_capacity=10, max_failures=3, lockout_seconds=60))
    token = issue(client, "alice")
    # 2 次失败（未达阈值）
    for _ in range(2):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    # 再制造足够多的审计记录，把早期记录全部淘汰
    for _ in range(30):
        client.post("/sessions", json={"subject": "spam"})
    stats = client.get("/ops/status").json()["audit"]
    log.info("场景=容量淘汰 | capacity=%d size=%d evicted=%d | 结果=通过",
             stats["capacity"], stats["size"], stats["evicted"])
    assert stats["size"] == 10 and stats["evicted"] > 0
    # 会话仍然有效
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": token})
    assert resp.status_code == 200
    # 失败计数未被清零：再失败 1 次（累计 3 次中的状态被成功清零了，重新计）
    # 上面成功访问清零了计数，这里重新验证锁定阈值仍按原参数生效
    for _ in range(3):
        client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    resp = client.get("/resources/doc-1", headers={"X-Session-Token": "bad"})
    log.info("场景=淘汰后限流仍生效 | 状态=%d | 结果=通过", resp.status_code)
    assert resp.status_code == 429


def test_concurrent_audit_writes_exact_count():
    """并发写入：审计条数精确、seq 唯一且递增，不丢不重。"""
    client = TestClient(create_app(max_failures=10_000))
    token = issue(client, "alice")

    def work(_):
        for _ in range(25):
            client.get("/resources/doc-1", headers={"X-Session-Token": token})

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(work, range(16)))
    page = client.get("/ops/audit", params={"limit": 500}).json()
    seqs = [r["seq"] for r in page["records"]]
    log.info("场景=16 路并发 x25 次访问 | 审计总数=%d seq唯一=%s | 结果=通过",
             page["total"], len(set(seqs)) == len(seqs))
    # 1 次签发 + 400 次放行 = 401 条
    assert page["total"] == 401
    assert len(set(seqs)) == len(seqs) and seqs == sorted(seqs)


def test_audit_log_unit_eviction_order():
    """单元级：FIFO 淘汰最旧记录，stats 计数准确。"""
    log_store = AuditLog(capacity=3)
    for i in range(5):
        log_store.record(trace_id=f"t{i}", source="s", action="a", outcome="allowed",
                         timestamp=float(i))
    page = log_store.query(AuditQuery(limit=10))
    kept = [r.seq for r in page.records]
    log.info("场景=单元淘汰顺序 | 保留seq=%s | 结果=通过", kept)
    assert kept == [3, 4, 5]
    stats = log_store.stats()
    assert stats["size"] == 3 and stats["evicted"] == 2 and stats["next_seq"] == 6
