"""本地审计存储：有界、线程安全、可筛选分页查询。

设计要点：
- 每条记录分配单调递增 seq，写入顺序可解释（seq 即全局写入顺序）；
- 追加在锁内完成，并发下不丢、不重；
- 容量有界（deque maxlen），写满后淘汰最旧记录并累计 evicted 计数；
- 审计存储与会话/限流状态完全独立，淘汰不影响任何在生效的状态。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuditRecord:
    """一次访问判定的审计记录。"""

    seq: int                 # 单调递增序号，解释写入顺序
    ts: float                # 写入时刻（epoch 秒）
    trace_id: str            # 请求追踪标识
    source: str              # 来源（客户端 IP）
    subject: str             # 主体（未知时为 ""）
    action: str              # 动作，如 resource_access / rotate / issue
    resource_id: str         # 目标资源（无则为 ""）
    outcome: str             # allowed / denied
    reason: str              # 判定依据（拒绝原因或 allowed）
    detail: str = ""         # 附加判定信息（如 matched_scope/owner）


@dataclass(frozen=True)
class AuditQuery:
    """审计查询条件：时间范围、主体、结果 + 分页。"""

    start_ts: float | None = None
    end_ts: float | None = None
    subject: str | None = None
    outcome: str | None = None
    offset: int = 0
    limit: int = 100


@dataclass(frozen=True)
class AuditPage:
    """分页查询结果。"""

    total: int               # 命中条件（未分页）的总数
    records: tuple[AuditRecord, ...] = field(default_factory=tuple)


class AuditStore:
    """有界审计存储。所有可变操作在同一把锁下完成。"""

    def __init__(self, capacity: int = 10000):
        if capacity <= 0:
            raise ValueError("audit capacity must be positive")
        self._capacity = capacity
        self._lock = threading.Lock()
        self._records: deque[AuditRecord] = deque(maxlen=capacity)
        self._seq = 0
        self._evicted = 0

    def append(
        self,
        *,
        trace_id: str,
        source: str,
        subject: str = "",
        action: str,
        resource_id: str = "",
        outcome: str,
        reason: str,
        detail: str = "",
        ts: float | None = None,
    ) -> AuditRecord:
        """追加一条审计记录。seq 分配与入队在同一锁内，保证顺序可解释、不丢不重。"""
        with self._lock:
            if len(self._records) >= self._capacity:
                self._evicted += 1
            self._seq += 1
            record = AuditRecord(
                seq=self._seq,
                ts=time.time() if ts is None else ts,
                trace_id=trace_id,
                source=source,
                subject=subject,
                action=action,
                resource_id=resource_id,
                outcome=outcome,
                reason=reason,
                detail=detail,
            )
            self._records.append(record)
            return record

    def query(self, q: AuditQuery | None = None) -> AuditPage:
        """按条件筛选并分页返回。结果按 seq 升序（即写入顺序）。"""
        q = q or AuditQuery()
        with self._lock:
            snapshot = list(self._records)
        matched = [
            r for r in snapshot
            if (q.start_ts is None or r.ts >= q.start_ts)
            and (q.end_ts is None or r.ts <= q.end_ts)
            and (q.subject is None or r.subject == q.subject)
            and (q.outcome is None or r.outcome == q.outcome)
        ]
        page = matched[q.offset: q.offset + q.limit]
        return AuditPage(total=len(matched), records=tuple(page))

    def stats(self) -> dict:
        """存储占用情况：当前条数、容量、已淘汰条数、已分配序号总数。"""
        with self._lock:
            return {
                "size": len(self._records),
                "capacity": self._capacity,
                "evicted": self._evicted,
                "total_appended": self._seq,
            }
