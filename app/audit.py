"""本地审计日志：记录每次访问判定，支持筛选、分页、容量淘汰（线程安全）。"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditRecord:
    """一次访问判定的审计记录（不可变）。

    - seq: 单调递增序号，写入顺序可解释（并发下由锁保证唯一且递增）
    - trace_id: 与响应对应的请求追踪标识
    - outcome: "allowed" 或拒绝原因（RejectionReason.value）
    """

    seq: int
    trace_id: str
    timestamp: float
    source: str            # 来源（客户端 IP）
    subject: str           # 主体；凭据不可知时为空串
    action: str            # 动作，如 "resource:read" / "session:rotate"
    resource_id: str       # 目标资源；无资源语义时为空串
    outcome: str           # 判定结果
    detail: str = ""       # 判定依据补充说明


@dataclass(frozen=True)
class AuditQuery:
    """审计筛选条件。None 表示不限制。"""

    since: float | None = None      # 时间范围下界（含）
    until: float | None = None      # 时间范围上界（含）
    subject: str | None = None      # 按主体精确匹配
    outcome: str | None = None      # 按结果精确匹配
    offset: int = 0                 # 分页偏移
    limit: int = 50                 # 分页大小


@dataclass(frozen=True)
class AuditPage:
    """一页审计结果。"""

    total: int                      # 满足筛选条件的总条数
    offset: int
    limit: int
    records: tuple[AuditRecord, ...]


class AuditLog:
    """有容量上限的审计存储。

    - 写入在锁内完成：并发下不丢、不重，seq 单调递增；
    - 容量满时淘汰最旧记录（FIFO），只影响审计数据本身，
      不涉及会话、失败计数或锁定状态；
    - 查询返回按 seq 升序（时间序）的分页结果。
    """

    def __init__(self, capacity: int = 10_000):
        self._capacity = max(1, capacity)
        self._lock = threading.Lock()
        self._records: deque[AuditRecord] = deque()
        self._next_seq = 1
        self._evicted = 0

    def record(
        self,
        *,
        trace_id: str,
        source: str,
        subject: str = "",
        action: str,
        resource_id: str = "",
        outcome: str,
        detail: str = "",
        timestamp: float | None = None,
    ) -> AuditRecord:
        """写入一条审计记录。

        序号分配与追加在同一把锁内完成：并发下每条记录恰好写入一次，
        seq 单调递增且与落库顺序一致。容量满时淘汰最旧记录（FIFO）。
        """
        rec = AuditRecord(
            seq=0,  # 占位，锁内分配真实序号
            trace_id=trace_id,
            timestamp=time.time() if timestamp is None else timestamp,
            source=source,
            subject=subject,
            action=action,
            resource_id=resource_id,
            outcome=outcome,
            detail=detail,
        )
        with self._lock:
            rec = AuditRecord(
                seq=self._next_seq,
                trace_id=rec.trace_id,
                timestamp=rec.timestamp,
                source=rec.source,
                subject=rec.subject,
                action=rec.action,
                resource_id=rec.resource_id,
                outcome=rec.outcome,
                detail=rec.detail,
            )
            self._next_seq += 1
            while len(self._records) >= self._capacity:
                self._records.popleft()
                self._evicted += 1
            self._records.append(rec)
        return rec

    def _matches(self, rec: AuditRecord, q: AuditQuery) -> bool:
        if q.since is not None and rec.timestamp < q.since:
            return False
        if q.until is not None and rec.timestamp > q.until:
            return False
        if q.subject is not None and rec.subject != q.subject:
            return False
        return not (q.outcome is not None and rec.outcome != q.outcome)

    def query(self, q: AuditQuery | None = None) -> AuditPage:
        """按条件筛选并分页返回（按 seq 升序，即写入时间序）。

        在锁内对当前快照做筛选，返回不可变元组，调用方看到的是一致快照。
        """
        q = q or AuditQuery()
        offset = max(0, q.offset)
        limit = max(0, q.limit)
        with self._lock:
            matched = [r for r in self._records if self._matches(r, q)]
        total = len(matched)
        page = matched[offset : offset + limit]
        return AuditPage(total=total, offset=offset, limit=limit, records=tuple(page))

    def stats(self) -> dict:
        """存储占用情况：容量、现存条数、已淘汰条数、已分配序号上界。"""
        with self._lock:
            return {
                "capacity": self._capacity,
                "size": len(self._records),
                "evicted": self._evicted,
                "next_seq": self._next_seq,
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
