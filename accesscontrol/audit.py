"""判定依据的审计记录。

每次认证/授权/限流判定都写入一条可复现的依据：
- 输入：来源、主体、资源、请求动作等
- 判定依据：命中的策略条件（TTL、角色、归属、连续失败计数等）
- 结果：allow / deny 及可区分原因

存储为进程内有界环形缓冲（线程安全），同时通过 logging 输出，
单测可直接读取缓冲并断言“输入-依据-结果”。
"""

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class DecisionRecord:
    request_id: str
    stage: str  # authenticate / authorize / rate_limit / rotate ...
    source: str
    decision: Decision
    reason: str | None = None
    subject: str | None = None
    action: str | None = None
    resource_id: str | None = None
    # 判定时实际依据的输入快照
    evidence: dict[str, Any] = field(default_factory=dict)
    at: float = field(default_factory=time.time)


class AuditLog:
    def __init__(self, capacity: int = 1024, logger: logging.Logger | None = None) -> None:
        self._buffer: deque[DecisionRecord] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._logger = logger or logging.getLogger("accesscontrol.audit")

    def record(self, record: DecisionRecord) -> None:
        with self._lock:
            self._buffer.append(record)
        # 结构化日志：输入、判定依据、结果
        payload = asdict(record)
        payload["decision"] = record.decision.value
        self._logger.info("DECISION %s", payload)

    def all(self) -> list[DecisionRecord]:
        with self._lock:
            return list(self._buffer)

    def records_for(self, request_id: str) -> list[DecisionRecord]:
        with self._lock:
            return [r for r in self._buffer if r.request_id == request_id]

    def last(self) -> DecisionRecord | None:
        with self._lock:
            return self._buffer[-1] if self._buffer else None
