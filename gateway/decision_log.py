"""运行期决策日志：每次访问判定恰好一条结构化日志，线程安全。

日志只携带标识与判定依据（日志 ID、主体标识、角色、资源标识、用途、
判定结论、结局分类、策略版本、逐条原因），绝不包含任何原始敏感字段值。

两个互不等价的结论字段：

- ``decision``：本次**判定本身**的放行/拒绝结论（``allow`` / ``deny``），
  与输出端是否故障无关，所有结局都可机读；
- ``outcome``：请求的**最终结局分类**（``allow`` / ``deny`` /
  ``audit_error`` / ``masking_error``）。

输出端故障语义：``DecisionLogger.emit`` 在任何情况下都不向调用方抛出异常，
日志故障绝不改变网关的对外结论与错误归类。主输出端失败时自动转投兜底端；
两端皆失败时条目进入进程内死信队列，可随后用 ``retry_dead_letters`` 补发。
每条条目按 ``log_id`` 去重，至多投递一次，并发下不丢不重。
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

# 判定结论：本次判定本身的放行/拒绝（独立于结局分类与输出端故障）
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"

# 结局分类：放行 / 拒绝 / 审计写入失败 / 脱敏失败
OUTCOME_ALLOW = "allow"
OUTCOME_DENY = "deny"
OUTCOME_AUDIT_ERROR = "audit_error"
OUTCOME_MASKING_ERROR = "masking_error"

LOGGER_NAME = "gateway.decision"


def new_log_id() -> str:
    """生成一条决策日志的全局唯一标识，用于失败兜底与去重。"""
    return f"dl-{uuid.uuid4().hex}"


@dataclass(frozen=True)
class DecisionLogEntry:
    """一条结构化决策日志（不含任何原始敏感值）。"""

    timestamp: datetime
    subject_id: str
    role: str
    resource_id: str
    purpose: str
    decision: str  # 判定本身的结论：allow / deny（所有结局均携带）
    outcome: str  # 最终结局：allow / deny / audit_error / masking_error
    policy_version: int
    reasons: tuple[str, ...] = ()
    view: str | None = None
    reference: str | None = None
    log_id: str = field(default_factory=new_log_id)

    def to_dict(self) -> dict:
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp.isoformat(),
            "subject_id": self.subject_id,
            "role": self.role,
            "resource_id": self.resource_id,
            "purpose": self.purpose,
            "decision": self.decision,
            "outcome": self.outcome,
            "policy_version": self.policy_version,
            "reasons": list(self.reasons),
            "view": self.view,
            "reference": self.reference,
        }


class DecisionLogSink(Protocol):
    """决策日志输出端接口。实现方不得在异常消息中放入请求敏感数据。"""

    def write(self, entry: DecisionLogEntry) -> None: ...


class LoggingLogSink:
    """默认输出端：标准 logging（其 Handler 调用自身线程安全）。

    结构化字段同时放在 JSON 消息与 LogRecord 的 extra 属性上，
    便于本地用日志捕获（如 pytest caplog）按关键字段断言。
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger(LOGGER_NAME)

    def write(self, entry: DecisionLogEntry) -> None:
        payload = entry.to_dict()
        # extra 字段加 dl_ 前缀，避免与 LogRecord 内建属性冲突
        extras = {f"dl_{k}": v for k, v in payload.items()}
        self._logger.info(
            "access_decision %s",
            json.dumps(payload, ensure_ascii=False),
            extra=extras,
        )


class StderrFallbackSink:
    """主输出端故障时的兜底输出端：直接写 stderr（不依赖 logging 配置）。"""

    def __init__(self, stream=None) -> None:
        # 惰性解析 sys.stderr，便于测试注入且兼容解释器收尾阶段
        self._stream = stream

    def write(self, entry: DecisionLogEntry) -> None:
        stream = self._stream if self._stream is not None else sys.stderr
        stream.write(
            "access_decision_fallback "
            + json.dumps(entry.to_dict(), ensure_ascii=False)
            + "\n"
        )
        stream.flush()


def _try_write(sink: DecisionLogSink, entry: DecisionLogEntry) -> str | None:
    """尝试写入一个输出端。

    成功返回 None；失败只保留异常**类型名**用于计数，绝不记录异常文本
    （第三方输出端可能把请求数据拼进异常消息），避免敏感值二次泄漏。
    """
    try:
        sink.write(entry)
    except Exception as exc:  # noqa: BLE001 - 日志失败归一化，绝不外抛
        return type(exc).__name__
    return None


class DecisionLogger:
    """决策日志发射器：输出端故障隔离，并发下每条判定恰好投递一条。

    - 主输出端失败 -> 转投兜底输出端（默认写 stderr）；
    - 两端皆失败 -> 条目进入死信队列，``retry_dead_letters`` 可补发；
    - 按 ``log_id`` 去重：同一 ``emit`` 重放/补发绝不产生第二条；
    - ``emit`` 永不抛出异常：日志故障不改变放行/拒绝结论与错误归类。
    """

    def __init__(
        self,
        sink: DecisionLogSink | None = None,
        *,
        fallback: DecisionLogSink | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if sink is None:
            sink = LoggingLogSink(logger)
        self._sink = sink
        self._fallback = fallback if fallback is not None else StderrFallbackSink()
        self._lock = threading.Lock()
        self._delivered: set[str] = set()
        self._dead: list[DecisionLogEntry] = []
        # 仅计数异常类型名，不保留异常文本
        self._primary_failures = 0
        self._fallback_delivered = 0
        self._dead_lettered = 0

    def emit(self, entry: DecisionLogEntry) -> None:
        """发射一条决策日志；保证不向调用方抛出任何异常。"""
        try:
            with self._lock:
                if entry.log_id in self._delivered:
                    return  # 幂等：同一判定不重复记录
                if _try_write(self._sink, entry) is None:
                    self._delivered.add(entry.log_id)
                    return
                self._primary_failures += 1
                if _try_write(self._fallback, entry) is None:
                    self._delivered.add(entry.log_id)
                    self._fallback_delivered += 1
                    return
                self._dead.append(entry)
                self._dead_lettered += 1
        except Exception:  # noqa: BLE001 - 最后防线：静默吞掉，日志故障不影响请求
            return

    def retry_dead_letters(self) -> int:
        """补发死信队列中的条目，返回本次成功投递数。已投递的绝不重复。"""
        delivered_now = 0
        with self._lock:
            remaining: list[DecisionLogEntry] = []
            for entry in self._dead:
                if entry.log_id in self._delivered:
                    continue
                if _try_write(self._sink, entry) is None:
                    self._delivered.add(entry.log_id)
                    delivered_now += 1
                    continue
                if _try_write(self._fallback, entry) is None:
                    self._delivered.add(entry.log_id)
                    delivered_now += 1
                    continue
                remaining.append(entry)
            self._dead = remaining
        return delivered_now

    def dead_letters(self) -> tuple[DecisionLogEntry, ...]:
        """返回两端均失败、尚未补发的条目（不含任何原始敏感值）。"""
        with self._lock:
            return tuple(self._dead)

    def stats(self) -> dict[str, int]:
        """输出端投递计数，便于本地验证不丢不重（不含任何请求内容）。"""
        with self._lock:
            return {
                "delivered": len(self._delivered),
                "primary_failures": self._primary_failures,
                "fallback_delivered": self._fallback_delivered,
                "dead_lettered": self._dead_lettered,
                "dead_pending": len(self._dead),
            }
