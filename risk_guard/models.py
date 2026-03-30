from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional


Decision = Literal["allow", "confirm", "block"]
Severity = Literal["info", "warning", "critical"]


@dataclass
class ToolCall:
    tool_name: str
    params: Dict[str, Any]
    source: str = "unknown"
    namespace: Optional[str] = None
    user_prompt: str = ""
    session_id: Optional[str] = None
    actor_id: Optional[str] = None
    raw_event: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskSignal:
    code: str
    title: str
    detail: str
    severity: Severity
    score: float
    confirm_required: bool = False
    block: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationResult:
    decision: Decision
    severity: Severity
    summary: str
    user_message: str
    signals: List[RiskSignal]
    confirmation_id: Optional[str] = None
    confirmation_ttl_seconds: int = 0
    policy_version: str = "2026-03-29"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["signals"] = [signal.to_dict() for signal in self.signals]
        return payload
