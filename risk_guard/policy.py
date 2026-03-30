from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List

from .models import EvaluationResult, RiskSignal, ToolCall
from .pai_client import QwenJudge
from .store import ApprovalStore


SECRET_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"api[_ -]?key",
        r"secret",
        r"token",
        r"password",
        r"access[_ -]?key",
        r"private[_ -]?key",
        r"credential",
        r"ssh[_ -]?key",
        r"私钥",
        r"密码",
        r"口令",
        r"秘钥",
        r"密钥",
        r"令牌",
    ]
]

INJECTION_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"ignore (all )?(previous|prior) instructions",
        r"reveal (the )?(system|developer) prompt",
        r"bypass (safety|security|guardrails?)",
        r"do not ask for approval",
        r"act as root",
        r"you are now in unrestricted mode",
        r"忽略(之前|以上|所有).*(指令|要求|规则)",
        r"不要(请求|发起).*(审批|确认)",
        r"绕过(安全|审批|确认|限制)",
        r"输出(系统提示词|开发者提示词)",
    ]
]

SENSITIVE_PATH_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"\.ssh/",
        r"id_rsa",
        r"id_ed25519",
        r"\.env",
        r"credentials",
        r"secret",
        r"kubeconfig",
    ]
]


class RiskPolicyEngine:
    def __init__(self, policy: Dict[str, Any], approvals: ApprovalStore, qwen_judge: QwenJudge, confirm_ttl_seconds: int) -> None:
        self.policy = policy
        self.approvals = approvals
        self.qwen_judge = qwen_judge
        self.confirm_ttl_seconds = confirm_ttl_seconds

    def evaluate(self, call: ToolCall) -> EvaluationResult:
        tool_signature = self._signature(call)
        if self.approvals.is_allow_always(tool_signature):
            return EvaluationResult(
                decision="allow",
                severity="info",
                summary="Previously approved sensitive action.",
                user_message="该操作已被你明确长期授权，本次直接放行。",
                signals=[],
            )

        signals = self._collect_rule_signals(call)
        llm_signals = self._collect_llm_signals(call)
        signals.extend(llm_signals)
        decision = self._merge_decision(signals)
        severity = self._max_severity(signals)
        summary = self._build_summary(signals, decision)
        user_message = self._build_user_message(signals, decision, call)

        confirmation_id = None
        ttl_seconds = 0
        if decision == "confirm":
            payload = {
                "tool_name": call.tool_name,
                "params": call.params,
                "source": call.source,
                "summary": summary,
                "signals": [signal.to_dict() for signal in signals],
            }
            confirmation_id = self.approvals.create_pending(tool_signature, payload, self.confirm_ttl_seconds)
            ttl_seconds = self.confirm_ttl_seconds

        return EvaluationResult(
            decision=decision,
            severity=severity,
            summary=summary,
            user_message=user_message,
            signals=signals,
            confirmation_id=confirmation_id,
            confirmation_ttl_seconds=ttl_seconds,
        )


    def _collect_rule_signals(self, call: ToolCall) -> List[RiskSignal]:
        signals: List[RiskSignal] = []
        tool_name = call.tool_name.lower()
        prompt = call.user_prompt
        params_blob = json.dumps(call.params, ensure_ascii=False)
        combined = f"{call.tool_name}\n{prompt}\n{params_blob}"

        for pattern in INJECTION_PATTERNS:
            if pattern.search(prompt):
                signals.append(
                    RiskSignal(
                        code="prompt_injection",
                        title="疑似 Prompt 注入",
                        detail="输入中出现了绕过系统提示词或审批流程的典型模式。",
                        severity="critical",
                        score=0.97,
                        block=True,
                        evidence={"pattern": pattern.pattern},
                    )
                )
                break

        for item in self.policy.get("tool_rules", []):
            names = [name.lower() for name in item.get("tool_names", [])]
            keywords = [word.lower() for word in item.get("param_keywords", [])]
            name_hit = any(name in tool_name for name in names) if names else False
            keyword_hit = any(self._keyword_match(word, combined) for word in keywords) if keywords else False
            if item.get("code") == "payment_risk":
                keyword_hit = self._payment_keyword_hit(call, keywords)
            source_hit = item.get("source") in (None, "", call.source)
            if source_hit and (name_hit or keyword_hit):
                signals.append(
                    RiskSignal(
                        code=item["code"],
                        title=item["title"],
                        detail=item["detail"],
                        severity=item["severity"],
                        score=float(item.get("score", 0.8)),
                        confirm_required=item.get("action") == "confirm",
                        block=item.get("action") == "block",
                        evidence={"tool_name": call.tool_name, "source": call.source},
                    )
                )

        if any(pattern.search(combined) for pattern in SECRET_PATTERNS):
            signals.append(
                RiskSignal(
                    code="secret_exposure",
                    title="疑似敏感信息披露",
                    detail="请求中包含秘钥、密码或令牌类字段，需要明确确认后才可继续。",
                    severity="critical",
                    score=0.95,
                    confirm_required=True,
                    evidence={"tool_name": call.tool_name},
                )
            )

        if any(pattern.search(combined) for pattern in SENSITIVE_PATH_PATTERNS):
            signals.append(
                RiskSignal(
                    code="sensitive_file_access",
                    title="敏感文件访问风险",
                    detail="请求指向可能包含秘钥、环境变量或凭据的敏感文件路径。",
                    severity="critical",
                    score=0.96,
                    confirm_required=True,
                    evidence={"tool_name": call.tool_name},
                )
            )

        destructive_verbs = tuple(self.policy.get("destructive_verbs", []))
        if destructive_verbs and any(verb in tool_name for verb in destructive_verbs):
            signals.append(
                RiskSignal(
                    code="destructive_operation",
                    title="高风险副作用操作",
                    detail="工具名表现出明显的增删改或执行副作用，需要用户二次确认。",
                    severity="warning",
                    score=0.88,
                    confirm_required=True,
                    evidence={"tool_name": call.tool_name},
                )
            )

        return self._dedupe(signals)

    def _collect_llm_signals(self, call: ToolCall) -> List[RiskSignal]:
        result = self.qwen_judge.evaluate(
            {
                "tool_name": call.tool_name,
                "source": call.source,
                "namespace": call.namespace,
                "params": call.params,
                "user_prompt": call.user_prompt,
            }
        )
        if not result:
            return []

        signals: List[RiskSignal] = []
        for item in result.get("signals", []):
            try:
                signals.append(
                    RiskSignal(
                        code=item["code"],
                        title=item["title"],
                        detail=item["detail"],
                        severity=item["severity"],
                        score=float(item.get("score", 0.5)),
                        confirm_required=bool(item.get("confirm_required", False)),
                        block=bool(item.get("block", False)),
                    )
                )
            except KeyError:
                continue
        return self._dedupe(signals)

    def _merge_decision(self, signals: List[RiskSignal]) -> str:
        if any(signal.block for signal in signals):
            return "block"
        if any(signal.confirm_required for signal in signals):
            return "confirm"
        return "allow"

    def _max_severity(self, signals: List[RiskSignal]) -> str:
        rank = {"info": 0, "warning": 1, "critical": 2}
        best = "info"
        for signal in signals:
            if rank[signal.severity] > rank[best]:
                best = signal.severity
        return best

    def _build_summary(self, signals: List[RiskSignal], decision: str) -> str:
        if not signals:
            return "No material risk signals detected."
        titles = "；".join(signal.title for signal in signals[:3])
        return f"{decision.upper()}: {titles}"

    def _build_user_message(self, signals: List[RiskSignal], decision: str, call: ToolCall) -> str:
        tool_name = call.tool_name or "unknown_tool"
        if decision == "allow":
            return f"工具 `{tool_name}` 未发现需要拦截或确权的高风险信号。"
        if decision == "block":
            return "检测到高置信度风险，本次操作已被阻断。若确属必要，请先调整指令，避免越权、注入或敏感信息暴露。"
        return self._build_confirm_message(signals, call)

    def _build_confirm_message(self, signals: List[RiskSignal], call: ToolCall) -> str:
        tool_name = call.tool_name or "unknown_tool"
        details = "；".join(signal.detail for signal in signals[:2])

        if tool_name == "web_search":
            query = call.params.get("query")
            if isinstance(query, str) and query:
                return (
                    "将调用 `web_search` 向外部搜索服务发送以下查询："
                    f"`{query}`。\n\n"
                    f"风险原因：{details}\n\n"
                    "请选择：`Allow once` 仅放行本次搜索，`Always allow` 放行同类请求，`Deny` 拒绝本次搜索。"
                )

        if tool_name == "exec":
            command = self._extract_exec_command(call.params)
            command_line = ""
            if command:
                preview = command[:160] + ("..." if len(command) > 160 else "")
                command_line = f"即将执行的命令：`{preview}`。\n\n"
            return (
                "将调用 `exec` 执行命令、脚本或程序。\n\n"
                f"{command_line}"
                f"风险原因：{details}\n\n"
                "请选择：`Allow once` 仅放行本次执行，`Always allow` 放行同类请求，`Deny` 拒绝本次执行。"
            )

        if tool_name == "sessions_send":
            message = call.params.get("message")
            snippet = ""
            if isinstance(message, str) and message:
                snippet = f"待发送内容摘要：`{message[:80]}{'...' if len(message) > 80 else ''}`。\n\n"
            return (
                f"将调用 `{tool_name}` 向外部会话发送内容。\n\n"
                f"{snippet}"
                f"风险原因：{details}\n\n"
                "请选择：`Allow once` 仅放行本次发送，`Always allow` 放行同类请求，`Deny` 拒绝本次发送。"
            )

        return (
            f"将调用 `{tool_name}` 执行潜在高风险操作。\n\n"
            f"风险原因：{details}\n\n"
            "请选择：`Allow once` 仅放行本次操作，`Always allow` 放行同类请求，`Deny` 拒绝本次操作。"
        )

    def _extract_exec_command(self, params: Dict[str, Any]) -> str:
        candidates = [
            params.get("cmd"),
            params.get("command"),
            params.get("script"),
        ]
        for value in candidates:
            if isinstance(value, str) and value.strip():
                return value.strip()

        argv = params.get("argv")
        if isinstance(argv, list):
            parts = [str(item) for item in argv if isinstance(item, (str, int, float))]
            if parts:
                return " ".join(parts)

        args = params.get("args")
        if isinstance(args, list):
            parts = [str(item) for item in args if isinstance(item, (str, int, float))]
            if parts:
                return " ".join(parts)

        return ""

    def _signature(self, call: ToolCall) -> str:
        stable = json.dumps(
            {
                "tool_name": call.tool_name,
                "source": call.source,
                "namespace": call.namespace,
                "params": call.params,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    def _keyword_match(self, keyword: str, text: str) -> bool:
        lowered = text.lower()
        token = keyword.lower().strip()
        if not token:
            return False

        # Multi-word phrases and shell fragments are matched as plain substrings.
        if re.search(r"[\s._/\-]", token):
            return token in lowered

        # Plain alphanumeric tokens use word-boundary matching to reduce false positives,
        # e.g. avoid matching "pay" inside unrelated words.
        pattern = re.compile(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", re.IGNORECASE)
        return bool(pattern.search(lowered))

    def _payment_keyword_hit(self, call: ToolCall, keywords: List[str]) -> bool:
        combined = f"{call.user_prompt}\n{json.dumps(call.params, ensure_ascii=False)}".lower()
        hits = [keyword for keyword in keywords if self._keyword_match(keyword, combined)]
        params = call.params if isinstance(call.params, dict) else {}

        amount_like = any(
            key in params
            for key in ["amount", "price", "total", "currency", "invoice", "order_id", "payment_id"]
        )
        payment_tool = any(
            token in call.tool_name.lower()
            for token in ["payment", "checkout", "purchase", "transfer", "invoice", "order"]
        )

        if payment_tool:
            return bool(hits) or amount_like

        # Avoid false positives like reminders that merely mention "pay".
        if amount_like and hits:
            return True

        strong_hits = {"payment", "checkout", "purchase", "transfer", "invoice"}
        return len([hit for hit in hits if hit in strong_hits]) >= 1 and amount_like

    def _dedupe(self, signals: List[RiskSignal]) -> List[RiskSignal]:
        seen = set()
        unique: List[RiskSignal] = []
        for signal in signals:
            if signal.code in seen:
                continue
            seen.add(signal.code)
            unique.append(signal)
        return unique
