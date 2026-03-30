from __future__ import annotations

import json
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from typing import Any, Dict

from .config import AppConfig
from .models import ToolCall
from .pai_client import QwenJudge
from .policy import RiskPolicyEngine
from .store import ApprovalStore

DEBUG_EVALUATE_LOG = Path("/tmp/risk-guard-evaluate.jsonl")


def _append_evaluate_log(payload: Dict[str, Any], client_address: Any) -> None:
    record = {
        "client": client_address[0] if isinstance(client_address, tuple) and client_address else "",
        "payload": payload,
    }
    try:
        with DEBUG_EVALUATE_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        return


def _is_empty_payload(payload: Dict[str, Any]) -> bool:
    tool_name = payload.get("tool_name")
    user_prompt = payload.get("user_prompt")
    params = payload.get("params")
    raw_event = payload.get("raw_event")
    return (
        not tool_name
        and not user_prompt
        and (not isinstance(params, dict) or not params)
        and (not isinstance(raw_event, dict) or not raw_event)
    )


def _apple_script_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _notify_pending_confirmation(tool_name: str, message: str) -> None:
    title = _apple_script_string("Risk Guard")
    subtitle = _apple_script_string(f"{tool_name or 'unknown_tool'} requires confirmation")
    body = _apple_script_string(message[:180] + ("..." if len(message) > 180 else ""))
    script = f'display notification "{body}" with title "{title}" subtitle "{subtitle}"'
    try:
        subprocess.run(
            ["osascript", "-e", script],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return


def build_app(config: AppConfig) -> ThreadingHTTPServer:
    approvals = ApprovalStore(config.db_path)
    qwen_judge = QwenJudge(config.qwen)
    ui_root = Path(__file__).resolve().parent.parent / "ui"

    def make_engine() -> RiskPolicyEngine:
        return RiskPolicyEngine(
            policy=config.load_policy(),
            approvals=approvals,
            qwen_judge=qwen_judge,
            confirm_ttl_seconds=config.confirm_ttl_seconds,
        )

    class Handler(BaseHTTPRequestHandler):
        server_version = "RiskGuard/0.1"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_file(ui_root / "index.html", "text/html; charset=utf-8")
                return
            if parsed.path == "/health":
                self._send_json({"ok": True})
                return
            if parsed.path == "/v1/policy":
                self._send_json(config.load_policy())
                return
            if parsed.path == "/v1/audit":
                query = parse_qs(parsed.query)
                limit = int(query.get("limit", ["100"])[0])
                decision = query.get("decision", [None])[0]
                self._send_json({"items": approvals.list_evaluations(limit=limit, decision=decision)})
                return
            if parsed.path == "/v1/approvals":
                query = parse_qs(parsed.query)
                limit = int(query.get("limit", ["100"])[0])
                status = query.get("status", [None])[0]
                self._send_json({"items": approvals.list_approvals(limit=limit, status=status)})
                return
            if parsed.path == "/static/index.css":
                self._send_file(ui_root / "index.css", "text/css; charset=utf-8")
                return
            if parsed.path == "/static/index.js":
                self._send_file(ui_root / "index.js", "application/javascript; charset=utf-8")
                return
            self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            if self.path == "/v1/evaluate":
                payload = self._read_json()
                _append_evaluate_log(payload, self.client_address)
                call = ToolCall(
                    tool_name=payload.get("tool_name", ""),
                    params=payload.get("params", {}),
                    source=payload.get("source", "unknown"),
                    namespace=payload.get("namespace"),
                    user_prompt=payload.get("user_prompt", ""),
                    session_id=payload.get("session_id"),
                    actor_id=payload.get("actor_id"),
                    raw_event=payload.get("raw_event", {}),
                )
                result = make_engine().evaluate(call)
                result_payload = result.to_dict()
                if not _is_empty_payload(payload):
                    approvals.record_evaluation(
                        {
                            "tool_name": call.tool_name,
                            "source": call.source,
                            "namespace": call.namespace,
                            "user_prompt": call.user_prompt,
                            "params": call.params,
                            "raw_event": call.raw_event,
                            **result_payload,
                            "approval_status": "pending" if result.confirmation_id else None,
                        }
                    )
                if result.confirmation_id:
                    _notify_pending_confirmation(call.tool_name, result.user_message)
                self._send_json(result_payload)
                return

            if self.path == "/v1/confirm":
                payload = self._read_json()
                record = approvals.resolve(
                    approval_id=payload["confirmation_id"],
                    decision=payload["decision"],
                )
                if not record:
                    self._send_json({"error": "approval_not_found"}, status=HTTPStatus.NOT_FOUND)
                    return
                self._send_json({"ok": True, "record": record})
                return
            if self.path == "/v1/policy":
                payload = self._read_json()
                self._save_policy(payload)
                self._send_json({"ok": True, "policy": config.load_policy()})
                return

            self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_json(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8"))

        def _send_json(self, payload: Dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
            data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _send_file(self, path: Path, content_type: str) -> None:
            if not path.exists():
                self._send_json({"error": "not_found"}, status=HTTPStatus.NOT_FOUND)
                return
            data = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _save_policy(self, payload: Dict[str, Any]) -> None:
            config.policy_path.parent.mkdir(parents=True, exist_ok=True)
            config.policy_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

    return ThreadingHTTPServer((config.host, config.port), Handler)


def main() -> None:
    config = AppConfig.from_env()
    server = build_app(config)
    print(f"risk-guard listening on http://{config.host}:{config.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
