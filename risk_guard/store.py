from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


class ApprovalStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    tool_signature TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS allow_always (
                    tool_signature TEXT PRIMARY KEY,
                    approved_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evaluations (
                    id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    tool_name TEXT NOT NULL,
                    source TEXT NOT NULL,
                    namespace TEXT,
                    user_prompt TEXT NOT NULL,
                    params_json TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    user_message TEXT NOT NULL,
                    signals_json TEXT NOT NULL,
                    raw_event_json TEXT NOT NULL DEFAULT '{}',
                    confirmation_id TEXT,
                    approval_status TEXT
                )
                """
            )
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(evaluations)").fetchall()
            }
            if "raw_event_json" not in columns:
                conn.execute(
                    "ALTER TABLE evaluations ADD COLUMN raw_event_json TEXT NOT NULL DEFAULT '{}'"
                )
            conn.commit()

    def create_pending(self, tool_signature: str, payload: Dict[str, Any], ttl_seconds: int) -> str:
        approval_id = str(uuid.uuid4())
        now = int(time.time())
        expires_at = now + ttl_seconds
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (id, created_at, expires_at, status, tool_signature, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (approval_id, now, expires_at, "pending", tool_signature, json.dumps(payload, ensure_ascii=False)),
            )
            conn.commit()
        return approval_id

    def resolve(self, approval_id: str, decision: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tool_signature, payload_json, expires_at, status FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
            if not row:
                return None
            tool_signature, payload_json, expires_at, status = row
            if status != "pending":
                return {
                    "tool_signature": tool_signature,
                    "payload": json.loads(payload_json),
                    "expires_at": expires_at,
                    "status": status,
                }
            now = int(time.time())
            final_status = "timeout" if now > expires_at else decision
            conn.execute("UPDATE approvals SET status = ? WHERE id = ?", (final_status, approval_id))
            conn.execute(
                "UPDATE evaluations SET approval_status = ? WHERE confirmation_id = ?",
                (final_status, approval_id),
            )
            if final_status == "allow-always":
                conn.execute(
                    """
                    INSERT INTO allow_always (tool_signature, approved_at, payload_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(tool_signature) DO UPDATE SET
                        approved_at = excluded.approved_at,
                        payload_json = excluded.payload_json
                    """,
                    (tool_signature, now, payload_json),
                )
            conn.commit()
            return {
                "tool_signature": tool_signature,
                "payload": json.loads(payload_json),
                "expires_at": expires_at,
                "status": final_status,
            }

    def is_allow_always(self, tool_signature: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tool_signature FROM allow_always WHERE tool_signature = ?",
                (tool_signature,),
            ).fetchone()
            return row is not None

    def record_evaluation(self, payload: Dict[str, Any]) -> str:
        evaluation_id = str(uuid.uuid4())
        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO evaluations (
                    id,
                    created_at,
                    tool_name,
                    source,
                    namespace,
                    user_prompt,
                    params_json,
                    decision,
                    severity,
                    summary,
                    user_message,
                    signals_json,
                    raw_event_json,
                    confirmation_id,
                    approval_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evaluation_id,
                    now,
                    payload["tool_name"],
                    payload["source"],
                    payload.get("namespace"),
                    payload.get("user_prompt", ""),
                    json.dumps(payload.get("params", {}), ensure_ascii=False),
                    payload["decision"],
                    payload["severity"],
                    payload["summary"],
                    payload["user_message"],
                    json.dumps(payload.get("signals", []), ensure_ascii=False),
                    json.dumps(payload.get("raw_event", {}), ensure_ascii=False),
                    payload.get("confirmation_id"),
                    payload.get("approval_status"),
                ),
            )
            conn.commit()
        return evaluation_id

    def _display_prompt(self, tool_name: str, user_prompt: str, params: Dict[str, Any]) -> str:
        if user_prompt:
            return user_prompt
        if tool_name == "web_search":
            query = params.get("query")
            if isinstance(query, str) and query:
                return query
        return ""

    def list_evaluations(self, limit: int = 100, decision: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = """
            SELECT
                id,
                created_at,
                tool_name,
                source,
                namespace,
                user_prompt,
                params_json,
                decision,
                severity,
                summary,
                user_message,
                signals_json,
                raw_event_json,
                confirmation_id,
                approval_status
            FROM evaluations
        """
        params: List[Any] = []
        if decision:
            sql += " WHERE decision = ?"
            params.append(decision)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        items: List[Dict[str, Any]] = []
        for row in rows:
            params = json.loads(row[6])
            user_prompt = self._display_prompt(row[2], row[5], params)
            items.append(
                {
                    "id": row[0],
                    "created_at": row[1],
                    "tool_name": row[2],
                    "source": row[3],
                    "namespace": row[4],
                    "user_prompt": user_prompt,
                    "params": params,
                    "decision": row[7],
                    "severity": row[8],
                    "summary": row[9],
                    "user_message": row[10],
                    "signals": json.loads(row[11]),
                    "raw_event": json.loads(row[12]),
                    "confirmation_id": row[13],
                    "approval_status": row[14],
                }
            )
        return items

    def list_approvals(self, limit: int = 100, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = """
            SELECT id, created_at, expires_at, status, tool_signature, payload_json
            FROM approvals
        """
        params: List[Any] = []
        if status:
            sql += " WHERE status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [
            {
                "id": row[0],
                "created_at": row[1],
                "expires_at": row[2],
                "status": row[3],
                "tool_signature": row[4],
                "payload": json.loads(row[5]),
            }
            for row in rows
        ]
