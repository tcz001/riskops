from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "config" / "policy.json"
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "risk_guard.db"


@dataclass
class QwenBackendConfig:
    enabled: bool
    provider: str
    base_url: str
    api_key: str
    model: str
    timeout_seconds: int = 10


@dataclass
class AppConfig:
    host: str = "127.0.0.1"
    port: int = 8099
    policy_path: Path = DEFAULT_POLICY_PATH
    db_path: Path = DEFAULT_DB_PATH
    confirm_ttl_seconds: int = 600
    qwen: Optional[QwenBackendConfig] = None

    @classmethod
    def from_env(cls) -> "AppConfig":
        host = os.getenv("RISK_GUARD_HOST", "127.0.0.1")
        port = int(os.getenv("RISK_GUARD_PORT", "8099"))
        policy_path = Path(os.getenv("RISK_GUARD_POLICY_PATH", str(DEFAULT_POLICY_PATH)))
        db_path = Path(os.getenv("RISK_GUARD_DB_PATH", str(DEFAULT_DB_PATH)))
        confirm_ttl_seconds = int(os.getenv("RISK_GUARD_CONFIRM_TTL_SECONDS", "600"))

        provider = os.getenv("QWEN_PROVIDER", "").strip()
        base_url = os.getenv("QWEN_BASE_URL", "").strip()
        api_key = os.getenv("QWEN_API_KEY", "").strip()
        model = os.getenv("QWEN_MODEL", "").strip()
        qwen = None
        if provider and base_url and api_key and model:
            qwen = QwenBackendConfig(
                enabled=True,
                provider=provider,
                base_url=base_url.rstrip("/"),
                api_key=api_key,
                model=model,
                timeout_seconds=int(os.getenv("QWEN_TIMEOUT_SECONDS", "10")),
            )

        return cls(
            host=host,
            port=port,
            policy_path=policy_path,
            db_path=db_path,
            confirm_ttl_seconds=confirm_ttl_seconds,
            qwen=qwen,
        )

    def load_policy(self) -> dict:
        with self.policy_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

