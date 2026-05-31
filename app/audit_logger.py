"""
Audit Logger — writes every gateway interaction to a structured JSONL file.

Each line is a self-contained JSON object (newline-delimited JSON / JSONL).
This format is directly ingestible by tools like Splunk, Datadog, Elasticsearch,
or any SIEM without preprocessing.

Fields logged per event:
  - timestamp_iso, request_id, api_key_hint, client_ip
  - prompt (truncated to 500 chars for storage efficiency)
  - response (truncated to 500 chars)
  - decision: "allowed" | "blocked" | "rate_limited"
  - block_reason (if decision != "allowed")
  - model, tokens_used, latency_ms
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class AuditLogger:
    def __init__(self, log_path: str = "logs/audit.jsonl"):
        self.log_path = Path(log_path)
        self._lock = threading.Lock()
        self._file = None

    def setup(self):
        """Create log directory and open file handle. Called at app startup."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.log_path, "a", encoding="utf-8", buffering=1)
        logger.info(f"Audit log opened: {self.log_path}")

    def close(self):
        """Flush and close file handle. Called at app shutdown."""
        if self._file:
            self._file.flush()
            self._file.close()
            self._file = None

    def log(
        self,
        request_id: str,
        api_key_hint: str,
        client_ip: str,
        prompt: str,
        decision: str,
        response: str | None = None,
        model: str | None = None,
        tokens_used: int | None = None,
        latency_ms: int | None = None,
        block_reason: str | None = None,
    ):
        """Write a single audit event. Thread-safe."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "api_key_hint": api_key_hint,
            "client_ip": client_ip,
            "decision": decision,
            "prompt_preview": prompt[:500] if prompt else None,
            "response_preview": response[:500] if response else None,
            "block_reason": block_reason,
            "model": model,
            "tokens_used": tokens_used,
            "latency_ms": latency_ms,
        }
        # Remove None values to keep logs compact
        event = {k: v for k, v in event.items() if v is not None}

        line = json.dumps(event, ensure_ascii=False)

        with self._lock:
            if self._file:
                self._file.write(line + "\n")
            else:
                # Fallback to stderr if file not open (e.g., during testing)
                logger.info(f"AUDIT: {line}")
