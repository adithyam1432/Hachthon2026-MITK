"""
Enterprise Privacy-Preserving Audit Logger.
Records operational telemetry and compliance events without ever writing raw PII to disk.
"""

import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLogger:
    """Safe audit logger adhering to strict Zero-PII logging standards."""

    def __init__(self, log_filepath: Optional[str] = None):
        self.log_filepath = Path(log_filepath) if log_filepath else None
        self.memory_logs: List[Dict[str, Any]] = []

    def record_event(
        self,
        request_id: str,
        tool_name: str,
        action: str,
        counts_by_type: Dict[str, int],
        duration_ms: float,
        verification_passed: bool,
        blocked: bool = False,
        error_type: Optional[str] = None,
        sanitized_payload: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Creates a compliance audit entry.
        Computes cryptographic hash of sanitized payload for tamper evidence.
        """
        payload_sha256 = ""
        if sanitized_payload is not None:
            try:
                payload_str = json.dumps(sanitized_payload, default=str)
                payload_sha256 = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
            except Exception:
                payload_sha256 = "hash_failed"

        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "request_id": request_id,
            "tool_name": tool_name,
            "action": action,
            "categories_detected": counts_by_type,
            "total_entities_secured": sum(counts_by_type.values()),
            "overhead_ms": round(duration_ms, 3),
            "verification_passed": verification_passed,
            "blocked": blocked,
            "error_type": error_type,
            "sanitized_payload_sha256": payload_sha256,
        }

        self.memory_logs.append(entry)

        if self.log_filepath:
            try:
                self.log_filepath.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_filepath, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                pass

        return entry

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self.memory_logs[-limit:]

    def get_memory_logs(self) -> List[Dict[str, Any]]:
        """Returns all in-memory audit log entries."""
        return list(self.memory_logs)

    def clear(self) -> None:
        self.memory_logs.clear()
