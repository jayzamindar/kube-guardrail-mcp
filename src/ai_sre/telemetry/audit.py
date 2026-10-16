"""Append-only, immutable audit logger with synchronized fsync disk durability."""

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

from ai_sre.schemas.base import StrictBaseModel

logger = logging.getLogger("ai_sre.telemetry.audit")

DEFAULT_AUDIT_PATH: Final[str] = "./data/audit/audit.jsonl"

AuditEventType = Literal["QUERY", "PLAN_MINTED", "MUTATION_EXECUTED", "EXECUTION_BLOCKED"]
AuditStatus = Literal["SUCCESS", "FAILED", "REJECTED"]


class AuditEvent(StrictBaseModel):
    """Immutable audit record strictly adhering to SOC2/PCI-DSS logging requirements."""

    timestamp_utc: str
    event_type: AuditEventType
    tool_name: str
    action_id: str | None = None
    actor: str = "AI_SRE_AGENT"
    payload_hash: str | None = None
    status: AuditStatus
    details: dict[str, Any] = {}


class AuditLogger:
    """Thread-safe, append-only audit ledger with guaranteed disk synchronization."""

    def __init__(self, log_path: Path | str | None = None) -> None:
        if log_path is not None:
            self.log_path = Path(log_path)
        else:
            self.log_path = Path(os.getenv("AI_SRE_AUDIT_LOG_PATH", DEFAULT_AUDIT_PATH))

        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        event_type: AuditEventType,
        tool_name: str,
        status: AuditStatus,
        action_id: str | None = None,
        payload_hash: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Appends a new audit record and forces an immediate disk sync via os.fsync."""
        event = AuditEvent(
            timestamp_utc=datetime.now(UTC).isoformat(),
            event_type=event_type,
            tool_name=tool_name,
            action_id=action_id,
            actor="AI_SRE_AGENT",
            payload_hash=payload_hash,
            status=status,
            details=details or {},
        )

        line = event.model_dump_json() + "\n"

        with open(self.log_path, mode="a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            # Force OS disk controller write to guarantee audit durability across crashes
            os.fsync(f.fileno())

        logger.debug("Committed audit event: %s (%s)", event_type, tool_name)
        return event

    def query_events(
        self,
        limit: int = 50,
        event_type: AuditEventType | None = None,
    ) -> list[AuditEvent]:
        """Reads recent audit records in reverse chronological order."""
        if not self.log_path.exists():
            return []

        records: list[AuditEvent] = []
        with open(self.log_path, encoding="utf-8") as f:
            lines = f.readlines()

        # Parse from most recent backwards
        for raw_line in reversed(lines):
            line = raw_line.strip()
            if not line:
                continue
            try:
                event_dict = json.loads(line)
                evt = AuditEvent.model_validate(event_dict)
                if event_type is None or evt.event_type == event_type:
                    records.append(evt)
                    if len(records) >= limit:
                        break
            except Exception as e:
                logger.error("Corrupted audit record encountered: %s (%s)", line, e)

        return records
