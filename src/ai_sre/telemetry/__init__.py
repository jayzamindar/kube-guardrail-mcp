"""Observability package: OpenTelemetry distributed tracing and immutable audit logging."""

from ai_sre.telemetry.audit import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    AuditStatus,
)
from ai_sre.telemetry.tracer import (
    get_tracer,
    setup_telemetry,
    trace_operation,
)

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "AuditStatus",
    "get_tracer",
    "setup_telemetry",
    "trace_operation",
]
