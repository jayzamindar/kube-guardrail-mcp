"""Unit tests for Telemetry Plane: OpenTelemetry distributed tracing and immutable audit ledger."""

from pathlib import Path

import pytest
from opentelemetry.trace import StatusCode

from ai_sre.telemetry import (
    AuditLogger,
    setup_telemetry,
    trace_operation,
)


def test_audit_logger_append_and_query(tmp_path: Path) -> None:
    """Verify AuditLogger writes immutable records and supports reverse chronological querying."""
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_path=log_file)

    # 1. Log query event
    evt1 = logger.log_event(
        event_type="QUERY",
        tool_name="cluster_get_overview",
        status="SUCCESS",
        details={"namespaces_queried": ["payments"]},
    )
    assert evt1.actor == "AI_SRE_AGENT"
    assert evt1.status == "SUCCESS"

    # 2. Log capability minted event
    evt2 = logger.log_event(
        event_type="PLAN_MINTED",
        tool_name="cluster_plan_remediation",
        status="SUCCESS",
        action_id="11111111-2222-3333-4444-555555555555",
        payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        details={"action_type": "scale_workload", "replicas": 5},
    )
    assert evt2.action_id == "11111111-2222-3333-4444-555555555555"

    # 3. Log mutation executed event
    logger.log_event(
        event_type="MUTATION_EXECUTED",
        tool_name="cluster_execute_remediation",
        status="SUCCESS",
        action_id="11111111-2222-3333-4444-555555555555",
        details={"k8s_status": "Scaled to 5"},
    )

    # Query all events (most recent first)
    records = logger.query_events(limit=10)
    assert len(records) == 3
    assert records[0].event_type == "MUTATION_EXECUTED"
    assert records[1].event_type == "PLAN_MINTED"
    assert records[2].event_type == "QUERY"

    # Query filtered by event_type
    plan_records = logger.query_events(event_type="PLAN_MINTED")
    assert len(plan_records) == 1
    assert plan_records[0].action_id == "11111111-2222-3333-4444-555555555555"


@pytest.mark.asyncio
async def test_opentelemetry_trace_operation_success() -> None:
    """Verify trace_operation generates span with correct attributes and OK status."""
    _, exporter = setup_telemetry(service_name="test-sre", use_in_memory=True)
    assert exporter is not None
    exporter.clear()

    async with trace_operation(
        "test_get_logs",
        attributes={"pod_name": "payments-pod", "tail_lines": 50},
    ):
        pass  # Successful operation

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "test_get_logs"
    assert span.status.status_code == StatusCode.OK
    assert span.attributes is not None
    assert span.attributes.get("pod_name") == "payments-pod"
    assert span.attributes.get("tail_lines") == 50


@pytest.mark.asyncio
async def test_opentelemetry_trace_operation_error_capture() -> None:
    """Verify trace_operation captures exceptions and marks span status as ERROR."""
    _, exporter = setup_telemetry(service_name="test-sre", use_in_memory=True)
    assert exporter is not None
    exporter.clear()

    with pytest.raises(ValueError) as exc_info:
        async with trace_operation("failing_k8s_call"):
            raise ValueError("Kubernetes connection timeout")

    assert "Kubernetes connection timeout" in str(exc_info.value)

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "failing_k8s_call"
    assert span.status.status_code == StatusCode.ERROR
    assert "Kubernetes connection timeout" in (span.status.description or "")
