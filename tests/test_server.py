"""End-to-end integration tests for the Master MCP Server tool suite."""

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import ai_sre.server as server_module
from ai_sre.k8s import KubernetesAdapter
from ai_sre.server import app


def _extract_tool_json(result: Any) -> dict[str, Any]:
    """Extracts and parses JSON string from MCP CallToolResult or TextContent."""
    if hasattr(result, "content") and result.content:
        raw_text = result.content[0].text
    elif isinstance(result, list) and result:
        first = result[0]
        raw_text = first.text if hasattr(first, "text") else str(first)
    else:
        raw_text = str(result)
    return json.loads(raw_text)  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def mock_k8s_backend() -> None:
    """Mocks underlying K8s APIs so tests run in-memory without cluster connection."""
    mock_core = MagicMock()
    mock_apps = MagicMock()

    # Mock Node
    node = MagicMock()
    node.metadata.name = "prod-node-1"
    node.status.capacity = {"cpu": "16", "memory": "32Gi"}
    node.status.conditions = [MagicMock(type="Ready", status="True")]
    mock_core.list_node = AsyncMock(return_value=MagicMock(items=[node]))

    # Mock Pod
    pod = MagicMock()
    pod.metadata.name = "payments-service-589"
    pod.metadata.namespace = "payments"
    pod.spec.node_name = "prod-node-1"
    pod.status.phase = "Running"
    pod.status.conditions = [MagicMock(type="Ready", status="True")]
    pod.status.container_statuses = [MagicMock(restart_count=0)]
    mock_core.list_namespaced_pod = AsyncMock(return_value=MagicMock(items=[pod]))
    mock_core.list_pod_for_all_namespaces = AsyncMock(return_value=MagicMock(items=[pod]))

    # Mock dirty log with AWS secret and PAN
    dirty_log = (
        "2026-10-16 ERROR Transaction failed for card 4532015112830366 "
        "using aws_key AKIAIOSFODNN7EXAMPLE"
    )
    mock_core.read_namespaced_pod_log = AsyncMock(return_value=dirty_log)

    # Mock Deployment for scale & restart
    dep = MagicMock()
    dep.spec.replicas = 2
    dep.spec.template.metadata.annotations = {}
    mock_apps.read_namespaced_deployment = AsyncMock(return_value=dep)
    mock_apps.patch_namespaced_deployment_scale = AsyncMock(return_value=MagicMock())
    mock_apps.patch_namespaced_deployment = AsyncMock(return_value=MagicMock())

    adapter = KubernetesAdapter(
        core_api=mock_core,
        apps_api=mock_apps,
        sanitizer=server_module.sanitizer,
        approval_gate=server_module.approval_gate,
    )
    adapter._initialized = True
    server_module.k8s_adapter = adapter


@pytest.mark.asyncio
async def test_mcp_cluster_overview_tool() -> None:
    """Verify cluster_get_overview tool returns parsed telemetry."""
    res = await app.call_tool("cluster_get_overview", arguments={})
    data = _extract_tool_json(res)

    assert data["total_nodes"] == 1
    assert data["total_pods"] == 1
    assert data["healthy_pods_count"] == 1


@pytest.mark.asyncio
async def test_mcp_pod_logs_sanitization_tool() -> None:
    """Verify cluster_get_pod_logs scrubs secrets through MCP boundary."""
    res = await app.call_tool(
        "cluster_get_pod_logs",
        arguments={"namespace": "payments", "pod_name": "payments-service-589"},
    )
    data = _extract_tool_json(res)

    assert "[REDACTED_AWS_ACCESS_KEY]" in data["sanitized_logs"]
    assert "[PII:PAN:" in data["sanitized_logs"]
    assert "AKIAIOSFODNN7EXAMPLE" not in data["sanitized_logs"]
    assert "4532015112830366" not in data["sanitized_logs"]


@pytest.mark.asyncio
async def test_mcp_rag_lifecycle_tools() -> None:
    """Verify indexing and semantic search over runbooks via MCP tools."""
    index_res = await app.call_tool(
        "rag_index_document",
        arguments={
            "title": "CrashLoopBackOff Settlement",
            "content": "# Runbook\n## Resolution\nRestart redis cache and verify connection pool.",
            "category": "runbook",
            "tags": ["settlement", "k8s"],
        },
    )
    index_data = _extract_tool_json(index_res)
    assert index_data["status"] == "INDEXED"

    search_res = await app.call_tool(
        "rag_search_runbooks",
        arguments={"query": "CrashLoopBackOff settlement redis connection pool", "limit": 1},
    )
    search_data = _extract_tool_json(search_res)
    assert search_data["total_found"] >= 1
    assert "CrashLoopBackOff Settlement" in search_data["results"][0]["title"]


@pytest.mark.asyncio
async def test_mcp_two_phase_remediation_lifecycle() -> None:
    """Verify Phase 1 planning mints capability and Phase 2 executes it with anti-replay."""
    action = {
        "action_type": "scale_workload",
        "namespace": "payments",
        "deployment_name": "payments-api",
        "replicas": 5,
        "audit_justification": "Handling morning peak traffic volume",
    }

    # Phase 1: Plan remediation
    plan_res = await app.call_tool("cluster_plan_remediation", arguments={"action": action})
    plan_data = _extract_tool_json(plan_res)

    assert plan_data["status"] == "AWAITING_APPROVAL"
    token = plan_data["approval_token"]
    assert token is not None
    assert '-  "replicas": 2' in plan_data["dry_run_diff"]
    assert '+  "replicas": 5' in plan_data["dry_run_diff"]

    # Phase 2: Execute remediation
    exec_res = await app.call_tool(
        "cluster_execute_remediation",
        arguments={"approval_token": token, "action": action},
    )
    exec_data = _extract_tool_json(exec_res)
    assert exec_data["status"] == "EXECUTED"

    # Anti-Replay: Attempting to reuse the token must be rejected
    replay_res = await app.call_tool(
        "cluster_execute_remediation",
        arguments={"approval_token": token, "action": action},
    )
    replay_data = _extract_tool_json(replay_res)
    assert replay_data["status"] == "REJECTED_TOKEN_INVALID"


@pytest.mark.asyncio
async def test_mcp_audit_query_tool() -> None:
    """Verify audit_query_events surfaces all preceding tool actions in audit ledger."""
    res = await app.call_tool("audit_query_events", arguments={"limit": 5})
    data = _extract_tool_json(res)

    assert data["total"] >= 1
    recent_event = data["events"][0]
    assert recent_event["actor"] == "AI_SRE_AGENT"
    assert recent_event["status"] in ("SUCCESS", "REJECTED")
