"""AI-SRE Cluster Manager: Master MCP Server with Two-Phase Execution Gate and Local RAG."""

import json
import logging
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer
from pydantic import TypeAdapter

from ai_sre.config import settings
from ai_sre.guardrails import SanitizationPipeline
from ai_sre.k8s import KubernetesAdapter
from ai_sre.rag import RunbookVectorStore
from ai_sre.schemas.cluster import (
    ClusterOverviewRequest,
    GetClusterEventsRequest,
    GetPodLogsRequest,
)
from ai_sre.schemas.rag import (
    IndexRunbookRequest,
    IndexRunbookResponse,
    SearchRunbooksRequest,
    SearchRunbooksResponse,
)
from ai_sre.schemas.remediation import (
    ExecuteRemediationRequest,
    PlanRemediationRequest,
    RemediationAction,
)
from ai_sre.security import ApprovalGate
from ai_sre.telemetry import (
    AuditEventType,
    AuditLogger,
    AuditStatus,
    setup_telemetry,
    trace_operation,
)

# Configure logging to stderr to prevent corrupting stdio JSON-RPC transport
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("ai_sre.server")

# 1. Initialize core system planes
setup_telemetry(service_name=settings.server_name)
audit_logger = AuditLogger(log_path=settings.audit_log_path)
sanitizer = SanitizationPipeline()
approval_gate = ApprovalGate(
    secret_key=settings.gate_secret.encode("utf-8") if settings.gate_secret else None,
    default_ttl=settings.approval_token_ttl,
)
vector_store = RunbookVectorStore(db_path=settings.db_path)
k8s_adapter = KubernetesAdapter(
    sanitizer=sanitizer,
    approval_gate=approval_gate,
)

# 2. Create MCPServer (MCP 2.x SDK)
app = MCPServer(
    name=settings.server_name,
    version=settings.server_version,
    instructions=(
        "Fintech-grade AI-SRE Cluster Manager MCP Server. "
        "Enforces Two-Phase Execution Gate for mutating actions, "
        "sanitizes logs for secrets/PII, and provides local RAG runbook search."
    ),
)


# Helper: Execute tool safely with OpenTelemetry span and immutable audit logging
async def _execute_traced_tool(
    tool_name: str,
    event_type: AuditEventType,
    operation: Any,
    action_id: str | None = None,
    payload_hash: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> str:
    span_attrs = {"tool.name": tool_name}
    if attributes:
        span_attrs.update(attributes)

    try:
        async with trace_operation(tool_name, attributes=span_attrs):
            result = await operation()
            res_json = (
                result.model_dump_json()
                if hasattr(result, "model_dump_json")
                else json.dumps(result, indent=2)
            )

            status: AuditStatus = "SUCCESS"
            if hasattr(result, "status") and "REJECTED" in str(result.status):
                status = "REJECTED"

            audit_logger.log_event(
                event_type=event_type,
                tool_name=tool_name,
                status=status,
                action_id=action_id,
                payload_hash=payload_hash,
                details={"status_output": getattr(result, "status", "OK")},
            )
            return res_json

    except Exception as exc:
        logger.error("Error executing tool '%s': %s", tool_name, exc, exc_info=True)
        sanitized_err, _ = sanitizer.redactor.redact(str(exc))
        audit_logger.log_event(
            event_type=event_type,
            tool_name=tool_name,
            status="FAILED",
            action_id=action_id,
            payload_hash=payload_hash,
            details={"error": sanitized_err},
        )
        return json.dumps(
            {
                "error": True,
                "tool": tool_name,
                "message": f"Tool execution failed: {sanitized_err}",
            }
        )


# ---------------------------------------------------------------------------
# Tool 1: cluster_get_overview (Query)
# ---------------------------------------------------------------------------
@app.tool()
async def cluster_get_overview(namespace_filter: list[str] | None = None) -> str:
    """Retrieves cluster node health, resource saturation, and lists failing/crashing pods."""
    req = ClusterOverviewRequest(namespace_filter=namespace_filter)
    return await _execute_traced_tool(
        tool_name="cluster_get_overview",
        event_type="QUERY",
        operation=lambda: k8s_adapter.get_cluster_overview(req),
        attributes={"filter.namespaces": namespace_filter},
    )


# ---------------------------------------------------------------------------
# Tool 2: cluster_get_pod_logs (Query)
# ---------------------------------------------------------------------------
@app.tool()
async def cluster_get_pod_logs(
    namespace: str,
    pod_name: str,
    container: str | None = None,
    tail_lines: int = 100,
    since_seconds: int | None = None,
) -> str:
    """Streams pod logs guaranteed free of credentials (AWS keys, JWTs) and masked for PII."""
    req = GetPodLogsRequest(
        namespace=namespace,
        pod_name=pod_name,
        container=container,
        tail_lines=tail_lines,
        since_seconds=since_seconds,
    )
    return await _execute_traced_tool(
        tool_name="cluster_get_pod_logs",
        event_type="QUERY",
        operation=lambda: k8s_adapter.get_pod_logs(req),
        attributes={"pod.name": pod_name, "pod.namespace": namespace},
    )


# ---------------------------------------------------------------------------
# Tool 3: cluster_get_events (Query)
# ---------------------------------------------------------------------------
@app.tool()
async def cluster_get_events(
    namespace: str | None = None,
    warning_only: bool = True,
    limit: int = 50,
) -> str:
    """Queries cluster Warning/Error events to isolate root causes for failing workloads."""
    req = GetClusterEventsRequest(
        namespace=namespace,
        warning_only=warning_only,
        limit=limit,
    )
    return await _execute_traced_tool(
        tool_name="cluster_get_events",
        event_type="QUERY",
        operation=lambda: k8s_adapter.get_cluster_events(req),
        attributes={"namespace": namespace, "warning_only": warning_only},
    )


# ---------------------------------------------------------------------------
# Tool 4: rag_search_runbooks (Query)
# ---------------------------------------------------------------------------
@app.tool()
async def rag_search_runbooks(
    query: str,
    limit: int = 3,
    category_filter: str | None = None,
    min_score: float = 0.30,
) -> str:
    """Semantically searches local SRE runbooks, post-mortems, and procedures via LanceDB."""
    req = SearchRunbooksRequest(
        query=query,
        limit=limit,
        category_filter=category_filter,
        min_score=min_score,
    )

    async def _search_op() -> SearchRunbooksResponse:
        results = vector_store.search(
            query=req.query,
            limit=req.limit,
            category_filter=req.category_filter,
            min_score=req.min_score,
        )
        return SearchRunbooksResponse(
            query=req.query,
            results=results,
            total_found=len(results),
        )

    return await _execute_traced_tool(
        tool_name="rag_search_runbooks",
        event_type="QUERY",
        operation=_search_op,
        attributes={"rag.query": query},
    )


# ---------------------------------------------------------------------------
# Tool 5: rag_index_document (Command)
# ---------------------------------------------------------------------------
@app.tool()
async def rag_index_document(
    title: str,
    content: str,
    category: str = "runbook",
    tags: list[str] | None = None,
    source_path: str = "custom.md",
) -> str:
    """Indexes a new runbook or post-mortem incident report into the local vector database."""
    req = IndexRunbookRequest(
        title=title,
        content=content,
        category=category,
        tags=tags or [],
        source_path=source_path,
    )

    async def _index_op() -> IndexRunbookResponse:
        chunks_count = vector_store.index_document(
            title=req.title,
            content=req.content,
            category=req.category,
            tags=req.tags,
            source_path=req.source_path,
        )
        return IndexRunbookResponse(
            status="INDEXED",
            document_id=req.title,
            chunks_indexed=chunks_count,
        )

    return await _execute_traced_tool(
        tool_name="rag_index_document",
        event_type="QUERY",
        operation=_index_op,
        attributes={"doc.title": title},
    )


# ---------------------------------------------------------------------------
# Tool 6: cluster_plan_remediation (Phase 1 2PC-Gate)
# ---------------------------------------------------------------------------
@app.tool()
async def cluster_plan_remediation(action: dict[str, Any]) -> str:
    """Phase 1: Proposes a cluster mutation (restart, scale, rollback).

    Executes a server-side dry-run, computes a unified diff, and returns a signed
    cryptographic HMAC capability token with a 300s TTL.
    """
    remediation_action: RemediationAction = TypeAdapter(RemediationAction).validate_python(action)
    req = PlanRemediationRequest(action=remediation_action)

    return await _execute_traced_tool(
        tool_name="cluster_plan_remediation",
        event_type="PLAN_MINTED",
        operation=lambda: k8s_adapter.plan_remediation(req.action),
        payload_hash=req.action.canonical_hash(),
        attributes={"action_type": req.action.action_type},
    )


# ---------------------------------------------------------------------------
# Tool 7: cluster_execute_remediation (Phase 2 2PC-Gate)
# ---------------------------------------------------------------------------
@app.tool()
async def cluster_execute_remediation(
    approval_token: str,
    action: dict[str, Any],
) -> str:
    """Phase 2: Executes a previously approved mutation.

    Validates HMAC signature, 300s TTL, single-use anti-replay nonce, and canonical
    payload hash before mutating the Kubernetes cluster.
    """
    remediation_action: RemediationAction = TypeAdapter(RemediationAction).validate_python(action)
    req = ExecuteRemediationRequest(approval_token=approval_token, action=remediation_action)

    return await _execute_traced_tool(
        tool_name="cluster_execute_remediation",
        event_type="MUTATION_EXECUTED",
        operation=lambda: k8s_adapter.execute_remediation(
            approval_token=req.approval_token,
            action=req.action,
        ),
        payload_hash=req.action.canonical_hash(),
        attributes={"action_type": req.action.action_type},
    )


# ---------------------------------------------------------------------------
# Tool 8: audit_query_events (Query)
# ---------------------------------------------------------------------------
@app.tool()
async def audit_query_events(
    limit: int = 20,
    event_type: str | None = None,
) -> str:
    """Queries the immutable append-only audit trail in reverse chronological order."""
    valid_event_type: AuditEventType | None = None
    if event_type in ("QUERY", "PLAN_MINTED", "MUTATION_EXECUTED", "EXECUTION_BLOCKED"):
        valid_event_type = event_type  # type: ignore[assignment]

    async def _query_op() -> dict[str, Any]:
        records = audit_logger.query_events(limit=limit, event_type=valid_event_type)
        return {
            "total": len(records),
            "events": [r.model_dump(mode="json") for r in records],
        }

    return await _execute_traced_tool(
        tool_name="audit_query_events",
        event_type="QUERY",
        operation=_query_op,
        attributes={"limit": limit},
    )


def main() -> None:
    """Entrypoint to run the AI-SRE MCP Server using stdio transport."""
    logger.info("Starting AI-SRE Cluster Manager MCP Server on stdio transport...")
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
