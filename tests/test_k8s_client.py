"""Unit tests for KubernetesAsyncIO adapter: mock cluster, dry-run diffs, and backoff."""

from unittest.mock import AsyncMock, MagicMock, call

import pytest
from kubernetes_asyncio.client.exceptions import ApiException

from ai_sre.k8s import KubernetesAdapter, retry_with_backoff
from ai_sre.schemas.cluster import (
    ClusterOverviewRequest,
    GetPodLogsRequest,
)
from ai_sre.schemas.remediation import (
    RestartDeploymentAction,
    ScaleWorkloadAction,
)


@pytest.mark.asyncio
async def test_retry_with_backoff_on_transient_429() -> None:
    """Ensure retry_with_backoff retries on transient HTTP 429 and succeeds."""
    mock_op = AsyncMock()
    # First call raises 429, second call succeeds
    mock_op.side_effect = [
        ApiException(status=429, reason="Too Many Requests"),
        "success_payload",
    ]

    res = await retry_with_backoff(mock_op, max_retries=2, base_delay=0.01)
    assert res == "success_payload"
    assert mock_op.call_count == 2


@pytest.mark.asyncio
async def test_retry_with_backoff_fails_fast_on_404() -> None:
    """Ensure permanent 4xx errors (like 404 Not Found) are not retried."""
    mock_op = AsyncMock()
    mock_op.side_effect = ApiException(status=404, reason="Pod Not Found")

    with pytest.raises(ApiException) as exc_info:
        await retry_with_backoff(mock_op, max_retries=3, base_delay=0.01)

    assert exc_info.value.status == 404
    assert mock_op.call_count == 1  # No wasteful retries


@pytest.mark.asyncio
async def test_get_cluster_overview_detects_unhealthy_pods() -> None:
    """Verify cluster overview correctly identifies crashing pods and node resources."""
    mock_core = MagicMock()
    mock_apps = MagicMock()

    # Mock Node
    node = MagicMock()
    node.metadata.name = "node-worker-1"
    node.status.capacity = {"cpu": "8", "memory": "16Gi"}
    node.status.conditions = [MagicMock(type="Ready", status="True")]
    mock_core.list_node = AsyncMock(return_value=MagicMock(items=[node]))

    # Mock Pod 1 (Healthy)
    pod_healthy = MagicMock()
    pod_healthy.metadata.name = "payments-api-1"
    pod_healthy.metadata.namespace = "payments"
    pod_healthy.spec.node_name = "node-worker-1"
    pod_healthy.status.phase = "Running"
    pod_healthy.status.conditions = [MagicMock(type="Ready", status="True")]
    pod_healthy.status.container_statuses = [MagicMock(restart_count=0)]

    # Mock Pod 2 (CrashLoopBackOff)
    pod_crashing = MagicMock()
    pod_crashing.metadata.name = "fraud-detector-crash"
    pod_crashing.metadata.namespace = "payments"
    pod_crashing.spec.node_name = "node-worker-1"
    pod_crashing.status.phase = "CrashLoopBackOff"
    pod_crashing.status.conditions = [MagicMock(type="Ready", status="False")]
    pod_crashing.status.container_statuses = [MagicMock(restart_count=12)]

    mock_core.list_namespaced_pod = AsyncMock(
        return_value=MagicMock(items=[pod_healthy, pod_crashing])
    )

    adapter = KubernetesAdapter(core_api=mock_core, apps_api=mock_apps)
    adapter._initialized = True

    overview = await adapter.get_cluster_overview(
        ClusterOverviewRequest(namespace_filter=["payments"])
    )

    assert overview.total_nodes == 1
    assert overview.total_pods == 2
    assert overview.healthy_pods_count == 1
    assert len(overview.unhealthy_pods) == 1
    assert overview.unhealthy_pods[0].name == "fraud-detector-crash"
    assert overview.unhealthy_pods[0].restart_count == 12


@pytest.mark.asyncio
async def test_get_pod_logs_sanitizes_credentials_and_pii() -> None:
    """Verify raw pod stdout is scrubbed of credentials before returning from adapter."""
    mock_core = MagicMock()
    dirty_log = (
        "2026-10-16 ERROR auth failure using AKIAIOSFODNN7EXAMPLE "
        "for card 4532015112830366 on customer test.user@fintech.com"
    )
    mock_core.read_namespaced_pod_log = AsyncMock(return_value=dirty_log)

    adapter = KubernetesAdapter(core_api=mock_core, apps_api=MagicMock())
    adapter._initialized = True

    response = await adapter.get_pod_logs(
        GetPodLogsRequest(namespace="banking", pod_name="auth-service-pod")
    )

    assert response.pod_name == "auth-service-pod"
    assert "AKIAIOSFODNN7EXAMPLE" not in response.sanitized_logs
    assert "4532015112830366" not in response.sanitized_logs
    assert "[REDACTED_AWS_ACCESS_KEY]" in response.sanitized_logs
    assert "[PII:PAN:" in response.sanitized_logs
    assert "[PII:EMAIL:" in response.sanitized_logs


@pytest.mark.asyncio
async def test_two_phase_plan_and_execute_remediation() -> None:
    """Verify Phase 1 generates dry-run diff & approval token, and Phase 2 consumes it."""
    mock_core = MagicMock()
    mock_apps = MagicMock()

    # Mock current deployment
    current_dep = MagicMock()
    current_dep.spec.replicas = 2
    current_dep.spec.template.metadata.annotations = {}
    mock_apps.read_namespaced_deployment = AsyncMock(return_value=current_dep)
    mock_apps.patch_namespaced_deployment_scale = AsyncMock(return_value=MagicMock())
    mock_apps.patch_namespaced_deployment = AsyncMock(return_value=MagicMock())

    adapter = KubernetesAdapter(core_api=mock_core, apps_api=mock_apps)
    adapter._initialized = True

    action = ScaleWorkloadAction(
        namespace="settlement",
        deployment_name="ledger-worker",
        replicas=6,
        audit_justification="Scale up for end-of-day settlement batch",
    )

    # Phase 1: Plan remediation
    plan = await adapter.plan_remediation(action)
    assert plan.status == "AWAITING_APPROVAL"
    assert plan.approval_token is not None
    assert '-  "replicas": 2' in plan.dry_run_diff
    assert '+  "replicas": 6' in plan.dry_run_diff

    # Phase 2: Execute remediation
    exec_result = await adapter.execute_remediation(plan.approval_token, action)
    assert exec_result.status == "EXECUTED"
    expected_msg = "Successfully scaled deployment 'ledger-worker' to 6 replicas"
    assert expected_msg in exec_result.execution_summary

    # Ensure 2 calls were made: 1st with dry_run='All', 2nd without dry_run
    assert mock_apps.patch_namespaced_deployment_scale.call_count == 2
    mock_apps.patch_namespaced_deployment_scale.assert_has_calls(
        [
            call(
                name="ledger-worker",
                namespace="settlement",
                body={"spec": {"replicas": 6}},
                dry_run="All",
            ),
            call(
                name="ledger-worker",
                namespace="settlement",
                body={"spec": {"replicas": 6}},
            ),
        ]
    )


@pytest.mark.asyncio
async def test_restart_deployment_two_phase() -> None:
    """Verify rolling restart generates annotation patch and executes on approval."""
    mock_apps = MagicMock()
    current_dep = MagicMock()
    current_dep.spec.replicas = 3
    current_dep.spec.template.metadata.annotations = {}
    mock_apps.read_namespaced_deployment = AsyncMock(return_value=current_dep)
    mock_apps.patch_namespaced_deployment = AsyncMock(return_value=MagicMock())

    adapter = KubernetesAdapter(core_api=MagicMock(), apps_api=mock_apps)
    adapter._initialized = True

    action = RestartDeploymentAction(
        namespace="auth",
        deployment_name="oauth2-proxy",
        audit_justification="Cycling pods after certificate rotation",
    )

    plan = await adapter.plan_remediation(action)
    assert plan.status == "AWAITING_APPROVAL"
    assert "kubectl.kubernetes.io/restartedAt" in plan.dry_run_diff

    exec_res = await adapter.execute_remediation(plan.approval_token, action)
    assert exec_res.status == "EXECUTED"
    assert "Successfully triggered rolling restart" in exec_res.execution_summary
    assert mock_apps.patch_namespaced_deployment.call_count == 2
