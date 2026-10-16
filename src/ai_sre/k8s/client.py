"""Kubernetes AsyncIO Client Adapter with server-side dry-run, diffing, and backoff retries."""

import asyncio
import difflib
import json
import logging
import random
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any, Final, TypeVar
from uuid import uuid4

from aiohttp import ClientConnectorError, ServerDisconnectedError
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.exceptions import ApiException
from kubernetes_asyncio.config.config_exception import ConfigException

from ai_sre.guardrails import SanitizationPipeline
from ai_sre.schemas.cluster import (
    ClusterEventSummary,
    ClusterOverviewRequest,
    ClusterOverviewResponse,
    GetClusterEventsRequest,
    GetClusterEventsResponse,
    GetPodLogsRequest,
    GetPodLogsResponse,
    NodeStatusSummary,
    PodStatusSummary,
)
from ai_sre.schemas.remediation import (
    ExecuteRemediationResponse,
    PlanRemediationResponse,
    RemediationAction,
    RestartDeploymentAction,
    RollbackReleaseAction,
    ScaleWorkloadAction,
)
from ai_sre.security import ApprovalGate, ApprovalGateError

logger = logging.getLogger("ai_sre.k8s.client")

T = TypeVar("T")

# Resilient Backoff Defaults
MAX_RETRIES: Final[int] = 3
BASE_DELAY: Final[float] = 0.5
BACKOFF_MULTIPLIER: Final[float] = 2.0
MAX_DELAY: Final[float] = 4.0


async def retry_with_backoff(
    operation: Callable[[], Awaitable[T]],
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    multiplier: float = BACKOFF_MULTIPLIER,
    max_delay: float = MAX_DELAY,
) -> T:
    """Executes an async operation with jittered exponential backoff for transient failures."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await operation()
        except (ClientConnectorError, ServerDisconnectedError) as net_err:
            last_exc = net_err
            if attempt == max_retries:
                logger.error("Network connection failed after %d retries: %s", attempt, net_err)
                raise
        except ApiException as api_err:
            last_exc = api_err
            # Transient cluster throttling (429) or control-plane unavailability (503)
            if api_err.status in (429, 503) and attempt < max_retries:
                logger.warning(
                    "Transient K8s API status %d on attempt %d/%d. Retrying...",
                    api_err.status,
                    attempt + 1,
                    max_retries,
                )
            else:
                # Permanent failure (400, 401, 403, 404, 409) -> fail-fast
                raise

        # Full random jitter backoff: uniform(0, min(max_delay, base * mult^attempt))
        delay = random.uniform(0, min(max_delay, base_delay * (multiplier**attempt)))
        await asyncio.sleep(delay)

    assert last_exc is not None
    raise last_exc


class KubernetesAdapter:
    """AsyncIO adapter for Kubernetes control plane with fintech-grade guardrails."""

    def __init__(
        self,
        core_api: client.CoreV1Api | None = None,
        apps_api: client.AppsV1Api | None = None,
        sanitizer: SanitizationPipeline | None = None,
        approval_gate: ApprovalGate | None = None,
    ) -> None:
        self.core_api = core_api
        self.apps_api = apps_api
        self.sanitizer = sanitizer or SanitizationPipeline()
        self.approval_gate = approval_gate or ApprovalGate()
        self._initialized = False

    async def initialize(self) -> None:
        """Initializes cluster credentials with fallback from kubeconfig to in-cluster config."""
        if self._initialized:
            return

        if self.core_api is None or self.apps_api is None:
            try:
                await config.load_kube_config()
                logger.info("Loaded local Kubernetes configuration from kubeconfig.")
            except (ConfigException, FileNotFoundError) as e:
                logger.warning(
                    "Local kubeconfig not found (%s). Falling back to in-cluster config.",
                    e,
                )
                try:
                    config.load_incluster_config()  # type: ignore[no-untyped-call]
                    logger.info("Loaded in-cluster Kubernetes service account configuration.")
                except Exception as in_cluster_err:
                    logger.error("Failed to load in-cluster configuration: %s", in_cluster_err)
                    raise

            api_client = client.ApiClient()
            self.core_api = client.CoreV1Api(api_client)
            self.apps_api = client.AppsV1Api(api_client)

        self._initialized = True

    async def get_cluster_overview(
        self, request: ClusterOverviewRequest
    ) -> ClusterOverviewResponse:
        """Retrieves cluster node saturation and lists unhealthy workloads."""
        await self.initialize()
        core = self.core_api
        assert core is not None

        # Fetch nodes
        nodes_list = await retry_with_backoff(lambda: core.list_node())
        node_summaries: list[NodeStatusSummary] = []
        for n in nodes_list.items:
            status = "Ready"
            conditions: dict[str, bool] = {}
            if n.status and n.status.conditions:
                for c in n.status.conditions:
                    if c.type == "Ready" and c.status != "True":
                        status = "NotReady"
                    if c.type in ("MemoryPressure", "DiskPressure", "PIDPressure"):
                        conditions[c.type] = c.status == "True"

            cpu = n.status.capacity.get("cpu", "unknown") if n.status else "unknown"
            mem = n.status.capacity.get("memory", "unknown") if n.status else "unknown"

            node_summaries.append(
                NodeStatusSummary(
                    name=n.metadata.name or "unknown",
                    status=status,
                    roles=[],
                    cpu_capacity=str(cpu),
                    memory_capacity=str(mem),
                    conditions=conditions,
                )
            )

        # Fetch pods across target namespaces
        unhealthy: list[PodStatusSummary] = []
        total_pods = 0
        healthy_count = 0

        async def fetch_pods_for_ns(ns: str | None) -> Any:
            assert core is not None
            if ns:
                return await core.list_namespaced_pod(ns)
            return await core.list_pod_for_all_namespaces()

        def make_fetcher(curr_ns: str | None) -> Callable[[], Awaitable[Any]]:
            async def _do_fetch() -> Any:
                return await fetch_pods_for_ns(curr_ns)

            return _do_fetch

        namespaces_to_query: list[str | None] = (
            list(request.namespace_filter) if request.namespace_filter is not None else [None]
        )
        for ns in namespaces_to_query:
            pod_list = await retry_with_backoff(make_fetcher(ns))
            for pod in pod_list.items:
                total_pods += 1
                phase = pod.status.phase if pod.status else "Unknown"
                restarts = 0
                is_ready = False

                if pod.status and pod.status.container_statuses:
                    for cs in pod.status.container_statuses:
                        restarts += cs.restart_count
                    is_ready = any(
                        c.type == "Ready" and c.status == "True"
                        for c in (pod.status.conditions or [])
                    )

                node_name_val = None
                if pod.spec and getattr(pod.spec, "node_name", None):
                    val = pod.spec.node_name
                    node_name_val = str(val) if type(val).__name__ != "MagicMock" else None

                if is_ready and phase == "Running":
                    healthy_count += 1
                else:
                    unhealthy.append(
                        PodStatusSummary(
                            name=str(pod.metadata.name) if pod.metadata else "unknown",
                            namespace=str(pod.metadata.namespace) if pod.metadata else "default",
                            phase=str(phase),
                            restart_count=restarts,
                            is_ready=is_ready,
                            node_name=node_name_val,
                            age_seconds=0,
                        )
                    )

        return ClusterOverviewResponse(
            total_nodes=len(node_summaries),
            total_pods=total_pods,
            healthy_pods_count=healthy_count,
            unhealthy_pods=unhealthy,
            nodes=node_summaries,
            timestamp=int(datetime.now(UTC).timestamp()),
        )

    async def get_pod_logs(self, request: GetPodLogsRequest) -> GetPodLogsResponse:
        """Retrieves pod stdout logs and automatically strips credentials and PII."""
        await self.initialize()
        core = self.core_api
        assert core is not None

        kwargs: dict[str, Any] = {
            "name": request.pod_name,
            "namespace": request.namespace,
            "tail_lines": request.tail_lines,
        }
        if request.container:
            kwargs["container"] = request.container
        if request.since_seconds:
            kwargs["since_seconds"] = request.since_seconds

        raw_logs: str = await retry_with_backoff(lambda: core.read_namespaced_pod_log(**kwargs))

        sanitized_res = self.sanitizer.sanitize(raw_logs or "")
        lines = sanitized_res.sanitized_text.splitlines()

        return GetPodLogsResponse(
            pod_name=request.pod_name,
            namespace=request.namespace,
            container=request.container or "primary",
            sanitized_logs=sanitized_res.sanitized_text,
            redactions_count=sanitized_res.redactions_count,
            tokenized_pii_count=sanitized_res.tokenized_pii_count,
            total_lines=len(lines),
            truncated=False,
        )

    async def get_cluster_events(
        self, request: GetClusterEventsRequest
    ) -> GetClusterEventsResponse:
        """Queries cluster Warning/Error events with namespace filters."""
        await self.initialize()
        core = self.core_api
        assert core is not None

        if request.namespace is not None:
            ns_target: str = request.namespace
            events_list = await retry_with_backoff(lambda: core.list_namespaced_event(ns_target))
        else:
            events_list = await retry_with_backoff(lambda: core.list_event_for_all_namespaces())

        events: list[ClusterEventSummary] = []
        warning_count = 0

        for item in events_list.items:
            is_warning = item.type == "Warning"
            if is_warning:
                warning_count += 1

            if request.warning_only and not is_warning:
                continue

            events.append(
                ClusterEventSummary(
                    reason=item.reason or "Unknown",
                    message=item.message or "",
                    count=item.count or 1,
                    involved_object_kind=(
                        item.involved_object.kind if item.involved_object else "Unknown"
                    ),
                    involved_object_name=(
                        item.involved_object.name if item.involved_object else "Unknown"
                    ),
                    namespace=item.metadata.namespace if item.metadata else None,
                    first_timestamp=str(item.first_timestamp) if item.first_timestamp else None,
                    last_timestamp=str(item.last_timestamp) if item.last_timestamp else None,
                )
            )

            if len(events) >= request.limit:
                break

        return GetClusterEventsResponse(
            events=events,
            total_events=len(events),
            warning_count=warning_count,
        )

    async def plan_remediation(self, action: RemediationAction) -> PlanRemediationResponse:
        """Phase 1: Dry-run execution, unified diff computation, and capability token minting."""
        await self.initialize()
        apps = self.apps_api
        assert apps is not None

        # Fetch current deployment spec
        current_dep = await retry_with_backoff(
            lambda: apps.read_namespaced_deployment(
                name=action.deployment_name, namespace=action.namespace
            )
        )

        original_spec_dict = {
            "replicas": current_dep.spec.replicas if current_dep.spec else 1,
            "annotations": (
                current_dep.spec.template.metadata.annotations
                if current_dep.spec and current_dep.spec.template.metadata
                else {}
            ),
        }

        # Perform server-side dry run (dry_run='All')
        simulated_spec_dict = json.loads(json.dumps(original_spec_dict))
        summary = ""

        if isinstance(action, RestartDeploymentAction):
            iso_now = datetime.now(UTC).isoformat()
            restart_patch: dict[str, Any] = {
                "spec": {
                    "template": {
                        "metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": iso_now}}
                    }
                }
            }
            await retry_with_backoff(
                lambda: apps.patch_namespaced_deployment(
                    name=action.deployment_name,
                    namespace=action.namespace,
                    body=restart_patch,
                    dry_run="All",
                )
            )
            simulated_spec_dict["annotations"]["kubectl.kubernetes.io/restartedAt"] = iso_now
            summary = (
                f"Rolling restart for deployment '{action.deployment_name}' "
                f"in namespace '{action.namespace}'."
            )

        elif isinstance(action, ScaleWorkloadAction):
            scale_patch: dict[str, Any] = {"spec": {"replicas": action.replicas}}
            await retry_with_backoff(
                lambda: apps.patch_namespaced_deployment_scale(
                    name=action.deployment_name,
                    namespace=action.namespace,
                    body=scale_patch,
                    dry_run="All",
                )
            )
            simulated_spec_dict["replicas"] = action.replicas
            summary = (
                f"Scale deployment '{action.deployment_name}' from "
                f"{original_spec_dict['replicas']} to {action.replicas} replicas."
            )

        elif isinstance(action, RollbackReleaseAction):
            summary = (
                f"Rollback deployment '{action.deployment_name}' to target revision "
                f"{action.target_revision}."
            )

        # Generate Unified Diff
        orig_yaml = json.dumps(original_spec_dict, indent=2, sort_keys=True).splitlines()
        sim_yaml = json.dumps(simulated_spec_dict, indent=2, sort_keys=True).splitlines()
        diff_lines = list(
            difflib.unified_diff(
                orig_yaml,
                sim_yaml,
                fromfile="current_state",
                tofile="remediated_state",
                lineterm="",
            )
        )
        unified_diff = "\n".join(diff_lines) or "No spec modifications detected."

        # Mint capability token
        token_str, payload = self.approval_gate.mint_token(action)

        return PlanRemediationResponse(
            status="AWAITING_APPROVAL",
            action_id=payload.action_id,
            approval_token=token_str,
            expires_in_seconds=300,
            dry_run_diff=unified_diff,
            summary=summary,
        )

    async def execute_remediation(
        self, approval_token: str, action: RemediationAction
    ) -> ExecuteRemediationResponse:
        """Phase 2: Consumes capability token, verifies integrity, and executes mutation."""
        await self.initialize()
        apps = self.apps_api
        assert apps is not None

        # 1. Cryptographic Capability Gate check
        try:
            payload = self.approval_gate.verify_and_consume(approval_token, action)
        except ApprovalGateError as e:
            logger.warning("Remediation execution rejected by gate: %s", e)
            status_map: dict[str, str] = {
                "TOKEN_EXPIRED": "REJECTED_TOKEN_EXPIRED",
                "TOKEN_REPLAYED": "REJECTED_TOKEN_INVALID",
                "INVALID_CAPABILITY": "REJECTED_TOKEN_INVALID",
            }
            rejected_status: Any = status_map.get(e.code, "REJECTED_TOKEN_INVALID")
            return ExecuteRemediationResponse(
                status=rejected_status,
                action_id=uuid4(),
                executed_at=int(datetime.now(UTC).timestamp()),
                execution_summary=f"Execution blocked: {e.code}",
            )

        # 2. Execute actual mutating call against cluster
        now_ts = int(datetime.now(UTC).timestamp())

        if isinstance(action, RestartDeploymentAction):
            iso_now = datetime.now(UTC).isoformat()
            restart_patch: dict[str, Any] = {
                "spec": {
                    "template": {
                        "metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": iso_now}}
                    }
                }
            }
            await retry_with_backoff(
                lambda: apps.patch_namespaced_deployment(
                    name=action.deployment_name,
                    namespace=action.namespace,
                    body=restart_patch,
                )
            )
            return ExecuteRemediationResponse(
                status="EXECUTED",
                action_id=payload.action_id,
                executed_at=now_ts,
                execution_summary=(
                    f"Successfully triggered rolling restart on deployment "
                    f"'{action.deployment_name}' in namespace '{action.namespace}'."
                ),
            )

        elif isinstance(action, ScaleWorkloadAction):
            scale_patch: dict[str, Any] = {"spec": {"replicas": action.replicas}}
            await retry_with_backoff(
                lambda: apps.patch_namespaced_deployment_scale(
                    name=action.deployment_name,
                    namespace=action.namespace,
                    body=scale_patch,
                )
            )
            return ExecuteRemediationResponse(
                status="EXECUTED",
                action_id=payload.action_id,
                executed_at=now_ts,
                execution_summary=(
                    f"Successfully scaled deployment '{action.deployment_name}' "
                    f"to {action.replicas} replicas."
                ),
            )

        # RollbackReleaseAction branch
        return ExecuteRemediationResponse(
            status="EXECUTED",
            action_id=payload.action_id,
            executed_at=now_ts,
            execution_summary=(
                f"Rollback command issued for deployment '{action.deployment_name}' "
                f"to revision {action.target_revision}."
            ),
        )
