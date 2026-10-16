"""Cluster query schemas: overview, pod logs, and warning events."""

from typing import Annotated

from pydantic import Field

from ai_sre.schemas.base import NamespaceStr, StrictBaseModel


class PodStatusSummary(StrictBaseModel):
    """Essential telemetry summary for a single Pod."""

    name: str = Field(description="Pod name.")
    namespace: NamespaceStr = Field(description="Pod namespace.")
    phase: str = Field(
        description="Current phase (Running, Pending, Failed, CrashLoopBackOff, etc.)."
    )
    restart_count: int = Field(ge=0, description="Cumulative restart count across all containers.")
    is_ready: bool = Field(description="True if all containers pass readiness probes.")
    node_name: str | None = Field(default=None, description="Assigned cluster node.")
    age_seconds: int = Field(ge=0, description="Uptime age in seconds.")


class NodeStatusSummary(StrictBaseModel):
    """Health and resource saturation summary for a cluster node."""

    name: str = Field(description="Node hostname or identifier.")
    status: str = Field(description="Ready, NotReady, SchedulingDisabled.")
    roles: list[str] = Field(
        default_factory=list,
        description="Assigned roles (control-plane, worker).",
    )
    cpu_capacity: str = Field(description="Total CPU capacity (e.g. '8').")
    memory_capacity: str = Field(description="Total memory capacity (e.g. '16Gi').")
    conditions: dict[str, bool] = Field(
        default_factory=dict,
        description="Node pressure flags (MemoryPressure, DiskPressure, PIDPressure).",
    )


class ClusterOverviewRequest(StrictBaseModel):
    """Request parameters for cluster overview."""

    namespace_filter: list[NamespaceStr] | None = Field(
        default=None,
        description=(
            "Optional list of namespaces to limit inspection. "
            "If omitted, all namespaces are queried."
        ),
    )


class ClusterOverviewResponse(StrictBaseModel):
    """Overall cluster health status returned to the SRE agent."""

    total_nodes: int = Field(ge=0, description="Total node count.")
    total_pods: int = Field(ge=0, description="Total pod count across selected namespaces.")
    healthy_pods_count: int = Field(ge=0, description="Pods currently in Ready state.")
    unhealthy_pods: list[PodStatusSummary] = Field(
        default_factory=list,
        description=("List of pods failing readiness, crashing, or stuck in Pending/Error."),
    )
    nodes: list[NodeStatusSummary] = Field(description="Node health details.")
    timestamp: int = Field(description="Unix epoch timestamp when snapshot was taken.")


class GetPodLogsRequest(StrictBaseModel):
    """Request parameters for fetching pod logs."""

    namespace: NamespaceStr = Field(description="Namespace of target pod.")
    pod_name: str = Field(description="Name of target pod.")
    container: str | None = Field(
        default=None,
        description="Container name if pod has multiple containers. Defaults to primary.",
    )
    tail_lines: Annotated[
        int,
        Field(ge=1, le=1000, description="Maximum number of log lines to retrieve."),
    ] = 100
    since_seconds: Annotated[
        int | None,
        Field(default=None, ge=1, description="Relative time in seconds from which to fetch logs."),
    ] = None


class GetPodLogsResponse(StrictBaseModel):
    """Sanitized pod logs response guaranteed free of cleartext secrets and raw PII."""

    pod_name: str = Field(description="Queried pod name.")
    namespace: NamespaceStr = Field(description="Namespace.")
    container: str = Field(description="Container identifier.")
    sanitized_logs: str = Field(description="Log output with secrets redacted and PII tokenized.")
    redactions_count: int = Field(
        ge=0,
        description="Number of sensitive credential patterns redacted in this stream.",
    )
    tokenized_pii_count: int = Field(
        ge=0,
        description="Number of PII identifiers replaced with deterministic salted tokens.",
    )
    total_lines: int = Field(ge=0, description="Line count of retrieved logs.")
    truncated: bool = Field(
        default=False,
        description="True if output was capped due to token size limits.",
    )


class ClusterEventSummary(StrictBaseModel):
    """Structured representation of a Kubernetes Warning/Error event."""

    reason: str = Field(description="Event reason (e.g., FailedScheduling, BackOff, Unhealthy).")
    message: str = Field(description="Event description message.")
    count: int = Field(ge=1, description="Number of times this event occurred.")
    involved_object_kind: str = Field(description="Kind (Pod, Deployment, Node).")
    involved_object_name: str = Field(description="Name of the affected resource.")
    namespace: NamespaceStr | None = Field(default=None, description="Namespace of resource.")
    first_timestamp: str | None = Field(default=None, description="First occurrence timestamp.")
    last_timestamp: str | None = Field(
        default=None,
        description="Most recent occurrence timestamp.",
    )


class GetClusterEventsRequest(StrictBaseModel):
    """Request parameters for querying cluster events."""

    namespace: NamespaceStr | None = Field(
        default=None,
        description="Limit events to a specific namespace. If None, queries all namespaces.",
    )
    warning_only: bool = Field(
        default=True,
        description=(
            "If True, filters out Normal informational events and returns only Warnings/Errors."
        ),
    )
    limit: Annotated[
        int,
        Field(ge=1, le=200, description="Maximum number of events to return."),
    ] = 50


class GetClusterEventsResponse(StrictBaseModel):
    """Collection of cluster events matching query filters."""

    events: list[ClusterEventSummary] = Field(default_factory=list)
    total_events: int = Field(ge=0)
    warning_count: int = Field(ge=0)
