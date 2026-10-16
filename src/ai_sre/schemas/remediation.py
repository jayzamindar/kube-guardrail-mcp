"""Remediation action schemas, discriminated unions, and two-phase approval models."""

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import Field

from ai_sre.schemas.base import NamespaceStr, StrictBaseModel, WorkloadNameStr


class RemediationActionType(StrEnum):
    """Supported cluster mutating action types."""

    RESTART_DEPLOYMENT = "restart_deployment"
    SCALE_WORKLOAD = "scale_workload"
    ROLLBACK_RELEASE = "rollback_release"


class BaseRemediationAction(StrictBaseModel):
    """Abstract base for mutating actions requiring canonical hashing for 2PC token binding."""

    audit_justification: Annotated[
        str,
        Field(
            min_length=5,
            max_length=256,
            description="Mandatory SOX/Fintech audit reason explaining why mutation is needed.",
        ),
    ]

    def canonical_payload_json(self) -> str:
        """Produce deterministic, sorted JSON representation without whitespace for HMAC signing."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def canonical_hash(self) -> str:
        """Calculate SHA-256 fingerprint of the canonical payload."""
        return hashlib.sha256(self.canonical_payload_json().encode("utf-8")).hexdigest()


class RestartDeploymentAction(BaseRemediationAction):
    """Performs a rolling restart of a deployment (updating spec.template annotations)."""

    action_type: Literal[RemediationActionType.RESTART_DEPLOYMENT] = (
        RemediationActionType.RESTART_DEPLOYMENT
    )
    namespace: NamespaceStr = Field(description="Target Kubernetes namespace.")
    deployment_name: WorkloadNameStr = Field(description="Target deployment name.")


class ScaleWorkloadAction(BaseRemediationAction):
    """Scales a deployment's replica count within strict fintech safety bounds (1 to 10)."""

    action_type: Literal[RemediationActionType.SCALE_WORKLOAD] = (
        RemediationActionType.SCALE_WORKLOAD
    )
    namespace: NamespaceStr = Field(description="Target Kubernetes namespace.")
    deployment_name: WorkloadNameStr = Field(description="Target deployment name.")
    replicas: Annotated[
        int,
        Field(
            ge=1,
            le=10,
            description="Target replica count. Scaling to 0 is strictly forbidden to prevent DoS.",
        ),
    ]


class RollbackReleaseAction(BaseRemediationAction):
    """Rolls back a deployment to an explicit verified historical revision."""

    action_type: Literal[RemediationActionType.ROLLBACK_RELEASE] = (
        RemediationActionType.ROLLBACK_RELEASE
    )
    namespace: NamespaceStr = Field(description="Target Kubernetes namespace.")
    deployment_name: WorkloadNameStr = Field(description="Target deployment name.")
    target_revision: Annotated[
        int,
        Field(
            ge=1,
            description="Explicit historical revision target. Arbitrary revision 0 is forbidden.",
        ),
    ]


# Discriminated Union: guarantees compile-time & runtime validation based on 'action_type'
RemediationAction = Annotated[
    RestartDeploymentAction | ScaleWorkloadAction | RollbackReleaseAction,
    Field(discriminator="action_type"),
]


class ApprovalTokenPayload(StrictBaseModel):
    """Cryptographically bound capability token payload signed with HMAC-SHA256."""

    action_id: UUID = Field(default_factory=uuid4, description="Unique transaction trace ID.")
    action_hash: str = Field(description="SHA-256 hash of the canonical serialized action payload.")
    target_namespace: NamespaceStr = Field(description="Target namespace boundary.")
    target_workload: WorkloadNameStr = Field(description="Target workload identifier.")
    issued_at: int = Field(description="Unix epoch timestamp when token was minted.")
    expires_at: int = Field(description="Unix epoch timestamp when token expires (TTL: 300s).")
    client_nonce: str = Field(description="Entropy nonce to guarantee single-use anti-replay.")


class PlanRemediationRequest(StrictBaseModel):
    """Phase 1 Request: Agent proposes an action and requests a dry-run + capability token."""

    action: RemediationAction = Field(description="Specific polymorphic action payload.")


class PlanRemediationResponse(StrictBaseModel):
    """Phase 1 Response: Returns dry-run diff and the cryptographic approval token."""

    status: Literal["AWAITING_APPROVAL", "DRY_RUN_FAILED"] = "AWAITING_APPROVAL"
    action_id: UUID = Field(description="Unique correlation ID for this planned mutation.")
    approval_token: str = Field(
        description="Base64url-encoded signed HMAC capability token required for Phase 2."
    )
    expires_in_seconds: int = Field(default=300, description="Token remaining TTL in seconds.")
    dry_run_diff: str = Field(description="Unified diff preview of cluster state changes.")
    summary: str = Field(description="Human-readable remediation summary for operator review.")


class ExecuteRemediationRequest(StrictBaseModel):
    """Phase 2 Request: Agent submits the approval token and identical payload for execution."""

    approval_token: str = Field(
        description="The signed HMAC capability token issued in Phase 1 (plan_remediation)."
    )
    action: RemediationAction = Field(
        description="The identical action payload proposed during Phase 1."
    )


class ExecuteRemediationResponse(StrictBaseModel):
    """Phase 2 Response: Returns execution status and audit confirmation."""

    status: Literal[
        "EXECUTED",
        "REJECTED_TOKEN_INVALID",
        "REJECTED_TOKEN_EXPIRED",
        "EXECUTION_FAILED",
    ]
    action_id: UUID = Field(description="Correlation ID matching the original planned action.")
    executed_at: int = Field(description="Unix epoch timestamp of execution.")
    execution_summary: str = Field(description="Outcome details and Kubernetes event receipt.")
