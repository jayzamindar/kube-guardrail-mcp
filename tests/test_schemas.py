"""Unit tests for AI-SRE Pydantic v2 schemas: boundary validation and 2PC token hashing."""

import json

import pytest
from pydantic import ValidationError

from ai_sre.schemas import (
    ApprovalTokenPayload,
    PlanRemediationRequest,
    RemediationActionType,
    RestartDeploymentAction,
    RollbackReleaseAction,
    ScaleWorkloadAction,
)


def test_scale_workload_within_bounds() -> None:
    """Ensure scale action validates successfully within fintech bounds [1, 10]."""
    action = ScaleWorkloadAction(
        namespace="payments",
        deployment_name="transaction-processor",
        replicas=5,
        audit_justification="High CPU pressure detected during peak settlement window",
    )
    assert action.action_type == RemediationActionType.SCALE_WORKLOAD
    assert action.replicas == 5
    assert action.namespace == "payments"


def test_scale_workload_rejects_zero_and_over_cap() -> None:
    """Ensure scaling to 0 (DoS hazard) or >10 (runaway cost) is rejected at schema boundary."""
    # Test min bound violation (replicas=0)
    with pytest.raises(ValidationError) as exc_min:
        ScaleWorkloadAction(
            namespace="payments",
            deployment_name="transaction-processor",
            replicas=0,
            audit_justification="Scale down to save costs",
        )
    assert "greater than or equal to 1" in str(exc_min.value)

    # Test max bound violation (replicas=11)
    with pytest.raises(ValidationError) as exc_max:
        ScaleWorkloadAction(
            namespace="payments",
            deployment_name="transaction-processor",
            replicas=11,
            audit_justification="Emergency traffic surge",
        )
    assert "less than or equal to 10" in str(exc_max.value)


def test_rollback_rejects_zero_revision() -> None:
    """Ensure blind rollback (target_revision=0) is rejected; explicit positive integer required."""
    with pytest.raises(ValidationError) as exc:
        RollbackReleaseAction(
            namespace="banking",
            deployment_name="ledger-svc",
            target_revision=0,
            audit_justification="Revert last deployment",
        )
    assert "greater than or equal to 1" in str(exc.value)

    # Valid revision passes
    action = RollbackReleaseAction(
        namespace="banking",
        deployment_name="ledger-svc",
        target_revision=3,
        audit_justification="Reverting to last certified stable release after canary error spike",
    )
    assert action.target_revision == 3


def test_immutability_and_extra_fields_forbidden() -> None:
    """Verify frozen=True prevents mutation and extra='forbid' stops payload injection."""
    action = RestartDeploymentAction(
        namespace="auth",
        deployment_name="oauth2-gateway",
        audit_justification="Clearing stale connection pool leaks",
    )

    # Immutability check
    with pytest.raises(ValidationError):
        action.namespace = "compromised-ns"

    # Extra field injection check
    with pytest.raises(ValidationError) as exc_extra:
        RestartDeploymentAction.model_validate(
            {
                "action_type": "restart_deployment",
                "namespace": "auth",
                "deployment_name": "oauth2-gateway",
                "audit_justification": "Legitimate reason",
                "injected_command": "rm -rf /",
            }
        )
    assert "Extra inputs are not permitted" in str(exc_extra.value)


def test_canonical_hashing_determinism() -> None:
    """Verify that canonical serialization produces deterministic hashes."""
    action1 = ScaleWorkloadAction(
        namespace="payments",
        deployment_name="fraud-detection",
        replicas=3,
        audit_justification="Scaling up replicas for real-time risk scoring",
    )

    action2 = ScaleWorkloadAction.model_validate(json.loads(action1.model_dump_json()))

    assert action1.canonical_payload_json() == action2.canonical_payload_json()
    assert action1.canonical_hash() == action2.canonical_hash()
    assert len(action1.canonical_hash()) == 64  # Valid SHA-256 hex string


def test_polymorphic_discriminated_union() -> None:
    """Verify that PlanRemediationRequest properly deserializes the right action type."""
    raw_payload = {
        "action": {
            "action_type": "restart_deployment",
            "namespace": "settlement",
            "deployment_name": "clearing-engine",
            "audit_justification": "Scheduled memory purge as per Runbook SRE-404",
        }
    }
    req = PlanRemediationRequest.model_validate(raw_payload)
    assert isinstance(req.action, RestartDeploymentAction)
    assert req.action.deployment_name == "clearing-engine"


def test_approval_token_payload() -> None:
    """Verify approval token payload fields and validation."""
    token = ApprovalTokenPayload(
        action_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        target_namespace="payments",
        target_workload="core-api",
        issued_at=1700000000,
        expires_at=1700000300,
        client_nonce="deadbeef12345678",
    )
    assert token.expires_at - token.issued_at == 300
