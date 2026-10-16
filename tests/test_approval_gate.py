"""Unit tests for Two-Phase Approval Gate: capability tokens, anti-replay, and tamper resistance."""

import time

import pytest

from ai_sre.schemas.remediation import (
    RestartDeploymentAction,
    ScaleWorkloadAction,
)
from ai_sre.security import ApprovalGate, ApprovalGateError


def test_happy_path_mint_and_verify() -> None:
    """Verify that a valid token minted in Phase 1 can be consumed in Phase 2."""
    gate = ApprovalGate(secret_key=b"test-secret-key-for-fintech-sre-32b")
    action = ScaleWorkloadAction(
        namespace="payments",
        deployment_name="transaction-processor",
        replicas=4,
        audit_justification="Scaling to accommodate morning settlement batch",
    )

    token_str, minted_payload = gate.mint_token(action, ttl_seconds=60)
    assert token_str is not None
    assert minted_payload.action_hash == action.canonical_hash()

    # Phase 2: Consume capability
    consumed_payload = gate.verify_and_consume(token_str, action)
    assert consumed_payload.client_nonce == minted_payload.client_nonce
    assert consumed_payload.action_hash == action.canonical_hash()


def test_replay_attack_rejected() -> None:
    """Verify that a capability token cannot be re-used after being consumed."""
    gate = ApprovalGate()
    action = RestartDeploymentAction(
        namespace="auth",
        deployment_name="oauth2-proxy",
        audit_justification="Cycling pods after configmap update",
    )

    token_str, _ = gate.mint_token(action, ttl_seconds=60)

    # First consumption succeeds
    gate.verify_and_consume(token_str, action)

    # Second consumption attempt MUST raise TOKEN_REPLAYED
    with pytest.raises(ApprovalGateError) as exc_info:
        gate.verify_and_consume(token_str, action)

    assert exc_info.value.code == "TOKEN_REPLAYED"


def test_expired_token_rejected() -> None:
    """Verify that an expired token is rejected with TOKEN_EXPIRED."""
    gate = ApprovalGate()
    action = ScaleWorkloadAction(
        namespace="banking",
        deployment_name="core-ledger",
        replicas=2,
        audit_justification="Reducing replicas after load window",
    )

    # Mint token with 0 TTL (instantly expired)
    token_str, _ = gate.mint_token(action, ttl_seconds=0)

    # Sleep slightly to ensure time advances past issued_at
    time.sleep(0.01)

    with pytest.raises(ApprovalGateError) as exc_info:
        gate.verify_and_consume(token_str, action)

    assert exc_info.value.code == "TOKEN_EXPIRED"


def test_payload_tampering_rejected_as_invalid_capability() -> None:
    """Verify that altering any field in the action payload causes immediate rejection.

    Crucially, it must return generic INVALID_CAPABILITY rather than leaking hash differences.
    """
    gate = ApprovalGate()
    planned_action = ScaleWorkloadAction(
        namespace="payments",
        deployment_name="transaction-processor",
        replicas=3,
        audit_justification="Original approved plan",
    )

    token_str, _ = gate.mint_token(planned_action, ttl_seconds=60)

    # Attacker tries to execute with replicas=8 using the token issued for replicas=3
    tampered_action = ScaleWorkloadAction(
        namespace="payments",
        deployment_name="transaction-processor",
        replicas=8,
        audit_justification="Original approved plan",
    )

    with pytest.raises(ApprovalGateError) as exc_info:
        gate.verify_and_consume(token_str, tampered_action)

    assert exc_info.value.code == "INVALID_CAPABILITY"


def test_signature_forgery_rejected() -> None:
    """Verify that forged or altered signatures are rejected as INVALID_CAPABILITY."""
    gate = ApprovalGate()
    action = RestartDeploymentAction(
        namespace="settlement",
        deployment_name="clearing-engine",
        audit_justification="Standard rolling restart",
    )

    token_str, _ = gate.mint_token(action, ttl_seconds=60)
    encoded_payload, encoded_sig = token_str.split(".")

    # Forge signature by altering the last character
    forged_sig = encoded_sig[:-1] + ("A" if encoded_sig[-1] != "A" else "B")
    forged_token = f"{encoded_payload}.{forged_sig}"

    with pytest.raises(ApprovalGateError) as exc_info:
        gate.verify_and_consume(forged_token, action)

    assert exc_info.value.code == "INVALID_CAPABILITY"


def test_nonce_eviction_lifecycle() -> None:
    """Verify that expired nonces are purged from internal memory to prevent memory leaks."""
    gate = ApprovalGate()
    current_time = time.time()

    # Pre-populate internal cache with 1 expired nonce and 1 active nonce
    gate._used_nonces["expired_nonce"] = current_time - 10
    gate._used_nonces["active_nonce"] = current_time + 100

    assert len(gate._used_nonces) == 2

    # Trigger prune
    gate._prune_expired_nonces(current_time)

    assert "expired_nonce" not in gate._used_nonces
    assert "active_nonce" in gate._used_nonces
    assert len(gate._used_nonces) == 1
