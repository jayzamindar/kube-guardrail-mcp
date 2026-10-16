"""Two-Phase Capability Approval Gate: HMAC-SHA256 signing, verification, and anti-replay cache."""

import base64
import hmac
import json
import logging
import os
import secrets
import time
from typing import Final, Literal

from ai_sre.schemas.remediation import ApprovalTokenPayload, BaseRemediationAction

logger = logging.getLogger("ai_sre.security.approval_gate")

ErrorCode = Literal["TOKEN_EXPIRED", "TOKEN_REPLAYED", "INVALID_CAPABILITY"]


class ApprovalGateError(Exception):
    """Raised when capability token verification fails."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class ApprovalGate:
    """Zero-trust capability gate enforcing Two-Phase Commit for cluster mutations.

    Phase 1: Mints a cryptographically signed capability token bound to the action payload.
    Phase 2: Validates HMAC-SHA256 signature, expiry TTL, payload hash, and single-use nonce.
    """

    DEFAULT_TTL_SECONDS: Final[int] = 300

    def __init__(
        self,
        secret_key: bytes | None = None,
        default_ttl: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self.default_ttl = default_ttl
        self._used_nonces: dict[str, float] = {}

        if secret_key:
            self._secret_key = secret_key
        else:
            env_secret = os.getenv("AI_SRE_GATE_SECRET")
            if env_secret:
                self._secret_key = env_secret.encode("utf-8")
            else:
                logger.warning("AI_SRE_GATE_SECRET not set. Generating ephemeral 256-bit secret.")
                self._secret_key = secrets.token_bytes(32)

    def _prune_expired_nonces(self, current_time: float) -> None:
        """Self-cleaning eviction loop to keep memory footprint bounded."""
        expired = [nonce for nonce, exp in self._used_nonces.items() if current_time > exp]
        for nonce in expired:
            del self._used_nonces[nonce]

    def _sign(self, data: bytes) -> bytes:
        """Calculates HMAC-SHA256 signature for data payload."""
        return hmac.new(self._secret_key, data, "sha256").digest()

    def mint_token(
        self,
        action: BaseRemediationAction,
        ttl_seconds: int | None = None,
    ) -> tuple[str, ApprovalTokenPayload]:
        """Phase 1: Mints a compact, signed capability token bound to the action payload."""
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        now = int(time.time())
        expires_at = now + ttl

        # Extract namespace and workload if present on the action
        target_namespace = getattr(action, "namespace", "default")
        target_workload = getattr(action, "deployment_name", "unknown")

        payload = ApprovalTokenPayload(
            action_hash=action.canonical_hash(),
            target_namespace=target_namespace,
            target_workload=target_workload,
            issued_at=now,
            expires_at=expires_at,
            client_nonce=secrets.token_hex(16),
        )

        payload_bytes = payload.model_dump_json().encode("utf-8")
        signature = self._sign(payload_bytes)

        # Compact base64url serialization: base64(payload).base64(signature)
        encoded_payload = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        encoded_sig = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        token_str = f"{encoded_payload}.{encoded_sig}"

        return token_str, payload

    def verify_and_consume(
        self,
        token_str: str,
        action: BaseRemediationAction,
    ) -> ApprovalTokenPayload:
        """Phase 2: Validates token signature, TTL, payload integrity, and single-use nonce.

        Raises:
            ApprovalGateError: On expired, replayed, tampered, or invalid capability tokens.
        """
        now = time.time()
        self._prune_expired_nonces(now)

        # 1. Unpack token segments
        parts = token_str.split(".")
        if len(parts) != 2:
            raise ApprovalGateError("INVALID_CAPABILITY", "Malformed capability token format.")

        encoded_payload, encoded_sig = parts

        try:
            # Pad base64url strings if necessary
            payload_padding = "=" * (-len(encoded_payload) % 4)
            sig_padding = "=" * (-len(encoded_sig) % 4)
            payload_bytes = base64.urlsafe_b64decode(encoded_payload + payload_padding)
            provided_signature = base64.urlsafe_b64decode(encoded_sig + sig_padding)
        except Exception as e:
            raise ApprovalGateError("INVALID_CAPABILITY", "Invalid token encoding.") from e

        # 2. Verify HMAC signature in constant time
        expected_signature = self._sign(payload_bytes)
        if not hmac.compare_digest(expected_signature, provided_signature):
            raise ApprovalGateError("INVALID_CAPABILITY", "Capability authorization rejected.")

        # 3. Parse payload
        try:
            payload_dict = json.loads(payload_bytes.decode("utf-8"))
            payload = ApprovalTokenPayload.model_validate(payload_dict)
        except Exception as e:
            raise ApprovalGateError("INVALID_CAPABILITY", "Corrupted token payload.") from e

        # 4. Check expiration TTL
        if now > payload.expires_at:
            raise ApprovalGateError(
                "TOKEN_EXPIRED",
                f"Capability token expired {int(now - payload.expires_at)}s ago.",
            )

        # 5. Anti-Replay Check
        if payload.client_nonce in self._used_nonces:
            raise ApprovalGateError(
                "TOKEN_REPLAYED",
                "Replay detected: capability token has already been consumed.",
            )

        # 6. Payload Binding Check (Compare canonical SHA-256 hashes)
        current_action_hash = action.canonical_hash()
        if not hmac.compare_digest(payload.action_hash, current_action_hash):
            # Mask detailed hash mismatch as uniform INVALID_CAPABILITY to prevent oracles
            raise ApprovalGateError("INVALID_CAPABILITY", "Capability authorization rejected.")

        # 7. Consume capability: record nonce to prevent reuse
        self._used_nonces[payload.client_nonce] = float(payload.expires_at)

        return payload
