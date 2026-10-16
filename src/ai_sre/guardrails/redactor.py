"""High-entropy secret scanner and pattern-based credential redactor."""

import math
import re
from collections import Counter
from typing import Final


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character.

    H(X) = - sum(P(x) * log2(P(x)))
    Higher entropy indicates random/pseudorandom character distributions typical of API keys,
    hashes, and cryptographically generated tokens.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


# High-confidence deterministic signatures for known credential formats
KNOWN_SECRET_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    # Private Key blocks
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    # JWT tokens: header.payload.signature
    (
        "JWT_TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b"),
    ),
    # Bearer tokens (non-JWT fallback)
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/]+=*)"),
    ),
    # AWS Access Key IDs (20 chars, starting with AKIA/ABIA/ACCA/ASIA)
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    ),
    # AWS Secret Access Key in key-value config
    (
        "AWS_SECRET_KEY",
        re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
    # GitHub personal access tokens
    (
        "GITHUB_TOKEN",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"),
    ),
    # Database connection strings with credentials: scheme://user:password@host
    (
        "CONNECTION_STRING",
        re.compile(
            r"(?i)\b((?:postgres|postgresql|mysql|mongodb|redis|amqp):\/\/[^\s:@\/]+:)"
            r"(.*)"
            r"(@(?:[a-zA-Z0-9\-_]+(?:\.[a-zA-Z0-9\-_]+)+|localhost|\d{1,3}(?:\.\d{1,3}){3})"
            r"(?::\d+)?(?:\/[^\s\"']*)?)"
        ),
    ),
]

# Pattern for capturing key=value or key: value credential assignments
ASSIGNMENT_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"""(?ix)
    \b(?:password|passwd|secret|api[_-]?(?:key|secret)|token|auth[_-]?token|client[_-]?secret)\s*
    [:=]\s*
    ['"]?([^'"\s]{8,})['"]?
    """
)


class SecretRedactor:
    """Fintech-grade credential redactor with high-entropy fallback detection."""

    def __init__(self, entropy_threshold: float = 4.0, min_token_len: int = 16) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_token_len = min_token_len

    def redact(self, text: str) -> tuple[str, int]:
        """Scans and redacts credentials from input text.

        Returns:
            tuple[str, int]: (sanitized_text, total_redactions_count)
        """
        redactions_count = 0
        sanitized = text

        # Stage 1: Explicit pattern matching for known signature formats
        for secret_name, pattern in KNOWN_SECRET_PATTERNS:

            def replace_match(m: re.Match[str], name: str = secret_name) -> str:
                nonlocal redactions_count
                redactions_count += 1

                # Specific handling for connection strings (replace password only)
                if name == "CONNECTION_STRING" and m.lastindex == 3:
                    prefix = m.group(1)
                    suffix = m.group(3)
                    return f"{prefix}[REDACTED_CONNECTION_STRING]{suffix}"

                # Specific handling for bearer token or key-value configs
                if name in ("BEARER_TOKEN", "AWS_SECRET_KEY") and m.lastindex == 1:
                    full_str = m.group(0)
                    secret_val = m.group(1)
                    return full_str.replace(secret_val, f"[REDACTED_{name}]")

                return f"[REDACTED_{name}]"

            sanitized = pattern.sub(replace_match, sanitized)

        # Stage 2: Generic assignment detection with Shannon Entropy calculation
        def evaluate_assignment(m: re.Match[str]) -> str:
            nonlocal redactions_count
            full_match = m.group(0)
            candidate_secret = m.group(1)

            # Avoid double-redacting if already masked in Stage 1
            if "[REDACTED_" in candidate_secret:
                return full_match

            # Check if secret value qualifies by length and entropy threshold
            if len(candidate_secret) >= self.min_token_len:
                entropy = calculate_shannon_entropy(candidate_secret)
                if entropy >= self.entropy_threshold:
                    redactions_count += 1
                    return full_match.replace(candidate_secret, "[REDACTED_HIGH_ENTROPY_SECRET]")
            return full_match

        sanitized = ASSIGNMENT_PATTERN.sub(evaluate_assignment, sanitized)

        return sanitized, redactions_count
