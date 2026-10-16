"""Deterministic, salted PII tokenizer with Luhn-validated PAN masking."""

import hashlib
import hmac
import logging
import os
import re
import secrets
from typing import Final

logger = logging.getLogger("ai_sre.guardrails.tokenizer")


def is_luhn_valid(candidate: str) -> bool:
    """Verifies a sequence of digits against the ISO/IEC 7812 Luhn checksum algorithm.

    Used to distinguish genuine Primary Account Numbers (credit/debit cards) from random
    16-digit order IDs or internal sequence numbers.
    """
    digits = [int(char) for char in candidate if char.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    total = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0


# PAN pattern: 13-19 digits formatted with optional spaces or dashes
PAN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# Standard PII patterns
EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
SSN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
IBAN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
ACCOUNT_NUM_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:acct|account|acc_num)[_#:\s]+([0-9]{8,17})\b"
)


class PIITokenizer:
    """Deterministic, irreversible salted tokenizer for PII.

    Converts raw PII into correlated tokens [PII:<TYPE>:<HASH_8>] allowing SRE agents to trace
    repeating customer accounts or errors across disparate logs without exposing cleartext data.
    """

    _instance: "PIITokenizer | None" = None
    _salt: bytes

    def __new__(cls, *args: object, **kwargs: object) -> "PIITokenizer":
        """Singleton pattern: guarantees the salt is immutable for the lifetime of the process."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize_salt()
        return cls._instance

    def _initialize_salt(self) -> None:
        """Loads salt from AI_SRE_SALT or generates an ephemeral 32-byte salt."""
        env_salt = os.getenv("AI_SRE_SALT")
        if env_salt:
            self._salt = env_salt.encode("utf-8")
        else:
            logger.warning(
                "AI_SRE_SALT environment variable not configured. "
                "Generating ephemeral 256-bit random salt for this session."
            )
            self._salt = secrets.token_bytes(32)

    def _hash_token(self, pii_type: str, raw_value: str) -> str:
        """Computes HMAC-SHA256(salt, normalized_value) and returns an 8-character hex digest."""
        normalized = raw_value.strip().lower()
        digest = hmac.new(self._salt, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"[PII:{pii_type}:{digest[:8]}]"

    def tokenize(self, text: str) -> tuple[str, int]:
        """Scans, identifies, and transforms PII entities into salted deterministic tokens.

        Returns:
            tuple[str, int]: (tokenized_text, total_tokenized_count)
        """
        tokenized_count = 0
        tokenized_text = text

        # 1. PAN / Credit Cards (Must satisfy Luhn Check)
        def replace_pan(m: re.Match[str]) -> str:
            nonlocal tokenized_count
            matched_str = m.group(0)
            cleaned_digits = re.sub(r"[ -]", "", matched_str)
            if is_luhn_valid(cleaned_digits):
                tokenized_count += 1
                return self._hash_token("PAN", cleaned_digits)
            # Fails Luhn check -> harmless sequence number or trace ID
            return matched_str

        tokenized_text = PAN_PATTERN.sub(replace_pan, tokenized_text)

        # 2. Email Addresses
        def replace_email(m: re.Match[str]) -> str:
            nonlocal tokenized_count
            tokenized_count += 1
            return self._hash_token("EMAIL", m.group(0))

        tokenized_text = EMAIL_PATTERN.sub(replace_email, tokenized_text)

        # 3. Social Security Numbers (SSN)
        def replace_ssn(m: re.Match[str]) -> str:
            nonlocal tokenized_count
            tokenized_count += 1
            return self._hash_token("SSN", m.group(0))

        tokenized_text = SSN_PATTERN.sub(replace_ssn, tokenized_text)

        # 4. IBAN (International Bank Account Number)
        def replace_iban(m: re.Match[str]) -> str:
            nonlocal tokenized_count
            tokenized_count += 1
            return self._hash_token("IBAN", m.group(0))

        tokenized_text = IBAN_PATTERN.sub(replace_iban, tokenized_text)

        # 5. Account Numbers
        def replace_acct(m: re.Match[str]) -> str:
            nonlocal tokenized_count
            full_match = m.group(0)
            acct_digits = m.group(1)
            tokenized_count += 1
            hashed = self._hash_token("ACCT", acct_digits)
            return full_match.replace(acct_digits, hashed)

        tokenized_text = ACCOUNT_NUM_PATTERN.sub(replace_acct, tokenized_text)

        return tokenized_text, tokenized_count
