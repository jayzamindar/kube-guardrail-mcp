"""Guardrail engine for Level B Fintech credential redaction and PII tokenization."""

from dataclasses import dataclass

from ai_sre.guardrails.redactor import SecretRedactor
from ai_sre.guardrails.tokenizer import PIITokenizer


@dataclass(frozen=True)
class SanitizationResult:
    """Outcome of running text through the two-stage guardrail pipeline."""

    sanitized_text: str
    redactions_count: int
    tokenized_pii_count: int


class SanitizationPipeline:
    """Unified dual-stage fintech sanitization pipeline.

    Stage 1: High-entropy secret and credential redaction (AWS, JWTs, DB URLs, Private Keys).
    Stage 2: Deterministic salted PII tokenization with Luhn verification (PAN, SSN, IBAN, Email).
    """

    def __init__(
        self,
        redactor: SecretRedactor | None = None,
        tokenizer: PIITokenizer | None = None,
    ) -> None:
        self.redactor = redactor or SecretRedactor()
        self.tokenizer = tokenizer or PIITokenizer()

    def sanitize(self, raw_text: str) -> SanitizationResult:
        """Runs raw text through Stage 1 and Stage 2 in sequence."""
        # Stage 1: Strip high-entropy secrets and keys
        clean_secrets, secret_count = self.redactor.redact(raw_text)

        # Stage 2: Tokenize sensitive PII into correlated hash tokens
        final_text, pii_count = self.tokenizer.tokenize(clean_secrets)

        return SanitizationResult(
            sanitized_text=final_text,
            redactions_count=secret_count,
            tokenized_pii_count=pii_count,
        )


__all__ = [
    "PIITokenizer",
    "SanitizationPipeline",
    "SanitizationResult",
    "SecretRedactor",
]
