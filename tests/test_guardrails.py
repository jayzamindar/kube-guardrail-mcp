"""Unit tests for Level B Fintech Guardrails: secret redaction and PII tokenization."""

from ai_sre.guardrails import SanitizationPipeline, SecretRedactor
from ai_sre.guardrails.tokenizer import PIITokenizer, is_luhn_valid


def test_aws_and_jwt_secret_redaction() -> None:
    """Verify known credential signatures are masked with appropriate replacement tokens."""
    redactor = SecretRedactor()
    jwt_sample = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "doNotLeakThisTokenSignatureValue"
    )
    raw_log = (
        f"2026-10-15T22:00:00Z ERROR S3 connection failed using key AKIAIOSFODNN7EXAMPLE "
        f"and token {jwt_sample}"
    )

    sanitized, count = redactor.redact(raw_log)
    assert count == 2
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "[REDACTED_AWS_ACCESS_KEY]" in sanitized
    assert "[REDACTED_JWT_TOKEN]" in sanitized


def test_connection_string_password_redaction() -> None:
    """Ensure database connection URI passwords are excised while keeping host/db structure."""
    redactor = SecretRedactor()
    raw_log = (
        "FATAL: Connection refused for "
        "postgres://db_admin:P@ssw0rd99!Complex@prod-db.internal:5432/ledger"
    )

    sanitized, count = redactor.redact(raw_log)
    assert count >= 1
    assert "P@ssw0rd99!Complex" not in sanitized
    expected_masked = (
        "postgres://db_admin:[REDACTED_CONNECTION_STRING]@prod-db.internal:5432/ledger"
    )
    assert expected_masked in sanitized


def test_shannon_entropy_assignment_redaction() -> None:
    """Verify that unstructured high-entropy secrets in key=value assignments are caught."""
    redactor = SecretRedactor(entropy_threshold=4.0, min_token_len=16)
    raw_log = "Config dump: API_SECRET=9f8aB7c3D2e1F0gH8jK7lM6nP5qR4sT3uV2wX1yZ"

    sanitized, count = redactor.redact(raw_log)
    assert count == 1
    assert "9f8aB7c3D2e1F0gH8jK7lM6nP5qR4sT3uV2wX1yZ" not in sanitized
    assert "[REDACTED_HIGH_ENTROPY_SECRET]" in sanitized


def test_luhn_algorithm_validation() -> None:
    """Test Luhn algorithm correctly differentiates card numbers from random 16-digit IDs."""
    # Standard valid Visa test card number
    valid_visa = "4532015112830366"
    assert is_luhn_valid(valid_visa) is True

    # Valid MasterCard test number
    valid_mastercard = "5424 1801 2345 6789"
    assert is_luhn_valid(valid_mastercard) is True

    # Invalid 16-digit sequence (e.g. cluster trace ID)
    invalid_trace_id = "1234567890123456"
    assert is_luhn_valid(invalid_trace_id) is False


def test_pii_pan_tokenization_with_luhn_filter() -> None:
    """Ensure genuine card numbers are masked to salted tokens, while non-cards pass through."""
    tokenizer = PIITokenizer()
    raw_log = "Transaction failed for card 4532-0151-1283-0366 on trace_id 1234567890123456"

    sanitized, count = tokenizer.tokenize(raw_log)
    assert count == 1
    # Genuine PAN is tokenized
    assert "4532-0151-1283-0366" not in sanitized
    assert "[PII:PAN:" in sanitized
    # Non-card 16-digit trace ID remains untouched
    assert "1234567890123456" in sanitized


def test_pii_determinism_and_correlation() -> None:
    """Verify that identical PII values produce identical token hashes for log correlation."""
    tokenizer = PIITokenizer()
    log1 = "User alice@fintechbank.com triggered rate limit on account 987654321"
    log2 = "Alert: repeated login failure for alice@fintechbank.com"

    sanitized1, _ = tokenizer.tokenize(log1)
    sanitized2, _ = tokenizer.tokenize(log2)

    # Extract email token from log1
    assert "[PII:EMAIL:" in sanitized1
    assert "[PII:EMAIL:" in sanitized2

    email_token1 = [w for w in sanitized1.split() if w.startswith("[PII:EMAIL:")][0]
    email_token2 = [w for w in sanitized2.split() if w.startswith("[PII:EMAIL:")][0]

    # Both tokens must match identically so the AI can correlate them
    assert email_token1 == email_token2

    # Different email must produce a different hash
    log3 = "User bob@fintechbank.com logged in"
    sanitized3, _ = tokenizer.tokenize(log3)
    email_token3 = [w for w in sanitized3.split() if w.startswith("[PII:EMAIL:")][0]
    assert email_token1 != email_token3


def test_full_sanitization_pipeline() -> None:
    """Verify the integrated pipeline handles multi-vector credential and PII leakage."""
    pipeline = SanitizationPipeline()
    dirty_log = (
        "2026-10-15 ERROR customer=sarah.connor@banking.com card=4532015112830366 "
        "aws_key=AKIAIOSFODNN7EXAMPLE error='upstream connection timeout'"
    )

    result = pipeline.sanitize(dirty_log)
    assert result.redactions_count == 1  # AWS key
    assert result.tokenized_pii_count == 2  # Email + Card PAN

    assert "sarah.connor@banking.com" not in result.sanitized_text
    assert "4532015112830366" not in result.sanitized_text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.sanitized_text

    assert "[PII:EMAIL:" in result.sanitized_text
    assert "[PII:PAN:" in result.sanitized_text
    assert "[REDACTED_AWS_ACCESS_KEY]" in result.sanitized_text
