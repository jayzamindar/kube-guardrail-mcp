"""Application configuration and environment settings using Pydantic Settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for AI-SRE Cluster Manager."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server Info
    server_name: str = "ai-sre-cluster-manager"
    server_version: str = "0.1.0"

    # Local RAG & Vector Storage
    db_path: str = Field(default="./data/lancedb", alias="AI_SRE_DB_PATH")

    # Immutable Audit Logging
    audit_log_path: str = Field(default="./data/audit/audit.jsonl", alias="AI_SRE_AUDIT_LOG_PATH")

    # Cryptographic Secrets
    salt: str | None = Field(default=None, alias="AI_SRE_SALT")
    gate_secret: str | None = Field(default=None, alias="AI_SRE_GATE_SECRET")
    approval_token_ttl: int = Field(default=300, alias="AI_SRE_DEFAULT_TTL")

    # OpenTelemetry
    otlp_endpoint: str | None = Field(default=None, alias="OTEL_EXPORTER_OTLP_ENDPOINT")


settings = Settings()
