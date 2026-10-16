"""Local RAG schemas for runbook semantic search and indexing."""

from typing import Annotated

from pydantic import Field

from ai_sre.schemas.base import StrictBaseModel


class RunbookSearchResult(StrictBaseModel):
    """A matched section or document retrieved from local LanceDB vector store."""

    id: str = Field(description="Unique document or chunk identifier.")
    title: str = Field(description="Runbook or post-mortem title.")
    content: str = Field(description="Extracted markdown text content with remediation procedures.")
    score: float = Field(description="Vector cosine similarity or distance metric.")
    category: str = Field(description="Category (e.g. 'runbook', 'postmortem', 'architecture').")
    tags: list[str] = Field(
        default_factory=list,
        description="Associated system and component tags.",
    )
    source_path: str = Field(description="Local relative path to the source document.")


class SearchRunbooksRequest(StrictBaseModel):
    """Request parameters for searching SRE runbooks."""

    query: Annotated[
        str,
        Field(
            min_length=3,
            max_length=512,
            description="Diagnostic query or symptom (e.g. 'CrashLoopBackOff OOMKilled payments').",
        ),
    ]
    limit: Annotated[
        int,
        Field(default=3, ge=1, le=10, description="Max number of relevant runbooks to return."),
    ] = 3
    category_filter: str | None = Field(
        default=None,
        description="Optional filter by category ('runbook', 'postmortem', 'sop').",
    )
    min_score: Annotated[
        float,
        Field(default=0.30, ge=0.0, le=1.0, description="Minimum cosine relevance threshold."),
    ] = 0.30


class SearchRunbooksResponse(StrictBaseModel):
    """Semantic search results returned from local LanceDB."""

    query: str
    results: list[RunbookSearchResult] = Field(default_factory=list)
    total_found: int = Field(ge=0)


class IndexRunbookRequest(StrictBaseModel):
    """Request to ingest or update a runbook in the local vector database."""

    title: Annotated[str, Field(min_length=3, max_length=128)]
    content: Annotated[str, Field(min_length=20, max_length=50000)]
    category: Annotated[str, Field(min_length=2, max_length=32)] = "runbook"
    tags: list[str] = Field(default_factory=list)
    source_path: str = Field(default="custom_runbook.md")


class IndexRunbookResponse(StrictBaseModel):
    """Response confirming runbook ingestion."""

    status: str = "INDEXED"
    document_id: str
    chunks_indexed: int = Field(ge=1)
