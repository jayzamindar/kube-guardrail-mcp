"""Embedded LanceDB vector store for SRE runbooks, post-mortems, and procedures."""

import logging
import os
from pathlib import Path
from typing import Final

import lancedb
import pyarrow as pa  # type: ignore[import-untyped]
from lancedb.table import Table

from ai_sre.rag.chunker import MarkdownChunker
from ai_sre.rag.embeddings import EMBEDDING_DIMENSION, LocalEmbedder
from ai_sre.schemas.rag import RunbookSearchResult

logger = logging.getLogger("ai_sre.rag.vector_store")

DEFAULT_DB_PATH: Final[str] = "./data/lancedb"
RUNBOOKS_TABLE_NAME: Final[str] = "runbooks"


class RunbookVectorStore:
    """Local, embedded vector storage backed by LanceDB and FastEmbed.

    Provides microsecond-latency semantic search over Kubernetes runbooks and post-mortems
    with zero cloud API egress.
    """

    def __init__(
        self,
        db_path: Path | str | None = None,
        embedder: LocalEmbedder | None = None,
        chunker: MarkdownChunker | None = None,
    ) -> None:
        if db_path is not None:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path(os.getenv("AI_SRE_DB_PATH", DEFAULT_DB_PATH))

        self.embedder = embedder or LocalEmbedder()
        self.chunker = chunker or MarkdownChunker()

        self._db: lancedb.DBConnection | None = None
        self._table: Table | None = None

    def _get_table(self) -> Table:
        """Connects to LanceDB and opens or initializes the runbooks table schema."""
        if self._table is not None:
            return self._table

        self.db_path.mkdir(parents=True, exist_ok=True)
        self._db = lancedb.connect(str(self.db_path))

        try:
            self._table = self._db.open_table(RUNBOOKS_TABLE_NAME)
        except Exception:
            schema = pa.schema(
                [
                    pa.field("id", pa.string()),
                    pa.field("title", pa.string()),
                    pa.field("content", pa.string()),
                    pa.field("category", pa.string()),
                    pa.field("tags", pa.list_(pa.string())),
                    pa.field("source_path", pa.string()),
                    pa.field("vector", pa.list_(pa.float32(), EMBEDDING_DIMENSION)),
                ]
            )
            self._table = self._db.create_table(
                RUNBOOKS_TABLE_NAME, schema=schema, exist_ok=True
            )
            logger.info("Initialized new LanceDB runbooks table at %s", self.db_path)

        return self._table

    def index_document(
        self,
        title: str,
        content: str,
        category: str = "runbook",
        tags: list[str] | None = None,
        source_path: str = "runbook.md",
    ) -> int:
        """Chunks, embeds, and indexes a markdown document into LanceDB."""
        chunks = self.chunker.chunk_document(
            title=title,
            content=content,
            category=category,
            tags=tags,
            source_path=source_path,
        )
        if not chunks:
            return 0

        # Batch embed all chunk texts in parallel on CPU
        texts_to_embed = [chunk.content for chunk in chunks]
        vectors = self.embedder.embed_batch(texts_to_embed)

        records = [
            {
                "id": chunk.id,
                "title": chunk.title,
                "content": chunk.content,
                "category": chunk.category,
                "tags": chunk.tags,
                "source_path": chunk.source_path,
                "vector": vector,
            }
            for chunk, vector in zip(chunks, vectors, strict=True)
        ]

        table = self._get_table()
        table.add(records)
        logger.info("Indexed %d chunks for document '%s'", len(records), title)
        return len(records)

    def search(
        self,
        query: str,
        limit: int = 3,
        category_filter: str | None = None,
        min_score: float = 0.30,
    ) -> list[RunbookSearchResult]:
        """Performs cosine vector search with metadata filtering and relevance scoring."""
        table = self._get_table()
        query_vector = self.embedder.embed_text(query)

        # Retrieve a wider pool to account for post-query category and score filtering
        search_builder = (
            table.search(query_vector)
            .distance_type("cosine")  # type: ignore[attr-defined]
            .limit(limit * 3)
        )

        if category_filter:
            search_builder = search_builder.where(f"category = '{category_filter}'")

        rows = search_builder.to_list()
        results: list[RunbookSearchResult] = []

        for row in rows:
            # LanceDB cosine metric returns distance where 0.0 is identical
            raw_distance = float(row.get("_distance", 1.0))
            score = max(0.0, 1.0 - raw_distance)

            if score < min_score:
                continue

            results.append(
                RunbookSearchResult(
                    id=str(row["id"]),
                    title=str(row["title"]),
                    content=str(row["content"]),
                    score=round(score, 4),
                    category=str(row["category"]),
                    tags=list(row.get("tags") or []),
                    source_path=str(row.get("source_path", "runbook.md")),
                )
            )

            if len(results) >= limit:
                break

        return results
