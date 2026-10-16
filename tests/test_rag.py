"""Unit tests for Local RAG Pipeline: chunking hierarchy, vector generation, and LanceDB search."""

from pathlib import Path

from ai_sre.rag import (
    EMBEDDING_DIMENSION,
    LocalEmbedder,
    MarkdownChunker,
    RunbookVectorStore,
)


def test_markdown_chunker_hierarchical_context() -> None:
    """Verify markdown sections inherit structural heading paths."""
    sample_md = """# Payments Architecture
Overview of payments settlement architecture.

## Incident Response
General procedure for triaging payment failures.

### CrashLoopBackOff Resolution
When payments-svc is failing readiness:
1. Check pod logs for OOMKilled or SIGTERM.
2. Verify Redis cluster connection.
"""
    chunker = MarkdownChunker(max_chunk_chars=1000)
    chunks = chunker.chunk_document(
        title="Payments SRE Guide",
        content=sample_md,
        category="runbook",
        tags=["payments", "k8s"],
    )

    assert len(chunks) == 3
    # Check that deepest section contains full hierarchy path
    crashloop_chunk = [c for c in chunks if "CrashLoopBackOff" in c.heading_path][0]
    expected_header = "[Payments Architecture > Incident Response > CrashLoopBackOff Resolution]"
    assert expected_header in crashloop_chunk.content
    assert crashloop_chunk.category == "runbook"
    assert "payments" in crashloop_chunk.tags


def test_markdown_chunker_sliding_window_for_large_sections() -> None:
    """Verify that sections exceeding max_chunk_chars trigger sliding window with overlap."""
    large_body = "SRE Procedure Step Details: " + ("x" * 2500)
    sample_md = f"# Large Runbook\n## Detailed Section\n{large_body}"

    chunker = MarkdownChunker(max_chunk_chars=1000, overlap_chars=200)
    chunks = chunker.chunk_document(title="Big Doc", content=sample_md)

    # Should be partitioned into multiple parts (Part 1, Part 2, Part 3)
    assert len(chunks) > 1
    assert "Part 1" in chunks[0].heading_path
    assert "Part 2" in chunks[1].heading_path


def test_local_embedder_dimension() -> None:
    """Verify FastEmbed generates 384-dimensional dense vectors on CPU."""
    embedder = LocalEmbedder()
    vector = embedder.embed_text("Kubernetes Pod OOMKilled triage procedure")

    assert len(vector) == EMBEDDING_DIMENSION
    assert all(isinstance(x, float) for x in vector)


def test_lancedb_indexing_and_semantic_search(tmp_path: Path) -> None:
    """Verify indexing runbooks into embedded LanceDB and semantic retrieval accuracy."""
    vector_store = RunbookVectorStore(db_path=tmp_path / "test_lancedb")

    oom_runbook = """# Runbook: OOMKilled Diagnostics
## Symptoms
Pod terminates with ExitCode 137 or reason OOMKilled.
## Remediation
1. Increase memory request and limits in deployment manifest.
2. Inspect JVM heap size or memory leaks in transaction buffer.
"""

    redis_runbook = """# Runbook: Redis Cache Saturation
## Symptoms
Elevated latency on read operations, maxmemory eviction warnings.
## Remediation
1. Scale up Redis cluster replica nodes.
2. Flush expired session keys or update eviction policy to volatile-lru.
"""

    indexed_oom = vector_store.index_document(
        title="OOMKilled Diagnostics",
        content=oom_runbook,
        category="runbook",
        tags=["memory", "oom", "linux"],
    )
    indexed_redis = vector_store.index_document(
        title="Redis Cache Saturation",
        content=redis_runbook,
        category="runbook",
        tags=["redis", "cache", "latency"],
    )

    assert indexed_oom >= 1
    assert indexed_redis >= 1

    # 1. Query for memory termination should rank OOMKilled runbook first
    results = vector_store.search("pod killed exit code 137 out of memory", limit=2, min_score=0.50)
    assert len(results) >= 1
    assert "OOMKilled" in results[0].title
    assert results[0].score >= 0.50

    # 2. Query for cache latency should return Redis runbook
    redis_results = vector_store.search(
        "redis eviction spike cache latency", limit=2, min_score=0.50
    )
    assert len(redis_results) >= 1
    assert "Redis" in redis_results[0].title

    # 3. Completely irrelevant query filtered out by min_score
    irrelevant_results = vector_store.search(
        "chocolate chip cookie recipe with butter", min_score=0.75
    )
    assert len(irrelevant_results) == 0
