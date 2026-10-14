"""Functional tests for the RAG vector store (embedded Qdrant + FastEmbed).

These exercise the real embedded store and ONNX embedding model end to end.
They are skipped automatically when the optional ``rag`` dependency group
is not installed (``uv sync --group rag``). The first run downloads the
FastEmbed model weights, so network access is required once.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

pytest.importorskip("qdrant_client", reason="rag dependency group not installed")
pytest.importorskip("fastembed", reason="rag dependency group not installed")

from src.rag.config import RAGConfig  # noqa: E402
from src.rag.ingest import DocumentChunk, DocumentIngester  # noqa: E402
from src.rag.retriever import ThreatIntelRetriever  # noqa: E402

DWELL_TIME_TEXT = (
    "# Detection Metrics Report\n\n"
    "## Dwell time\n\n"
    "The median dwell time for intrusions fell to 11 days in 2023. "
    "Ransomware incidents are detected faster, with a median of 5 days, "
    "while espionage campaigns persist for months before discovery.\n\n"
    "## Detection source\n\n"
    "External parties notified 62% of victims; internal teams found the rest."
)

SUPPLY_CHAIN_TEXT = (
    "Supply chain attacks accounted for 23% of incidents in the reporting "
    "period. Compromised dependencies and malicious packages were the "
    "dominant initial access vector in build environments."
)


@pytest.fixture()
def rag_config(tmp_path: Path) -> RAGConfig:
    """RAG config with two known documents in a temp directory."""
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "dwell_time.md").write_text(DWELL_TIME_TEXT, encoding="utf-8")
    (docs / "supply_chain.txt").write_text(SUPPLY_CHAIN_TEXT, encoding="utf-8")
    return RAGConfig(
        documents_dir=docs,
        vector_store_dir=tmp_path / "qdrant",
        output_dir=tmp_path / "out",
        top_k=4,
    )


def test_doc_id_is_valid_uuid_and_deterministic() -> None:
    """Point IDs satisfy Qdrant's UUID requirement and are stable."""
    first = DocumentChunk(text="text A", source="s.md", page=0, chunk_index=0)
    second = DocumentChunk(text="text B", source="s.md", page=0, chunk_index=0)

    assert uuid.UUID(first.doc_id)  # raises ValueError if malformed
    assert first.doc_id == second.doc_id  # keyed on position, not content
    assert (
        first.doc_id
        != DocumentChunk(text="text A", source="s.md", page=0, chunk_index=1).doc_id
    )


def test_ingest_and_retrieve_round_trip(rag_config: RAGConfig) -> None:
    """Markdown/text docs are chunked, embedded, stored, and retrievable."""
    ingester = DocumentIngester(rag_config)
    try:
        total = ingester.ingest_directory()
        assert total > 0
        assert ingester.client.count(rag_config.collection_name).count == total
    finally:
        ingester.close()

    retriever = ThreatIntelRetriever(rag_config)
    try:
        assert retriever.doc_count() == total

        chunks = retriever.retrieve("median dwell time before detection", top_k=3)

        assert chunks, "expected at least one retrieved chunk"
        scores = [c.score for c in chunks]
        assert scores == sorted(scores, reverse=True)
        assert all(0.0 <= s <= 1.0 for s in scores)
        assert chunks[0].source == "dwell_time.md"
        assert any("dwell" in c.text.lower() for c in chunks)

        context = retriever.format_context(chunks)
        assert "dwell_time.md" in context
        assert "relevance:" in context
    finally:
        retriever.close()


def test_reingest_is_idempotent(rag_config: RAGConfig) -> None:
    """A second ingest run stores zero duplicate chunks."""
    counts: list[int] = []
    for _ in range(2):
        ingester = DocumentIngester(rag_config)
        try:
            ingester.ingest_directory()
            counts.append(ingester.client.count(rag_config.collection_name).count)
        finally:
            ingester.close()

    assert counts[0] > 0
    assert counts[0] == counts[1]


def test_retriever_fails_without_ingested_store(tmp_path: Path) -> None:
    """Retrieval before ingestion raises a clear FileNotFoundError."""
    retriever = ThreatIntelRetriever(RAGConfig(vector_store_dir=tmp_path / "missing"))

    with pytest.raises(FileNotFoundError, match="Run ingestion first"):
        _ = retriever.client


def test_pdf_ingestion_and_retrieval(rag_config: RAGConfig) -> None:
    """PDFs are extracted via pymupdf4llm and become searchable chunks."""
    pymupdf = pytest.importorskip("pymupdf", reason="pymupdf4llm not installed")

    pdf_path = rag_config.documents_dir / "ransomware.pdf"
    doc = pymupdf.open()
    try:
        page = doc.new_page()
        page.insert_text(
            (72, 72),
            "Ransomware was present in 44 percent of breaches analysed. "
            "Median time from initial access to encryption was under 24 hours.",
        )
        doc.save(str(pdf_path))
    finally:
        doc.close()

    ingester = DocumentIngester(rag_config)
    try:
        total = ingester.ingest_directory()
    finally:
        ingester.close()
    assert total > 0

    retriever = ThreatIntelRetriever(rag_config)
    try:
        chunks = retriever.retrieve("ransomware share of breaches", top_k=3)
    finally:
        retriever.close()

    assert chunks
    assert chunks[0].source == "ransomware.pdf"
    assert "44 percent" in chunks[0].text or "44%" in chunks[0].text
