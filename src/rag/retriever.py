"""Retrieval module for threat parameter calibration.

Handles embedding queries, retrieving relevant chunks from an
embedded Qdrant vector store, and formatting context for the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.rag.config import RAGConfig

if TYPE_CHECKING:
    from qdrant_client import QdrantClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    """A retrieved chunk with relevance score.

    Attributes:
        text: Chunk text content.
        source: Source document filename.
        page: Page number in source document.
        heading: Nearest section heading.
        score: Cosine similarity score (clamped to 0-1, higher is better).
    """

    text: str
    source: str
    page: int
    heading: str
    score: float


class ThreatIntelRetriever:
    """Retrieves relevant threat intelligence passages for parameter calibration.

    Args:
        config: RAG configuration instance.
    """

    def __init__(self, config: RAGConfig | None = None) -> None:
        self.config = config or RAGConfig()
        self._client: QdrantClient | None = None

    @property
    def client(self) -> QdrantClient:
        """Lazy-initialise the embedded Qdrant client (read-mostly)."""
        if self._client is None:
            if not self.config.vector_store_dir.exists():
                msg = (
                    f"Vector store not found: {self.config.vector_store_dir}. "
                    "Run ingestion first."
                )
                raise FileNotFoundError(msg)
            try:
                from qdrant_client import QdrantClient
            except ImportError as exc:
                msg = "Install the optional RAG dependencies with: uv sync --group rag"
                raise RuntimeError(msg) from exc
            client = QdrantClient(path=str(self.config.vector_store_dir))
            if not client.collection_exists(self.config.collection_name):
                msg = (
                    f"Collection '{self.config.collection_name}' not found. "
                    "Run ingestion first."
                )
                raise FileNotFoundError(msg)
            self._client = client
            logger.info(
                "Connected to collection '%s' (%d documents)",
                self.config.collection_name,
                self.doc_count(),
            )
        return self._client

    def close(self) -> None:
        """Release the embedded store's file lock."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def doc_count(self) -> int:
        """Return the number of stored chunks."""
        return self.client.count(self.config.collection_name).count

    def retrieve(self, query: str, top_k: int | None = None) -> list[RetrievedChunk]:
        """Retrieve the most relevant chunks for a query.

        Args:
            query: Natural language query string.
            top_k: Number of results. Defaults to config.top_k.

        Returns:
            List of retrieved chunks sorted by relevance (best first).
        """
        from qdrant_client import models

        k = top_k or self.config.top_k

        points = self.client.query_points(
            collection_name=self.config.collection_name,
            query=models.Document(text=query, model=self.config.embedding_model),
            limit=k,
            with_payload=True,
        ).points

        chunks: list[RetrievedChunk] = []
        if not points:
            logger.warning("No results for query: %s", query[:80])
            return chunks

        for point in points:
            # Qdrant cosine score is already a similarity (higher is better)
            similarity = max(0.0, min(1.0, float(point.score)))
            meta = point.payload or {}
            source = meta.get("source")
            page = meta.get("page")
            heading = meta.get("heading")
            text = meta.get("text")
            chunks.append(
                RetrievedChunk(
                    text=text if isinstance(text, str) else "",
                    source=source if isinstance(source, str) else "unknown",
                    page=int(page) if isinstance(page, (int, float)) else 0,
                    heading=heading if isinstance(heading, str) else "",
                    score=similarity,
                )
            )

        return chunks

    def format_context(self, chunks: list[RetrievedChunk]) -> str:
        """Format retrieved chunks into a context string for the LLM.

        Includes source attribution for each chunk so the LLM can
        cite its sources in the output.

        Args:
            chunks: List of retrieved chunks.

        Returns:
            Formatted context string with source citations.
        """
        if not chunks:
            return "No relevant threat intelligence passages found."

        parts: list[str] = []
        for i, chunk in enumerate(chunks, 1):
            header = f"[Source {i}: {chunk.source}"
            if chunk.page:
                header += f", p.{chunk.page}"
            if chunk.heading:
                header += f" — {chunk.heading}"
            header += f" (relevance: {chunk.score:.2f})]"

            parts.append(f"{header}\n{chunk.text}")

        return "\n\n---\n\n".join(parts)

    def build_calibration_query(
        self,
        parameter: str,
        finding_id: str,
        context_name: str,
        cwe: str,
        vulnerability_type: str,
    ) -> str:
        """Build a targeted retrieval query for a specific parameter.

        Generates a natural-language query optimised for retrieving
        relevant threat intelligence for a specific (finding, context,
        parameter) triple.

        Args:
            parameter: One of 'reachability', 'detectability', 'exploit_maturity'.
            finding_id: Finding identifier (e.g., 'F1', 'F2').
            context_name: Deployment context (e.g., 'CI Build-Only', 'Prod K8s Multi-Tenant').
            cwe: CWE identifier (e.g., 'CWE-78').
            vulnerability_type: Human-readable vulnerability type (e.g., 'config injection to RCE').

        Returns:
            Optimised query string for retrieval.
        """
        query_templates = {
            "reachability": (
                f"What percentage or frequency of real-world attacks involve "
                f"{vulnerability_type} ({cwe}) as an initial access vector "
                f"in {context_name} environments? "
                f"Include supply chain attack statistics, attack vector frequency "
                f"distributions, and breach initial access methods."
            ),
            "detectability": (
                f"What is the median time-to-detection or dwell time for "
                f"{vulnerability_type} ({cwe}) attacks in {context_name} environments? "
                f"Include detection rates, monitoring effectiveness, "
                f"and security operations statistics."
            ),
            "exploit_maturity": (
                f"What is the exploitation timeline and maturity for "
                f"{vulnerability_type} ({cwe})? "
                f"Include statistics on time from disclosure to exploitation, "
                f"availability of exploit tools, and EPSS-related data."
            ),
        }

        query = query_templates.get(parameter)
        if query is None:
            msg = f"Unknown parameter: {parameter}. Expected one of {list(query_templates)}"
            raise ValueError(msg)

        return query
