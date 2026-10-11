"""Retrieval module for threat parameter calibration.

Handles embedding queries, retrieving relevant chunks from ChromaDB,
and formatting context for the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.rag.config import RAGConfig

if TYPE_CHECKING:
    from chromadb.api.models.Collection import Collection

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RetrievedChunk:
    """A retrieved chunk with relevance score.

    Attributes:
        text: Chunk text content.
        source: Source document filename.
        page: Page number in source document.
        heading: Nearest section heading.
        score: Cosine similarity score (0-1, higher is better).
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
        self._collection: Collection | None = None

    @property
    def collection(self) -> Collection:
        """Lazy-initialise the ChromaDB collection (read-only)."""
        if self._collection is None:
            if not self.config.chroma_persist_dir.exists():
                msg = (
                    f"ChromaDB directory not found: {self.config.chroma_persist_dir}. "
                    "Run ingestion first."
                )
                raise FileNotFoundError(msg)
            try:
                import chromadb
            except ImportError as exc:
                msg = "Install the optional RAG dependencies with: uv sync --group rag"
                raise RuntimeError(msg) from exc
            client = chromadb.PersistentClient(
                path=str(self.config.chroma_persist_dir),
            )
            self._collection = client.get_collection(
                name=self.config.collection_name,
            )
            logger.info(
                "Connected to collection '%s' (%d documents)",
                self.config.collection_name,
                self._collection.count(),
            )
        return self._collection

    def retrieve(self, query: str, top_k: int | None = None) -> list[RetrievedChunk]:
        """Retrieve the most relevant chunks for a query.

        Args:
            query: Natural language query string.
            top_k: Number of results. Defaults to config.top_k.

        Returns:
            List of retrieved chunks sorted by relevance (best first).
        """
        k = top_k or self.config.top_k

        results = self.collection.query(
            query_texts=[query],
            n_results=k,
            include=["documents", "metadatas", "distances"],
        )

        chunks: list[RetrievedChunk] = []
        if not results or not results["documents"] or not results["documents"][0]:
            logger.warning("No results for query: %s", query[:80])
            return chunks

        documents = results["documents"][0]
        metadatas = (
            results["metadatas"][0] if results["metadatas"] else [{}] * len(documents)
        )
        distances = (
            results["distances"][0] if results["distances"] else [1.0] * len(documents)
        )

        for doc, meta, dist in zip(documents, metadatas, distances, strict=False):
            # ChromaDB cosine distance → similarity (1 - distance)
            similarity = max(0.0, 1.0 - dist)
            source = meta.get("source")
            page = meta.get("page")
            heading = meta.get("heading")
            chunks.append(
                RetrievedChunk(
                    text=doc,
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
