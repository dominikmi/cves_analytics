"""Document ingestion pipeline.

Extracts text from PDFs and markdown files, chunks them with
section-aware splitting, and stores in an embedded Qdrant vector
store (embedding is handled by FastEmbed via ONNX Runtime).
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from src.rag.config import RAGConfig

if TYPE_CHECKING:
    from qdrant_client import QdrantClient

logger = logging.getLogger(__name__)


class DocumentChunk:
    """A chunk of text with metadata for vector storage.

    Attributes:
        text: The chunk text content.
        source: Source file path.
        page: Page number (for PDFs) or section index.
        chunk_index: Sequential index within the source document.
        heading: Nearest section heading, if detected.
    """

    __slots__ = ("chunk_index", "heading", "page", "source", "text")

    def __init__(
        self,
        text: str,
        source: str,
        page: int,
        chunk_index: int,
        heading: str = "",
    ) -> None:
        self.text = text
        self.source = source
        self.page = page
        self.chunk_index = chunk_index
        self.heading = heading

    @property
    def doc_id(self) -> str:
        """Deterministic UUID from content hash for deduplication.

        Qdrant point IDs must be integers or UUIDs, so the SHA-256
        digest is formatted as a UUID string.
        """
        content = f"{self.source}:{self.page}:{self.chunk_index}"
        digest = hashlib.sha256(content.encode()).hexdigest()[:32]
        return (
            f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-"
            f"{digest[16:20]}-{digest[20:32]}"
        )

    @property
    def metadata(self) -> dict[str, str | int]:
        """Metadata dict for vector store payload."""
        return {
            "source": self.source,
            "page": self.page,
            "chunk_index": self.chunk_index,
            "heading": self.heading,
        }


class DocumentIngester:
    """Ingests threat intel documents into an embedded Qdrant store.

    Supports PDF (via pymupdf4llm) and markdown files.
    Chunks are section-aware: splits prefer section boundaries
    over arbitrary character counts.

    Args:
        config: RAG configuration instance.
    """

    def __init__(self, config: RAGConfig | None = None) -> None:
        self.config = config or RAGConfig()
        self._client: QdrantClient | None = None

    @property
    def client(self) -> QdrantClient:
        """Lazy-initialise the embedded Qdrant client and collection."""
        if self._client is None:
            try:
                from qdrant_client import QdrantClient, models
            except ImportError as exc:
                msg = "Install the optional RAG dependencies with: uv sync --group rag"
                raise RuntimeError(msg) from exc
            self.config.vector_store_dir.mkdir(parents=True, exist_ok=True)
            client = QdrantClient(path=str(self.config.vector_store_dir))
            if not client.collection_exists(self.config.collection_name):
                client.create_collection(
                    collection_name=self.config.collection_name,
                    vectors_config=models.VectorParams(
                        size=client.get_embedding_size(self.config.embedding_model),
                        distance=models.Distance.COSINE,
                    ),
                )
            self._client = client
            logger.info(
                "Qdrant collection '%s' ready (%d documents)",
                self.config.collection_name,
                self._client.count(self.config.collection_name).count,
            )
        return self._client

    def close(self) -> None:
        """Release the embedded store's file lock."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def ingest_directory(self, directory: Path | None = None) -> int:
        """Ingest all supported files from a directory.

        Args:
            directory: Path to scan. Defaults to config.documents_dir.

        Returns:
            Total number of chunks ingested.
        """
        doc_dir = directory or self.config.documents_dir
        if not doc_dir.exists():
            logger.warning("Documents directory does not exist: %s", doc_dir)
            doc_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Created empty directory: %s", doc_dir)
            return 0

        supported = {".pdf", ".md", ".txt"}
        files = [f for f in doc_dir.iterdir() if f.suffix.lower() in supported]

        if not files:
            logger.warning("No supported files found in %s", doc_dir)
            return 0

        total_chunks = 0
        t_start = time.perf_counter()
        for i, filepath in enumerate(sorted(files), 1):
            size_kb = filepath.stat().st_size / 1024
            logger.info(
                "[%d/%d] Ingesting: %s (%.1f KB)",
                i,
                len(files),
                filepath.name,
                size_kb,
            )
            t_file = time.perf_counter()
            chunks = self._extract_chunks(filepath)
            if chunks:
                self._store_chunks(chunks)
                total_chunks += len(chunks)
                elapsed = time.perf_counter() - t_file
                logger.info(
                    "  → %d chunks from %s (%.1fs)",
                    len(chunks),
                    filepath.name,
                    elapsed,
                )
            else:
                logger.info("  → 0 chunks (empty or failed)")

        total_elapsed = time.perf_counter() - t_start
        logger.info(
            "Ingestion complete: %d total chunks from %d files in %.1fs",
            total_chunks,
            len(files),
            total_elapsed,
        )
        return total_chunks

    def _extract_chunks(self, filepath: Path) -> list[DocumentChunk]:
        """Extract and chunk a single file.

        Args:
            filepath: Path to the document file.

        Returns:
            List of document chunks.
        """
        if filepath.suffix.lower() == ".pdf":
            return self._extract_pdf(filepath)
        return self._extract_text(filepath)

    def _extract_pdf(self, filepath: Path) -> list[DocumentChunk]:
        """Extract chunks from a PDF using pymupdf4llm.

        Args:
            filepath: Path to the PDF file.

        Returns:
            List of document chunks.
        """
        try:
            import pymupdf4llm
        except ImportError:
            logger.error("pymupdf4llm not installed. Run: uv add pymupdf4llm")
            return []

        try:
            md_pages = pymupdf4llm.to_markdown(str(filepath), page_chunks=True)
        except Exception:
            logger.exception("Failed to extract PDF: %s", filepath)
            return []

        chunks: list[DocumentChunk] = []
        for page_data in md_pages:
            page_num = page_data.get("metadata", {}).get("page", 0)
            text = page_data.get("text", "")
            if not text.strip():
                continue
            page_chunks = self._split_text(
                text,
                source=filepath.name,
                page=page_num,
                start_index=len(chunks),
            )
            chunks.extend(page_chunks)
        return chunks

    def _extract_text(self, filepath: Path) -> list[DocumentChunk]:
        """Extract chunks from a text/markdown file.

        Args:
            filepath: Path to the text file.

        Returns:
            List of document chunks.
        """
        try:
            text = filepath.read_text(encoding="utf-8")
        except Exception:
            logger.exception("Failed to read file: %s", filepath)
            return []

        if not text.strip():
            return []

        return self._split_text(text, source=filepath.name, page=0, start_index=0)

    def _split_text(
        self,
        text: str,
        source: str,
        page: int,
        start_index: int,
    ) -> list[DocumentChunk]:
        """Split text into chunks, preferring section boundaries.

        Splits on markdown headings (## or ###) when possible,
        falls back to paragraph boundaries, then character limit.

        Args:
            text: Raw text to split.
            source: Source filename for metadata.
            page: Page number for metadata.
            start_index: Starting chunk index.

        Returns:
            List of document chunks.
        """
        chunk_size = self.config.chunk_size
        overlap = self.config.chunk_overlap

        # Split on section headings first
        sections = self._split_on_headings(text)

        chunks: list[DocumentChunk] = []
        current_heading = ""

        for section_text, heading in sections:
            if heading:
                current_heading = heading

            # If section fits in one chunk, keep it whole
            if len(section_text) <= chunk_size:
                if section_text.strip():
                    chunks.append(
                        DocumentChunk(
                            text=section_text.strip(),
                            source=source,
                            page=page,
                            chunk_index=start_index + len(chunks),
                            heading=current_heading,
                        )
                    )
                continue

            # Split large sections by paragraphs
            paragraphs = section_text.split("\n\n")
            buffer = ""

            for para in paragraphs:
                if len(buffer) + len(para) + 2 > chunk_size and buffer:
                    chunks.append(
                        DocumentChunk(
                            text=buffer.strip(),
                            source=source,
                            page=page,
                            chunk_index=start_index + len(chunks),
                            heading=current_heading,
                        )
                    )
                    # Keep overlap from end of previous chunk
                    buffer = buffer[-overlap:] + "\n\n" + para if overlap else para
                else:
                    buffer = buffer + "\n\n" + para if buffer else para

            if buffer.strip():
                chunks.append(
                    DocumentChunk(
                        text=buffer.strip(),
                        source=source,
                        page=page,
                        chunk_index=start_index + len(chunks),
                        heading=current_heading,
                    )
                )

        return chunks

    @staticmethod
    def _split_on_headings(text: str) -> list[tuple[str, str]]:
        """Split text on markdown headings, preserving heading context.

        Args:
            text: Markdown text.

        Returns:
            List of (section_text, heading) tuples.
        """
        import re

        heading_pattern = re.compile(r"^(#{1,4})\s+(.+)$", re.MULTILINE)
        matches = list(heading_pattern.finditer(text))

        if not matches:
            return [(text, "")]

        sections: list[tuple[str, str]] = []

        # Text before first heading
        if matches[0].start() > 0:
            sections.append((text[: matches[0].start()], ""))

        for i, match in enumerate(matches):
            heading = match.group(2).strip()
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            section_text = text[start:end]
            sections.append((section_text, heading))

        return sections

    def _store_chunks(self, chunks: list[DocumentChunk]) -> None:
        """Embed and store chunks in the Qdrant collection.

        Skips chunks that already exist (by doc_id) for idempotency.

        Args:
            chunks: List of document chunks to store.
        """
        from qdrant_client import models

        # Filter out already-ingested chunks
        ids = [c.doc_id for c in chunks]
        existing: set[str] = set()
        try:
            points = self.client.retrieve(
                collection_name=self.config.collection_name,
                ids=ids,
                with_payload=False,
                with_vector=False,
            )
            existing = {str(point.id) for point in points}
        except Exception as exc:
            logger.debug("Existing chunk lookup failed; ingesting all chunks: %s", exc)

        new_chunks = [c for c in chunks if c.doc_id not in existing]
        if not new_chunks:
            logger.info("  ↳ All %d chunks already ingested, skipping", len(chunks))
            return

        if existing:
            logger.info(
                "  ↳ %d new chunks (%d already exist)",
                len(new_chunks),
                len(existing),
            )

        logger.info("  ↳ Embedding + storing %d chunks...", len(new_chunks))
        t_store = time.perf_counter()
        self.client.upload_collection(
            collection_name=self.config.collection_name,
            vectors=[
                models.Document(text=c.text, model=self.config.embedding_model)
                for c in new_chunks
            ],
            payload=[{**c.metadata, "text": c.text} for c in new_chunks],
            ids=[c.doc_id for c in new_chunks],
        )
        logger.info("  ↳ Done in %.1fs", time.perf_counter() - t_store)
        logger.info("  ↳ Stored %d chunks in Qdrant", len(new_chunks))
