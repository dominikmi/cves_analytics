"""RAG system configuration.

Centralises all configuration for the threat parameter calibration
RAG pipeline: paths, model names, API endpoints, chunking parameters.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from src.utils.config import CONFIG_YAML


class RAGConfig(BaseSettings):
    """Configuration for the threat calibration RAG system.

    Reads from environment variables prefixed with ``RAG_`` or from
    a ``.env`` file in the project root.

    Attributes:
        documents_dir: Directory containing threat intel PDFs/markdown.
        vector_store_dir: Directory for Qdrant embedded vector storage.
        output_dir: Directory for calibration YAML output.
        llm_base_url: OpenAI-compatible API base URL for generation (LM Studio).
        llm_model: Generation model name as shown in LM Studio.
        llm_temperature: Sampling temperature for generation.
        llm_max_tokens: Maximum tokens for LLM response.
        llm_timeout: HTTP read timeout in seconds for LLM requests.
        llm_retries: Number of retries on timeout before giving up.
        chunk_size: Target chunk size in characters.
        chunk_overlap: Overlap between consecutive chunks in characters.
        top_k: Number of chunks to retrieve per query.
        collection_name: Vector store collection name.
        embedding_model: FastEmbed model name for vectorisation.
    """

    model_config = SettingsConfigDict(
        env_prefix="RAG_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # RAG_* env vars and .env override config.yaml; defaults last.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls, yaml_file=CONFIG_YAML),
            file_secret_settings,
        )

    # Paths
    documents_dir: Path = Field(
        default=Path("data/threat_intel"),
        description="Directory containing threat intel PDFs and markdown files",
    )
    vector_store_dir: Path = Field(
        default=Path("data/qdrant_db"),
        description="Qdrant embedded vector store directory",
    )
    output_dir: Path = Field(
        default=Path("output/calibration"),
        description="Directory for calibration YAML output",
    )

    # LLM (LM Studio OpenAI-compatible API)
    llm_base_url: str = Field(
        default="http://localhost:1234/v1",
        description="OpenAI-compatible API base URL for generation (LM Studio)",
    )
    llm_model: str = Field(
        default="local-model",
        description="Model name to pass to the LLM API",
    )
    llm_temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=2.0,
        description="Low temperature for factual extraction",
    )
    llm_max_tokens: int = Field(
        default=2048,
        ge=256,
        le=8192,
        description="Maximum tokens for LLM response",
    )
    llm_timeout: int = Field(
        default=300,
        ge=30,
        le=900,
        description="HTTP read timeout in seconds for LLM requests",
    )
    llm_retries: int = Field(
        default=1,
        ge=0,
        le=3,
        description="Number of retries on timeout before giving up",
    )

    # Chunking
    chunk_size: int = Field(
        default=1500,
        ge=200,
        le=10000,
        description="Target chunk size in characters",
    )
    chunk_overlap: int = Field(
        default=200,
        ge=0,
        le=2000,
        description="Overlap between consecutive chunks",
    )

    # Retrieval
    top_k: int = Field(
        default=8,
        ge=1,
        le=50,
        description="Number of chunks to retrieve per query",
    )
    collection_name: str = Field(
        default="threat_intel",
        description="Vector store collection name",
    )
    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        description="FastEmbed model used to vectorise chunks",
    )

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Logging level for RAG operations",
    )
