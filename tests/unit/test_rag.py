"""Focused tests for the optional threat-calibration RAG module."""

import json
from pathlib import Path

import pytest

from src.rag.calibrator import (
    CONTEXTS,
    FINDINGS,
    ParameterEstimate,
    ThreatCalibrator,
    _build_user_prompt,
    _safe_float,
)
from src.rag.cli import cmd_calibrate
from src.rag.config import RAGConfig
from src.rag.ingest import DocumentChunk, DocumentIngester
from src.rag.retriever import RetrievedChunk, ThreatIntelRetriever


def _config(tmp_path: Path) -> RAGConfig:
    return RAGConfig(
        documents_dir=tmp_path / "documents",
        vector_store_dir=tmp_path / "qdrant",
        output_dir=tmp_path / "output",
        chunk_size=200,
        chunk_overlap=20,
    )


def test_config_defaults_and_document_chunk_metadata(tmp_path: Path) -> None:
    """RAG settings and chunk metadata are deterministic."""
    config = _config(tmp_path)
    chunk = DocumentChunk(
        text="Threat text",
        source="report.md",
        page=3,
        chunk_index=1,
        heading="Initial Access",
    )

    assert config.documents_dir == tmp_path / "documents"
    assert config.top_k == 8
    assert chunk.doc_id == chunk.doc_id
    assert chunk.metadata == {
        "source": "report.md",
        "page": 3,
        "chunk_index": 1,
        "heading": "Initial Access",
    }


def test_ingester_splits_markdown_by_headings_and_size(tmp_path: Path) -> None:
    """Markdown chunking preserves section context without optional deps."""
    ingester = DocumentIngester(_config(tmp_path))
    text = (
        "# Report\n"
        "Intro paragraph.\n\n"
        "## Reachability\n"
        + ("Reachability evidence. " * 12)
        + "\n\n### Exploit maturity\n"
        + ("Exploit tooling evidence. " * 12)
    )

    sections = DocumentIngester._split_on_headings(text)
    chunks = ingester._split_text(
        text,
        source="report.md",
        page=0,
        start_index=0,
    )

    assert sections[0][1] == "Report"
    assert [section[1] for section in sections] == [
        "Report",
        "Reachability",
        "Exploit maturity",
    ]
    assert len(chunks) > 1
    assert all(chunk.source == "report.md" for chunk in chunks)
    assert {chunk.heading for chunk in chunks} == {
        "Report",
        "Reachability",
        "Exploit maturity",
    }


def test_retriever_query_and_context_formatting(tmp_path: Path) -> None:
    """Retrieval helpers produce cited context without the vector store."""
    retriever = ThreatIntelRetriever(_config(tmp_path))
    chunk = RetrievedChunk(
        text="23% of incidents involved the vector.",
        source="dbir.pdf",
        page=12,
        heading="Initial access",
        score=0.82,
    )

    query = retriever.build_calibration_query(
        parameter="reachability",
        finding_id="F2",
        context_name="CI Build-Only",
        cwe="CWE-78",
        vulnerability_type="configuration injection to RCE",
    )
    context = retriever.format_context([chunk])

    assert "F2" not in query
    assert "CWE-78" in query
    assert "CI Build-Only" in query
    assert "Source 1: dbir.pdf, p.12" in context
    assert "23% of incidents" in context
    with pytest.raises(ValueError, match="Unknown parameter"):
        retriever.build_calibration_query(
            parameter="impact",
            finding_id="F2",
            context_name="CI Build-Only",
            cwe="CWE-78",
            vulnerability_type="configuration injection to RCE",
        )


def test_safe_float_accepts_llm_numeric_variants() -> None:
    """The calibrator extracts numeric estimates from common LLM strings."""
    assert _safe_float(0.4) == 0.4
    assert _safe_float("approximately 0.35") == 0.35
    assert _safe_float("0.05-0.15") == 0.05
    with pytest.raises(ValueError, match="Cannot extract float"):
        _safe_float("not numeric")


def test_calibrator_parses_markdown_json_and_clamps_ranges(tmp_path: Path) -> None:
    """LLM output is parsed into a bounded, cited parameter estimate."""
    calibrator = ThreatCalibrator(_config(tmp_path))
    estimate = calibrator._parse_response(
        "```json\n"
        + json.dumps(
            {
                "tri_min": "-0.1",
                "tri_mode": "0.40",
                "tri_max": "1.2",
                "sources": ["DBIR"],
                "reasoning": "Observed frequency supports the mode.",
                "confidence": "moderate",
                "raw_statistics": ["23% of incidents"],
            }
        )
        + "\n```",
        "F2",
        "B",
        "reachability",
    )

    assert estimate.tri_min == 0.0
    assert estimate.tri_mode == 0.4
    assert estimate.tri_max == 1.0
    assert estimate.expected_value == pytest.approx((0.0 + 0.4 + 1.0) / 3.0)
    assert estimate.sources == ["DBIR"]
    assert estimate.confidence == "moderate"


def test_calibrator_uses_exploit_maturity_multiplier_bounds(tmp_path: Path) -> None:
    """Exploit maturity keeps its documented 0.5-1.5 multiplier range."""
    calibrator = ThreatCalibrator(_config(tmp_path))
    estimate = calibrator._parse_response(
        json.dumps({"tri_min": 0.1, "tri_mode": 1.0, "tri_max": 1.8}),
        "F2",
        "B",
        "exploit_maturity",
    )

    assert (estimate.tri_min, estimate.tri_mode, estimate.tri_max) == (0.5, 1.0, 1.5)


def test_calibrator_parse_failure_is_explicit(tmp_path: Path) -> None:
    """Malformed LLM output produces a failed estimate rather than an exception."""
    calibrator = ThreatCalibrator(_config(tmp_path))
    estimate = calibrator._parse_response(
        "not JSON",
        "F1",
        "A",
        "detectability",
    )

    assert estimate.confidence == "failed"
    assert "PARSE FAILURE" in estimate.reasoning


def test_calibrator_writes_and_loads_round_trip_provenance(tmp_path: Path) -> None:
    """Provenance output remains consumable by a retry run."""
    calibrator = ThreatCalibrator(_config(tmp_path))
    estimate = ParameterEstimate(
        finding_id="F2",
        context="B",
        parameter="exploit_maturity",
        tri_min=0.7,
        tri_mode=1.0,
        tri_max=1.3,
        expected_value=1.0,
        sources=["Source"],
        reasoning="Observed exploit availability.",
        confidence="high",
        raw_statistics=["PoC available"],
    )

    calibrator._write_output([estimate])
    loaded = calibrator._load_existing()

    loaded_estimate = loaded[("F2", "B", "exploit_maturity")]
    assert (
        loaded_estimate.tri_min,
        loaded_estimate.tri_mode,
        loaded_estimate.tri_max,
    ) == (
        0.7,
        1.0,
        1.3,
    )
    assert (tmp_path / "output" / "parameter_summary.yaml").exists()


def test_build_user_prompt_contains_finding_context_and_parameter() -> None:
    """Prompt construction carries the requested calibration dimensions."""
    prompt = _build_user_prompt(
        "detectability",
        FINDINGS[1],
        CONTEXTS[1],
        "Retrieved passage.",
    )

    assert "DETECTABILITY" in prompt
    assert "F2 — CWE-78" in prompt
    assert "B — Shared CI/CD Pipeline (Build-Only)" in prompt
    assert "Retrieved passage." in prompt


def test_cmd_calibrate_rejects_unknown_parameter(tmp_path: Path) -> None:
    """The RAG CLI validates target dimensions before touching the store."""
    args = type(
        "Args",
        (),
        {
            "finding": None,
            "context": None,
            "parameter": "invalid",
            "retry_failed": False,
        },
    )()

    assert cmd_calibrate(args, _config(tmp_path)) == 1
