"""CLI entry point for the threat calibration RAG system.

Usage:
    # Ingest threat intel documents
    python -m src.rag.cli ingest [--dir data/threat_intel]

    # Run calibration (requires LM Studio running)
    python -m src.rag.cli calibrate [--finding F2] [--context E] [--parameter reachability]

    # Re-run only failed/missing estimates (merges into existing results)
    python -m src.rag.cli calibrate --retry-failed

    # Check system status
    python -m src.rag.cli status
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

from src.rag.calibrator import CONTEXTS, FINDINGS, PARAMETERS, ThreatCalibrator
from src.rag.config import RAGConfig
from src.rag.ingest import DocumentIngester
from src.rag.retriever import ThreatIntelRetriever

logger = logging.getLogger(__name__)


def _setup_logging(level: str) -> None:
    """Configure logging for the CLI.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
    """
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_ingest(args: argparse.Namespace, config: RAGConfig) -> int:
    """Ingest threat intelligence documents into ChromaDB.

    Args:
        args: Parsed CLI arguments.
        config: RAG configuration.

    Returns:
        Exit code (0 = success).
    """
    doc_dir = Path(args.dir) if args.dir else config.documents_dir

    ingester = DocumentIngester(config)
    total = ingester.ingest_directory(doc_dir)

    if total == 0:
        print(f"\nNo documents found in {doc_dir}")
        print("Place PDF or markdown threat intel reports there and re-run.")
        print("\nRecommended sources:")
        print(
            "  - Verizon DBIR: https://www.verizon.com/business/resources/reports/dbir/"
        )
        print("  - Mandiant M-Trends: https://www.mandiant.com/m-trends")
        print(
            "  - Sonatype SOTSC: https://www.sonatype.com/state-of-the-software-supply-chain"
        )
        print(
            "  - ENISA Threat Landscape: https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends"
        )
        return 1

    print(f"\nIngested {total} chunks from {doc_dir}")
    print(f"ChromaDB stored at: {config.chroma_persist_dir}")
    return 0


def cmd_calibrate(args: argparse.Namespace, config: RAGConfig) -> int:
    """Run the calibration pipeline.

    Args:
        args: Parsed CLI arguments.
        config: RAG configuration.

    Returns:
        Exit code (0 = success).
    """
    # Filter targets if specified
    findings = FINDINGS
    contexts = CONTEXTS
    parameters = PARAMETERS

    if args.finding:
        findings = [f for f in findings if f["id"] == args.finding.upper()]
        if not findings:
            print(f"Unknown finding: {args.finding}. Valid: F1-F5")
            return 1

    if args.context:
        contexts = [c for c in contexts if c["short"] == args.context.upper()]
        if not contexts:
            print(f"Unknown context: {args.context}. Valid: A-E")
            return 1

    if args.parameter:
        if args.parameter not in PARAMETERS:
            print(f"Unknown parameter: {args.parameter}. Valid: {PARAMETERS}")
            return 1
        parameters = [args.parameter]

    calibrator = ThreatCalibrator(config)

    try:
        estimates = calibrator.calibrate_all(
            findings,
            contexts,
            parameters,
            retry_failed=getattr(args, "retry_failed", False),
        )
    except FileNotFoundError as exc:
        print(f"\nError: {exc}")
        print("Run 'python -m src.rag.cli ingest' first.")
        return 1
    except ConnectionError as exc:
        print(f"\nError: {exc}")
        print("Start LM Studio and load a model.")
        return 1

    # Print summary
    succeeded = [e for e in estimates if e.confidence != "failed"]
    failed = len(estimates) - len(succeeded)

    print("\nCalibration complete:")
    print(f"  Estimates produced: {len(succeeded)}")
    if failed:
        print(f"  Failed: {failed}")
    print(f"  Output: {config.output_dir}/parameter_provenance.yaml")
    print(f"  Summary: {config.output_dir}/parameter_summary.yaml")
    return 0


def cmd_status(args: argparse.Namespace, config: RAGConfig) -> int:
    """Check system status: ChromaDB, LLM, embeddings.

    Args:
        args: Parsed CLI arguments.
        config: RAG configuration.

    Returns:
        Exit code (0 = all healthy).
    """
    issues = 0

    # Check documents directory
    doc_dir = config.documents_dir
    if doc_dir.exists():
        supported = {".pdf", ".md", ".txt"}
        files = [f for f in doc_dir.iterdir() if f.suffix.lower() in supported]
        print(f"[OK] Documents dir: {doc_dir} ({len(files)} files)")
    else:
        print(f"[!!] Documents dir missing: {doc_dir}")
        issues += 1

    # Check ChromaDB
    if config.chroma_persist_dir.exists():
        try:
            retriever = ThreatIntelRetriever(config)
            count = retriever.collection.count()
            print(f"[OK] ChromaDB: {count} chunks in '{config.collection_name}'")
        except Exception as exc:
            print(f"[!!] ChromaDB error: {exc}")
            issues += 1
    else:
        print("[!!] ChromaDB not initialised (run ingest first)")
        issues += 1

    # Check LLM endpoint
    import requests

    try:
        resp = requests.get(f"{config.llm_base_url}/models", timeout=5)
        if resp.ok:
            models = resp.json().get("data", [])
            model_names = [m.get("id", "?") for m in models]
            print(
                f"[OK] LLM API: {config.llm_base_url} (models: {', '.join(model_names[:3])})"
            )
        else:
            print(f"[!!] LLM API responded with {resp.status_code}")
            issues += 1
    except requests.ConnectionError:
        print(f"[!!] LLM API unreachable at {config.llm_base_url}")
        issues += 1

    # Embeddings handled by ChromaDB's built-in model (no external API needed)
    print("[OK] Embeddings: ChromaDB built-in (no external API required)")

    if issues:
        print(f"\n{issues} issue(s) found.")
    else:
        print("\nAll systems ready.")
    return 1 if issues else 0


def main() -> int:
    """CLI entry point.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        prog="rag-calibrate",
        description="Threat parameter calibration RAG system",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level",
    )
    parser.add_argument(
        "--llm-url",
        default=None,
        help="Override LLM base URL (default: http://localhost:1234/v1)",
    )
    parser.add_argument(
        "--llm-model",
        default=None,
        help="Override LLM model name",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Ingest command
    ingest_parser = subparsers.add_parser(
        "ingest", help="Ingest threat intel documents"
    )
    ingest_parser.add_argument(
        "--dir",
        default=None,
        help="Directory containing threat intel PDFs/markdown",
    )

    # Calibrate command
    cal_parser = subparsers.add_parser("calibrate", help="Run parameter calibration")
    cal_parser.add_argument("--finding", default=None, help="Single finding (F1-F5)")
    cal_parser.add_argument("--context", default=None, help="Single context (A-E)")
    cal_parser.add_argument("--parameter", default=None, help="Single parameter")
    cal_parser.add_argument(
        "--retry-failed",
        action="store_true",
        default=False,
        help="Re-run only failed/missing estimates, merging into existing results",
    )

    # Status command
    subparsers.add_parser("status", help="Check system status")

    args = parser.parse_args()

    _setup_logging(args.log_level)

    # Build config with CLI overrides
    overrides: dict[str, Any] = {}
    if args.llm_url:
        overrides["llm_base_url"] = args.llm_url
    if args.llm_model:
        overrides["llm_model"] = args.llm_model

    config = RAGConfig(**overrides) if overrides else RAGConfig()

    commands = {
        "ingest": cmd_ingest,
        "calibrate": cmd_calibrate,
        "status": cmd_status,
    }

    return commands[args.command](args, config)


if __name__ == "__main__":
    sys.exit(main())
