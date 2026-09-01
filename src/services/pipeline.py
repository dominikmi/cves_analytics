"""Vulnerability assessment pipeline orchestrator.

Coordinates scanning, enrichment, Bayesian risk scoring, and attack
path analysis into a single reproducible workflow.
"""

from collections.abc import Callable
from dataclasses import dataclass

import polars as pl

from src.core.risk.bayesian_assessor import assess_vulnerabilities_bayesian
from src.data.loaders.cvss_bt import CVSSBTLoader
from src.data.loaders.cwe import CWELoader
from src.data.loaders.epss import EPSSLoader
from src.data.loaders.kev import KEVLoader
from src.data.stores.duckdb_store import DuckDBStore
from src.data.transformers.enricher import EnrichmentTransformer
from src.db.sqlite_models import Profile
from src.services.analysis import AttackPathService
from src.services.scanner import DockerScanner
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class PipelineResult:
    """Result of a pipeline execution."""

    findings_df: pl.DataFrame
    severity_counts: dict[str, int]
    avg_bayesian_risk: float | None


class VulnerabilityAssessmentPipeline:
    """Orchestrates the full vulnerability assessment pipeline.

    Steps:
    1. Load reference datasets (CVSS-BT, EPSS, KEV, CWE)
    2. Scan Docker images with Grype/Trivy
    3. Enrich scan results with reference data
    4. Compute Bayesian risk scores
    5. Analyze attack paths through kill chain
    6. Store findings in DuckDB
    """

    def __init__(
        self,
        profile: Profile,
        duckdb_store: DuckDBStore,
        data_dir: str = "./data",
        scanner_tool: str = "grype",
    ) -> None:
        self.profile = profile
        self.duckdb_store = duckdb_store
        self.data_dir = data_dir
        self.scanner = DockerScanner(tool=scanner_tool)

    def run(
        self,
        run_id: int | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> PipelineResult:
        """Execute the full pipeline.

        Args:
            run_id: Optional ScanRun id stamped onto stored findings so rows
                from repeated runs stay attributable in the DuckDB store.
            on_progress: Optional callback invoked with a human-readable step
                description as each stage completes (used for SSE streaming).
        """

        def _report(step: str) -> None:
            if on_progress is not None:
                on_progress(step)

        logger.info("Starting pipeline for profile %s", self.profile.name)

        # Step 1: Load reference datasets
        _report("Loading reference datasets (CVSS-BT, EPSS, KEV, CWE)")
        cvss_bt_df = CVSSBTLoader(self.data_dir).load()
        epss_df = EPSSLoader(self.data_dir).load()
        kev_df = KEVLoader(self.data_dir).load()
        cwe_loader = CWELoader(self.data_dir)

        # Step 2: Scan Docker images
        _report(f"Scanning {len(self.profile.image_inventory)} image(s)")
        scan_df = self.scanner.scan_batch(self.profile.image_inventory)
        logger.info("Scan complete: %d raw findings", len(scan_df))
        _report(f"Scan complete: {len(scan_df)} raw findings")

        # Step 3: Enrich with reference data
        _report("Enriching findings with reference data")
        enriched, matched = EnrichmentTransformer.enrich_cvss_bt(scan_df, cvss_bt_df)
        logger.info("CVSS-BT matched %d/%d findings", matched, len(scan_df))

        enriched = EnrichmentTransformer.enrich_epss(enriched, epss_df)

        if kev_df is not None:
            enriched = EnrichmentTransformer.enrich_kev(enriched, kev_df)

        # CWE enrichment
        if "cwe_id" in enriched.columns:
            cwe_ids = enriched.select("cwe_id").to_series().to_list()
            unique_ids = list(set(str(cid) for cid in cwe_ids if cid))
            import asyncio

            cwe_data = asyncio.run(cwe_loader.batch_get(unique_ids))
            enriched = EnrichmentTransformer.enrich_cwe(enriched, cwe_data)

        enriched = EnrichmentTransformer.standardize_types(enriched)
        logger.info("Enrichment complete: %d columns", len(enriched.columns))

        # Step 4: Bayesian risk assessment
        _report("Computing Bayesian risk scores")
        enriched = self._compute_bayesian_risk(enriched)

        # Step 5: Attack path analysis
        _report("Analyzing attack paths (kill chain)")
        enriched = self._analyze_attack_paths(enriched)

        # Step 6: Store findings (always stamp run_id so the schema is stable
        # across append-mode writes and rows stay attributable per scan run)
        _report("Storing findings")
        findings_df = enriched.with_columns(
            pl.lit(run_id or 0).cast(pl.Int64).alias("run_id")
        )
        self.duckdb_store.write_table("findings", findings_df, mode="append")

        # Compute summary
        severity_counts = self._count_severities(enriched)
        avg_risk = self._avg_bayesian_risk(enriched)

        logger.info(
            "Pipeline complete: %d findings, avg_risk=%.4f",
            len(enriched),
            avg_risk or 0,
        )

        return PipelineResult(
            findings_df=findings_df,
            severity_counts=severity_counts,
            avg_bayesian_risk=avg_risk,
        )

    def _compute_bayesian_risk(self, df: pl.DataFrame) -> pl.DataFrame:
        """Compute Bayesian risk scores for each finding."""
        if df.is_empty():
            return df

        if "cvss_base_score" not in df.columns or "epss" not in df.columns:
            logger.warning("Missing cvss_base_score or epss, skipping Bayesian risk")
            return df

        # Map column names to assess_vulnerabilities_bayesian expectations
        df = df.rename({"cvss_base_score": "cvss_score"})
        if "epss" in df.columns:
            df = df.rename({"epss": "epss_score"})

        # Add cvss_vector if available
        if "cvss_base_vector" in df.columns and "cvss_vector" not in df.columns:
            df = df.with_columns(pl.col("cvss_base_vector").alias("cvss_vector"))

        df = assess_vulnerabilities_bayesian(df)
        return df

    def _analyze_attack_paths(self, df: pl.DataFrame) -> pl.DataFrame:
        """Analyze attack paths through kill chain stages."""
        if df.is_empty():
            return df

        # Add kill_chain_phase from CVSS vector if available
        if "kill_chain_phase" not in df.columns and "cvss_vector" in df.columns:
            df = df.with_columns(
                pl.col("cvss_vector")
                .map_elements(self._extract_kill_chain_phase, return_dtype=pl.Utf8)
                .alias("kill_chain_phase")
            )

        return AttackPathService.analyze(df)

    @staticmethod
    def _extract_kill_chain_phase(cvss_vector: str) -> str:
        """Extract the dominant kill chain phase from a CVSS vector."""
        if not cvss_vector or not isinstance(cvss_vector, str):
            return "unknown"
        # AV:N (network) → initial_access, AV:L (local) → execution/lateral
        if "AV:N" in cvss_vector:
            return "initial_access"
        elif "AV:A" in cvss_vector:
            return "lateral_movement"
        elif "AV:L" in cvss_vector:
            return "execution"
        return "objective"

    def _count_severities(self, df: pl.DataFrame) -> dict[str, int]:
        """Count findings by severity level."""
        if df.is_empty() or "severity" not in df.columns:
            return {}
        counts: dict[str, int] = {}
        for row in (
            df.group_by("severity").agg(pl.len().alias("count")).iter_rows(named=True)
        ):
            counts[row["severity"]] = int(row["count"])
        return counts

    def _avg_bayesian_risk(self, df: pl.DataFrame) -> float | None:
        """Compute average Bayesian risk score."""
        if df.is_empty() or "posterior_probability" not in df.columns:
            return None
        val = df.select(pl.col("posterior_probability").mean()).item()
        return float(val) if val is not None else None
