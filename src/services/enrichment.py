"""Enrichment service for vulnerability data."""

from typing import Any

import polars as pl

from src.data.transformers.enricher import EnrichmentTransformer
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class EnrichmentService:
    """Orchestrates multi-source enrichment of vulnerability findings.

    Combines CVSS-BT, EPSS, KEV, and CWE data into scan results.
    """

    @staticmethod
    def enrich(
        scan_df: pl.DataFrame,
        cvss_bt_df: pl.DataFrame,
        epss_df: pl.DataFrame,
        kev_df: pl.DataFrame | None = None,
        cwe_data: dict[str, dict[str, Any]] | None = None,
    ) -> pl.DataFrame:
        """Apply all available enrichment sources.

        Args:
            scan_df: Raw scan results.
            cvss_bt_df: CVSS-BT reference data.
            epss_df: EPSS scores.
            kev_df: KEV catalog.
            cwe_data: CWE metadata mapping.

        Returns:
            Fully enriched DataFrame.
        """
        logger.info("Starting enrichment for %d findings", len(scan_df))

        enriched, matched = EnrichmentTransformer.enrich_cvss_bt(scan_df, cvss_bt_df)
        logger.info("CVSS-BT matched %d/%d", matched, len(scan_df))

        enriched = EnrichmentTransformer.enrich_epss(enriched, epss_df)

        if kev_df is not None:
            enriched = EnrichmentTransformer.enrich_kev(enriched, kev_df)

        if cwe_data and "cwe_id" in enriched.columns:
            enriched = EnrichmentTransformer.enrich_cwe(enriched, cwe_data)

        enriched = EnrichmentTransformer.standardize_types(enriched)

        logger.info("Enrichment complete: %d columns", len(enriched.columns))
        return enriched
