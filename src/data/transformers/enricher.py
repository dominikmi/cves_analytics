"""Data transformers for vulnerability enrichment pipelines."""

from typing import Any

import polars as pl

from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class EnrichmentTransformer:
    """Applies enrichment joins to vulnerability DataFrames.

    Provides methods to left-join reference datasets (CVSS-BT, EPSS, KEV,
    CWE) into a scan results DataFrame.
    """

    @staticmethod
    def enrich_cvss_bt(
        scan_df: pl.DataFrame,
        cvss_bt_df: pl.DataFrame,
        cve_col: str = "cve_id",
    ) -> tuple[pl.DataFrame, int]:
        """Left-join CVSS-BT data into scan results.

        Args:
            scan_df: Vulnerability scan DataFrame.
            cvss_bt_df: CVSS-BT reference DataFrame.
            cve_col: CVE ID column name in scan_df.

        Returns:
            Tuple of (enriched DataFrame, number of matched rows).
        """
        if scan_df.is_empty() or cvss_bt_df.is_empty():
            return scan_df, 0

        merge_cols = [
            "cve_id",
            "cvss_bt_score",
            "cvss_bt_severity",
            "cvss_bt_vector",
            "cvss_base_score",
            "cvss_base_severity",
            "cvss_base_vector",
            "epss",
            "cwe_id",
            "is_kev",
            "is_cisa_kev",
            "is_vulncheck_kev",
            "has_public_exploit",
            "has_exploitdb",
            "has_metasploit",
            "has_nuclei",
            "has_poc_github",
        ]
        available = [c for c in merge_cols if c in cvss_bt_df.columns]
        subset = cvss_bt_df.select(available).unique(subset=["cve_id"])

        enriched = scan_df.join(
            subset,
            left_on=cve_col,
            right_on="cve_id",
            how="left",
            suffix="_bt",
        )

        matched = enriched.select(pl.col("cvss_bt_score").is_not_null().sum()).item()
        logger.info("CVSS-BT enriched %d/%d rows", matched, len(scan_df))
        return enriched, matched

    @staticmethod
    def enrich_epss(
        scan_df: pl.DataFrame,
        epss_df: pl.DataFrame,
        cve_col: str = "cve_id",
    ) -> pl.DataFrame:
        """Left-join EPSS scores into scan results.

        Args:
            scan_df: Vulnerability scan DataFrame.
            epss_df: EPSS DataFrame with 'cve' and 'epss' columns.
            cve_col: CVE ID column name in scan_df.

        Returns:
            Enriched DataFrame.
        """
        if scan_df.is_empty() or epss_df.is_empty():
            return scan_df

        epss_renamed = (
            epss_df.rename({"cve": "cve_id"}) if "cve" in epss_df.columns else epss_df
        )
        return scan_df.join(
            epss_renamed.select("cve_id", "epss").unique(subset=["cve_id"]),
            left_on=cve_col,
            right_on="cve_id",
            how="left",
        )

    @staticmethod
    def enrich_kev(
        scan_df: pl.DataFrame,
        kev_df: pl.DataFrame | None,
        cve_col: str = "cve_id",
        kev_cve_col: str | None = None,
    ) -> pl.DataFrame:
        """Left-join KEV catalog into scan results.

        Args:
            scan_df: Vulnerability scan DataFrame.
            kev_df: KEV catalog DataFrame.
            cve_col: CVE ID column in scan_df.
            kev_cve_col: CVE ID column in kev_df (auto-detected if None).

        Returns:
            Enriched DataFrame with 'is_kev' boolean column.
        """
        if kev_df is None or scan_df.is_empty():
            return scan_df

        if kev_cve_col is None:
            kev_cve_col = "cveID" if "cveID" in kev_df.columns else "CISA/VN Number"

        kev_ids = kev_df.select(kev_cve_col).to_series().to_list()
        return scan_df.with_columns(
            pl.col(cve_col).is_in(kev_ids).alias("is_kev_from_catalog")
        )

    @staticmethod
    def enrich_cwe(
        scan_df: pl.DataFrame,
        cwe_data: dict[str, dict[str, Any]],
        cwe_col: str = "cwe_id",
    ) -> pl.DataFrame:
        """Enrich scan results with CWE metadata.

        Args:
            scan_df: Vulnerability scan DataFrame.
            cwe_data: Mapping from CWE ID to metadata dict.
            cwe_col: CWE ID column in scan_df.

        Returns:
            Enriched DataFrame with cwe_name, cwe_desc columns.
        """
        if scan_df.is_empty() or not cwe_data:
            return scan_df

        cwe_ids = scan_df.select(cwe_col).to_series().to_list()
        rows = []
        for cid in cwe_ids:
            meta = cwe_data.get(str(cid), {})
            rows.append(
                {
                    "cwe_id": str(cid),
                    "cwe_name": meta.get("cwe_name", "not_found"),
                    "cwe_desc": meta.get("cwe_desc", "not_found"),
                    "cwe_cc_scope": meta.get("cwe_cc_scope", "not_found"),
                    "cwe_cc_impact": meta.get("cwe_cc_impact", "not_found"),
                }
            )

        cwe_df = pl.DataFrame(rows)
        scan_df = scan_df.with_columns(pl.col(cwe_col).cast(pl.Utf8))
        return scan_df.join(
            cwe_df,
            on=cwe_col,
            how="left",
            suffix="_cwe",
        )

    @staticmethod
    def standardize_types(df: pl.DataFrame) -> pl.DataFrame:
        """Cast common columns to expected types.

        Ensures numeric columns are floats and boolean columns are booleans.

        Args:
            df: Input DataFrame.

        Returns:
            DataFrame with standardized types.
        """
        casts = []
        float_cols = ["cvss_base_score", "cvss_bt_score", "epss"]
        bool_cols = ["is_kev", "is_cisa_kev", "has_public_exploit"]

        for col in float_cols:
            if col in df.columns:
                casts.append(pl.col(col).cast(pl.Float64, strict=False))

        schema = df.schema
        for col in bool_cols:
            if col in schema:
                if schema[col] == pl.Utf8:
                    casts.append(
                        pl.col(col)
                        .str.to_lowercase()
                        .is_in(["true", "1", "yes"])
                        .alias(col)
                    )
                else:
                    casts.append(pl.col(col).cast(pl.Boolean, strict=False))

        return df.with_columns(casts) if casts else df
