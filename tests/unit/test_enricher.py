"""Tests for enrichment transformer."""

import polars as pl
import pytest

from src.data.transformers.enricher import EnrichmentTransformer


class TestEnrichmentTransformer:
    """Test EnrichmentTransformer join operations."""

    @pytest.fixture
    def scan_df(self) -> pl.DataFrame:
        return pl.DataFrame(
            {
                "cve_id": ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"],
                "package": ["nginx", "openssl", "curl"],
            }
        )

    @pytest.fixture
    def cvss_bt_df(self) -> pl.DataFrame:
        return pl.DataFrame(
            {
                "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
                "cvss_bt_score": [8.5, 7.0],
                "is_kev": [True, False],
            }
        )

    @pytest.fixture
    def epss_df(self) -> pl.DataFrame:
        return pl.DataFrame(
            {
                "cve": ["CVE-2024-0001", "CVE-2024-0003"],
                "epss": [0.8, 0.1],
            }
        )

    def test_enrich_cvss_bt(
        self, scan_df: pl.DataFrame, cvss_bt_df: pl.DataFrame
    ) -> None:
        enriched, count = EnrichmentTransformer.enrich_cvss_bt(scan_df, cvss_bt_df)
        assert count == 2
        assert "cvss_bt_score" in enriched.columns
        assert len(enriched) == 3

    def test_enrich_cvss_bt_empty_scan(self, cvss_bt_df: pl.DataFrame) -> None:
        empty = pl.DataFrame(schema={"cve_id": pl.Utf8})
        enriched, count = EnrichmentTransformer.enrich_cvss_bt(empty, cvss_bt_df)
        assert count == 0

    def test_enrich_cvss_bt_empty_reference(self, scan_df: pl.DataFrame) -> None:
        empty = pl.DataFrame(schema={"cve_id": pl.Utf8})
        enriched, count = EnrichmentTransformer.enrich_cvss_bt(scan_df, empty)
        assert count == 0

    def test_enrich_epss(self, scan_df: pl.DataFrame, epss_df: pl.DataFrame) -> None:
        enriched = EnrichmentTransformer.enrich_epss(scan_df, epss_df)
        assert "epss" in enriched.columns
        assert len(enriched) == 3

    def test_enrich_epss_empty(self, scan_df: pl.DataFrame) -> None:
        empty = pl.DataFrame(schema={"cve": pl.Utf8, "epss": pl.Float64})
        enriched = EnrichmentTransformer.enrich_epss(scan_df, empty)
        assert len(enriched) == 3

    def test_enrich_kev(self, scan_df: pl.DataFrame) -> None:
        kev_df = pl.DataFrame({"CISA/VN Number": ["CVE-2024-0001"]})
        enriched = EnrichmentTransformer.enrich_kev(scan_df, kev_df)
        assert "is_kev_from_catalog" in enriched.columns
        assert enriched["is_kev_from_catalog"][0] is True
        assert enriched["is_kev_from_catalog"][1] is False

    def test_enrich_kev_none(self, scan_df: pl.DataFrame) -> None:
        enriched = EnrichmentTransformer.enrich_kev(scan_df, None)
        assert "is_kev_from_catalog" not in enriched.columns

    def test_enrich_cwe(self, scan_df: pl.DataFrame) -> None:
        cwe_data = {
            "CWE-79": {"cwe_name": "XSS", "cwe_desc": "Cross-site scripting"},
        }
        df_with_cwe = scan_df.with_columns(pl.lit("CWE-79").alias("cwe_id"))
        enriched = EnrichmentTransformer.enrich_cwe(df_with_cwe, cwe_data)
        assert "cwe_name" in enriched.columns
        assert enriched["cwe_name"][0] == "XSS"

    def test_enrich_cwe_empty(self, scan_df: pl.DataFrame) -> None:
        enriched = EnrichmentTransformer.enrich_cwe(scan_df, {})
        assert "cwe_name" not in enriched.columns

    def test_standardize_types(self) -> None:
        df = pl.DataFrame(
            {
                "cvss_base_score": ["9.8", "7.5"],
                "is_kev": ["true", "false"],
            }
        )
        result = EnrichmentTransformer.standardize_types(df)
        assert result["cvss_base_score"].dtype == pl.Float64
        assert result["is_kev"].dtype == pl.Boolean
        assert result["is_kev"].to_list() == [True, False]

    def test_standardize_types_no_matching_cols(self) -> None:
        df = pl.DataFrame({"foo": [1, 2]})
        result = EnrichmentTransformer.standardize_types(df)
        assert result is not None
