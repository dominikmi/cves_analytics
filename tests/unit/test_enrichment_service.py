"""Tests for enrichment service."""

import polars as pl

from src.services.enrichment import EnrichmentService


class TestEnrichmentService:
    """Test EnrichmentService."""

    def test_enrich_empty(self) -> None:
        scan = pl.DataFrame(schema={"cve_id": pl.Utf8})
        cvss = pl.DataFrame(schema={"cve_id": pl.Utf8})
        epss = pl.DataFrame(schema={"cve": pl.Utf8, "epss": pl.Float64})
        result = EnrichmentService.enrich(scan, cvss, epss)
        assert result.is_empty()

    def test_enrich_with_data(self) -> None:
        scan = pl.DataFrame({"cve_id": ["CVE-2024-0001"]})
        cvss = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-0001"],
                "cvss_bt_score": [8.5],
            }
        )
        epss = pl.DataFrame({"cve": ["CVE-2024-0001"], "epss": [0.8]})
        result = EnrichmentService.enrich(scan, cvss, epss)
        assert "cvss_bt_score" in result.columns
        assert "epss" in result.columns

    def test_enrich_with_kev(self) -> None:
        scan = pl.DataFrame({"cve_id": ["CVE-2024-0001"]})
        cvss = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-0001"],
                "cvss_bt_score": [8.5],
            }
        )
        epss = pl.DataFrame({"cve": ["CVE-2024-0001"], "epss": [0.8]})
        kev = pl.DataFrame({"CISA/VN Number": ["CVE-2024-0001"]})
        result = EnrichmentService.enrich(scan, cvss, epss, kev_df=kev)
        assert "is_kev_from_catalog" in result.columns
