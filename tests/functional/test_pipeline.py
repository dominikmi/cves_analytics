"""Functional tests for the full vulnerability assessment pipeline.

Each test verifies one step of the pipeline end-to-end with realistic
synthetic data, confirming column names, types, and value ranges.
"""

import json
from unittest.mock import patch

import polars as pl
import pytest

from src.core.attack.kill_chain import KillChainCalculator
from src.core.risk.bayesian_assessor import assess_vulnerabilities_bayesian
from src.data.stores.duckdb_store import DuckDBStore
from src.data.transformers.enricher import EnrichmentTransformer
from src.db.sqlite_models import Profile
from src.services.analysis import AttackPathService
from src.services.enrichment import EnrichmentService
from src.services.pipeline import VulnerabilityAssessmentPipeline
from src.services.scanner import DockerScanner


@pytest.fixture
def scan_df() -> pl.DataFrame:
    """Realistic scan results with CVEs that will match CVSS-BT."""
    return pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9999"],
            "package": ["openssl", "curl", "nginx"],
            "version": ["3.0.0", "7.88.0", "1.24.0"],
            "image": ["myapp:latest", "myapp:latest", "web:1.0"],
            "severity": ["HIGH", "CRITICAL", "MEDIUM"],
        }
    )


@pytest.fixture
def cvss_bt_df() -> pl.DataFrame:
    """CVSS-BT reference data matching the scan CVEs."""
    return pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
            "cvss_bt_score": [7.5, 9.1],
            "cvss_bt_severity": ["HIGH", "CRITICAL"],
            "cvss_bt_vector": [
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ],
            "cvss_base_score": [7.5, 9.8],
            "cvss_base_severity": ["HIGH", "CRITICAL"],
            "cvss_base_vector": [
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ],
            "epss": [0.15, 0.85],
            "cwe_id": [264, 79],
        }
    )


@pytest.fixture
def epss_df() -> pl.DataFrame:
    """EPSS reference data."""
    return pl.DataFrame(
        {
            "cve_id": ["CVE-2024-1234", "CVE-2024-5678", "CVE-2023-9999"],
            "epss": [0.15, 0.85, 0.02],
        }
    )


@pytest.fixture
def kev_df() -> pl.DataFrame:
    """KEV catalog with one matching CVE."""
    return pl.DataFrame(
        {
            "CISA/VN Number": ["CVE-2024-5678"],
            "Product Name": ["curl"],
        }
    )


@pytest.fixture
def cwe_data() -> dict:
    """CWE metadata lookup."""
    return {
        "264": {
            "cwe_name": "Permissions Management",
            "cwe_desc": "Improper permissions.",
            "cwe_cc_scope": "Confidentiality",
            "cwe_cc_impact": "High",
        },
        "79": {
            "cwe_name": "Cross-site Scripting",
            "cwe_desc": "Improper neutralization.",
            "cwe_cc_scope": "Integrity",
            "cwe_cc_impact": "High",
        },
    }


@pytest.fixture
def duckdb_store() -> DuckDBStore:
    """In-memory DuckDB store."""
    store = DuckDBStore(":memory:")
    return store


class TestFunctionalScanner:
    """[STEP 1] Scanner: grype JSON output -> findings DataFrame."""

    def test_scan_single_image_returns_schema(self) -> None:
        """Parser extracts CVE ID, package, version, severity from grype JSON."""
        scanner = DockerScanner("grype")
        mock_json = json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2024-0001", "severity": "HIGH"},
                        "artifact": {"name": "libssl", "version": "3.0.0"},
                    },
                ],
            }
        )
        df = scanner._parse_output(mock_json.encode())
        assert not df.is_empty()
        assert set(df.columns) >= {"cve_id", "package", "version", "severity"}
        assert df["cve_id"][0] == "CVE-2024-0001"
        assert df["severity"][0] == "HIGH"

    def test_scan_batch_concatenates_results(self) -> None:
        """Batch scan concatenates per-image results."""
        scanner = DockerScanner("grype")
        mock_json1 = json.dumps(
            {
                "matches": [
                    {"vulnerability": {"id": "CVE-A"}, "artifact": {"name": "pkg1"}}
                ],
            }
        )
        mock_json2 = json.dumps(
            {
                "matches": [
                    {"vulnerability": {"id": "CVE-B"}, "artifact": {"name": "pkg2"}}
                ],
            }
        )
        with patch.object(scanner, "scan") as mock_scan:
            mock_scan.side_effect = [
                scanner._parse_output(mock_json1.encode()),
                scanner._parse_output(mock_json2.encode()),
            ]
            df = scanner.scan_batch(["img1", "img2"])
        assert len(df) == 2
        assert set(df["cve_id"].to_list()) == {"CVE-A", "CVE-B"}

    def test_scan_empty_on_invalid_json(self) -> None:
        """Invalid JSON produces empty DataFrame with correct schema."""
        scanner = DockerScanner("grype")
        df = scanner._parse_output(b"not json")
        assert df.is_empty()
        assert set(df.columns) >= {"cve_id", "package", "version", "severity"}


class TestFunctionalEnrichment:
    """[STEP 2] Enrichment: scan DF + reference data -> enriched DF."""

    def test_cvss_bt_enrichment_matches_cves(
        self, scan_df: pl.DataFrame, cvss_bt_df: pl.DataFrame
    ) -> None:
        """CVSS-BT join adds cvss_base_score, cvss_bt_score, epss, cwe_id columns."""
        enriched, matched = EnrichmentTransformer.enrich_cvss_bt(scan_df, cvss_bt_df)
        assert matched == 2  # 2 of 3 CVEs match
        assert "cvss_base_score" in enriched.columns
        assert "cvss_bt_score" in enriched.columns
        row1 = enriched.filter(pl.col("cve_id") == "CVE-2024-1234").row(0)
        assert row1[enriched.columns.index("cvss_base_score")] == 7.5
        row3 = enriched.filter(pl.col("cve_id") == "CVE-2023-9999").row(0)
        assert row3[enriched.columns.index("cvss_base_score")] is None

    def test_epss_enrichment_adds_scores(
        self, scan_df: pl.DataFrame, epss_df: pl.DataFrame
    ) -> None:
        """EPSS join adds epss column with float scores."""
        enriched = EnrichmentTransformer.enrich_epss(scan_df, epss_df)
        assert "epss" in enriched.columns
        assert enriched.filter(pl.col("cve_id") == "CVE-2024-5678")["epss"][0] == 0.85

    def test_kev_enrichment_marks_known_exploited(
        self, scan_df: pl.DataFrame, kev_df: pl.DataFrame
    ) -> None:
        """KEV join adds is_kev_from_catalog boolean column."""
        enriched = EnrichmentTransformer.enrich_kev(scan_df, kev_df)
        assert "is_kev_from_catalog" in enriched.columns
        assert (
            enriched.filter(pl.col("cve_id") == "CVE-2024-5678")["is_kev_from_catalog"][
                0
            ]
            is True
        )
        assert (
            enriched.filter(pl.col("cve_id") == "CVE-2024-1234")["is_kev_from_catalog"][
                0
            ]
            is False
        )

    def test_cwe_enrichment_adds_metadata(
        self, scan_df: pl.DataFrame, cvss_bt_df: pl.DataFrame, cwe_data: dict
    ) -> None:
        """CWE enrichment adds cwe_name, cwe_desc columns."""
        enriched, _ = EnrichmentTransformer.enrich_cvss_bt(scan_df, cvss_bt_df)
        enriched = EnrichmentTransformer.enrich_cwe(enriched, cwe_data)
        assert "cwe_name" in enriched.columns
        row1 = enriched.filter(pl.col("cve_id") == "CVE-2024-1234")
        assert row1["cwe_name"][0] == "Permissions Management"

    def test_full_enrichment_service(
        self,
        scan_df: pl.DataFrame,
        cvss_bt_df: pl.DataFrame,
        epss_df: pl.DataFrame,
        kev_df: pl.DataFrame,
        cwe_data: dict,
    ) -> None:
        """EnrichmentService applies all sources and standardizes types."""
        result = EnrichmentService.enrich(
            scan_df, cvss_bt_df, epss_df, kev_df, cwe_data
        )
        expected_cols = [
            "cvss_base_score",
            "cvss_bt_score",
            "epss",
            "cwe_name",
            "is_kev_from_catalog",
        ]
        for col in expected_cols:
            assert col in result.columns, f"Missing column: {col}"
        assert result["cvss_base_score"].dtype == pl.Float64


class TestFunctionalBayesianRisk:
    """[STEP 3] Bayesian risk: enriched DF -> posterior probability."""

    def _make_bayesian_df(self) -> pl.DataFrame:
        """Create a DataFrame with columns expected by assess_vulnerabilities_bayesian."""
        return pl.DataFrame(
            {
                "cvss_score": [7.5, 9.8, 5.0],
                "epss_score": [0.15, 0.85, 0.02],
                "cvss_vector": [
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
                ],
            }
        )

    def test_bayesian_risk_adds_columns(self) -> None:
        """Bayesian assessment adds posterior_probability and risk_category."""
        df = self._make_bayesian_df()
        result = assess_vulnerabilities_bayesian(df)
        assert "posterior_probability" in result.columns
        assert "risk_category" in result.columns
        assert "explanation" in result.columns

    def test_bayesian_risk_values_in_range(self) -> None:
        """Posterior probability is in [0, 1]."""
        df = self._make_bayesian_df()
        result = assess_vulnerabilities_bayesian(df)
        probs = result["posterior_probability"].to_list()
        for p in probs:
            assert 0.0 <= p <= 1.0

    def test_bayesian_risk_higher_epss_yields_higher_risk(self) -> None:
        """Higher EPSS score produces higher posterior probability (all else equal)."""
        df = pl.DataFrame(
            {
                "cvss_score": [7.5, 7.5],
                "epss_score": [0.01, 0.99],
                "cvss_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"] * 2,
            }
        )
        result = assess_vulnerabilities_bayesian(df)
        assert result["posterior_probability"][1] > result["posterior_probability"][0]


class TestFunctionalKillChain:
    """[STEP 4] Kill chain analysis: enriched DF -> attack path probability."""

    def test_kill_chain_calculator_returns_result(self) -> None:
        """KillChainCalculator produces a result with stage probabilities."""
        calc = KillChainCalculator()
        vulns = [
            {
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe_ids": [264],
            }
        ]
        result = calc.calculate_kill_chain_probability(
            application={},
            vulnerabilities=vulns,
            security_controls={
                "waf": True,
                "ids": True,
                "rbac": True,
                "network_segmentation": True,
            },
            docker_security_good=True,
        )
        assert 0.0 <= result.overall_probability <= 1.0
        assert result.threat_level in ("low", "medium", "high", "critical")
        assert len(result.critical_path) == 4

    def test_kill_chain_no_vulns_returns_zero(self) -> None:
        """Empty vulnerability list yields zero overall probability."""
        calc = KillChainCalculator()
        result = calc.calculate_kill_chain_probability(
            application={},
            vulnerabilities=[],
            security_controls={"waf": True},
            docker_security_good=True,
        )
        assert result.overall_probability == 0.0


class TestFunctionalAttackPathService:
    """[STEP 5] Attack path service: DF with kill_chain_phase -> annotated DF."""

    def test_analyze_skips_without_kill_chain_phase(self) -> None:
        """Service returns DF unchanged when kill_chain_phase column is missing."""
        df = pl.DataFrame({"cve_id": ["CVE-2024-0001"]})
        result = AttackPathService.analyze(df)
        assert result is df or result.equals(df)

    def test_analyze_adds_probability(self) -> None:
        """Service adds kill_chain_probability column when phase data exists."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-0001"],
                "kill_chain_phase": ["initial_access"],
                "cvss_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
            }
        )
        result = AttackPathService.analyze(df)
        assert "kill_chain_probability" in result.columns
        assert 0.0 <= result["kill_chain_probability"][0] <= 1.0


class TestFunctionalPipelineEndToEnd:
    """Full pipeline: profile -> scan -> enrich -> risk -> store."""

    def test_pipeline_run_returns_result(self, duckdb_store: DuckDBStore) -> None:
        """Pipeline produces findings DF, severity counts, and avg risk."""
        profile = Profile(
            id=1,
            name="test-profile",
            org_size="small",
            org_reach="internal",
            industry="tech",
            environment="dev",
            security_maturity=0.5,
            image_inventory=["myapp:latest"],
            created_at="2024-01-01T00:00:00",
        )
        with (
            patch("src.services.pipeline.CVSSBTLoader") as MockCVSS,
            patch("src.services.pipeline.EPSSLoader") as MockEPSS,
            patch("src.services.pipeline.KEVLoader") as MockKEV,
            patch("src.services.pipeline.CWELoader") as MockCWE,
            patch("src.services.pipeline.DockerScanner") as MockScanner,
        ):
            MockScanner.return_value.scan_batch.return_value = pl.DataFrame(
                {
                    "cve_id": ["CVE-PLACEHOLDER"],
                    "package": ["libtest"],
                    "version": ["1.0"],
                    "image": ["myapp:latest"],
                    "severity": ["UNKNOWN"],
                }
            )
            # Provide reference data that matches placeholder CVE
            MockCVSS.return_value.load.return_value = pl.DataFrame(
                {
                    "cve_id": ["CVE-PLACEHOLDER"],
                    "cvss_base_score": [7.5],
                    "cvss_bt_score": [7.0],
                    "epss": [0.5],
                    "cvss_base_vector": [
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    ],
                }
            )
            MockEPSS.return_value.load.return_value = pl.DataFrame(
                {
                    "cve_id": ["CVE-PLACEHOLDER"],
                    "epss": [0.5],
                }
            )
            MockKEV.return_value.load.return_value = pl.DataFrame(
                {
                    "CISA/VN Number": [],
                }
            )
            MockCWE.return_value.batch_get.return_value = {}

            pipeline = VulnerabilityAssessmentPipeline(profile, duckdb_store)
            result = pipeline.run()

        assert len(result.findings_df) == 1
        assert result.severity_counts == {"UNKNOWN": 1}
        assert result.avg_bayesian_risk is not None
        assert 0.0 <= result.avg_bayesian_risk <= 1.0

    def test_pipeline_stores_findings_in_duckdb(
        self, duckdb_store: DuckDBStore
    ) -> None:
        """Pipeline writes findings to DuckDB store."""
        profile = Profile(
            id=1,
            name="test-profile",
            org_size="small",
            org_reach="internal",
            industry="tech",
            environment="dev",
            security_maturity=0.5,
            image_inventory=["img1", "img2"],
            created_at="2024-01-01T00:00:00",
        )
        with (
            patch("src.services.pipeline.CVSSBTLoader") as MockCVSS,
            patch("src.services.pipeline.EPSSLoader") as MockEPSS,
            patch("src.services.pipeline.KEVLoader") as MockKEV,
            patch("src.services.pipeline.CWELoader") as MockCWE,
            patch("src.services.pipeline.DockerScanner") as MockScanner,
        ):
            MockScanner.return_value.scan_batch.return_value = pl.DataFrame(
                {
                    "cve_id": ["CVE-A", "CVE-B"],
                    "package": ["pkg1", "pkg2"],
                    "version": ["1.0", "2.0"],
                    "image": ["img1", "img2"],
                    "severity": ["HIGH", "MEDIUM"],
                }
            )
            MockCVSS.return_value.load.return_value = pl.DataFrame(
                schema={"cve_id": pl.Utf8}
            )
            MockEPSS.return_value.load.return_value = pl.DataFrame(
                schema={"cve_id": pl.Utf8, "epss": pl.Float64}
            )
            MockKEV.return_value.load.return_value = pl.DataFrame(
                schema={"CISA/VN Number": pl.Utf8}
            )
            MockCWE.return_value.batch_get.return_value = {}

            pipeline = VulnerabilityAssessmentPipeline(profile, duckdb_store)
            pipeline.run()

        df = duckdb_store.read_table("findings")
        assert len(df) == 2


class TestFunctionalDuckDBStore:
    """DuckDB store: write, read, append, execute."""

    def test_write_and_read(self) -> None:
        """write_table + read_table round-trips correctly."""
        store = DuckDBStore(":memory:")
        df = pl.DataFrame({"id": [1, 2], "name": ["a", "b"]})
        store.write_table("test", df)
        result = store.read_table("test")
        assert len(result) == 2
        assert set(result["name"].to_list()) == {"a", "b"}

    def test_append_mode(self) -> None:
        """Append mode adds rows without overwriting."""
        store = DuckDBStore(":memory:")
        store.write_table("test", pl.DataFrame({"x": [1]}))
        store.write_table("test", pl.DataFrame({"x": [2]}), mode="append")
        result = store.read_table("test")
        assert len(result) == 2

    def test_execute_sql(self) -> None:
        """execute() runs arbitrary SQL and returns DataFrame."""
        store = DuckDBStore(":memory:")
        store.write_table("test", pl.DataFrame({"x": [1, 2, 3]}))
        result = store.execute("SELECT COUNT(*) as cnt FROM test")
        assert result["cnt"][0] == 3
