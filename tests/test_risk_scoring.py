"""Unit tests for risk scoring module.

Tests cover:
- calculate_bayesian_risk function
- add_bayesian_risk_scores function
- categorize_by_bayesian_risk function
- Legacy interface functions
"""

import unittest

import polars as pl

from src.core.bayesian_risk import BayesianRiskAssessor, BayesianRiskResult
from src.core.risk_scoring import (
    add_bayesian_risk_scores,
    calculate_bayesian_risk,
    calculate_risk_score,
    categorize_by_bayesian_risk,
)


class TestCalculateBayesianRisk(unittest.TestCase):
    """Tests for calculate_bayesian_risk function."""

    def test_basic_calculation(self) -> None:
        """Test basic risk calculation with minimal data."""
        row = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
        }
        result = calculate_bayesian_risk(row)

        self.assertIsInstance(result, BayesianRiskResult)
        self.assertGreater(result.posterior_probability, 0)
        self.assertLess(result.posterior_probability, 1)

    def test_with_security_controls(self) -> None:
        """Test that security controls reduce risk."""
        row_no_controls = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
            "exposure": "internet-facing",
        }

        row_with_controls = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
            "exposure": "internet-facing",
            "security_controls": {
                "network_segmentation": True,
                "waf": True,
                "mfa": True,
            },
        }

        result_no_controls = calculate_bayesian_risk(row_no_controls)
        result_with_controls = calculate_bayesian_risk(row_with_controls)

        self.assertLess(
            result_with_controls.posterior_probability,
            result_no_controls.posterior_probability,
        )

    def test_with_threat_indicators(self) -> None:
        """Test that threat indicators increase risk."""
        row_no_threats = {
            "epss_score": 0.05,
            "cvss_score": 7.5,
        }

        row_with_kev = {
            "epss_score": 0.05,
            "cvss_score": 7.5,
            "is_kev": True,
        }

        result_no_threats = calculate_bayesian_risk(row_no_threats)
        result_with_kev = calculate_bayesian_risk(row_with_kev)

        self.assertGreater(
            result_with_kev.posterior_probability,
            result_no_threats.posterior_probability,
        )

    def test_with_cvss_bt_exploit_indicators(self) -> None:
        """Test CVSS-BT granular exploit indicators."""
        row = {
            "epss_score": 0.05,
            "cvss_score": 7.5,
            "has_exploitdb": True,
            "has_metasploit": True,
            "has_nuclei": False,
            "has_poc_github": True,
        }

        result = calculate_bayesian_risk(row)

        # Should have elevated risk due to exploit indicators
        self.assertGreater(result.posterior_probability, 0.05)

    def test_with_exposure(self) -> None:
        """Test exposure affects risk."""
        row_internal = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
            "exposure": "internal",
        }

        row_internet = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
            "exposure": "internet-facing",
        }

        result_internal = calculate_bayesian_risk(row_internal)
        result_internet = calculate_bayesian_risk(row_internet)

        self.assertGreater(
            result_internet.posterior_probability,
            result_internal.posterior_probability,
        )

    def test_with_asset_value(self) -> None:
        """Test asset value affects risk."""
        row_low = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
            "asset_value": "low",
        }

        row_critical = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
            "asset_value": "critical",
        }

        result_low = calculate_bayesian_risk(row_low)
        result_critical = calculate_bayesian_risk(row_critical)

        # Critical assets should have higher risk
        self.assertGreaterEqual(
            result_critical.posterior_probability,
            result_low.posterior_probability,
        )

    def test_with_cvss_vector(self) -> None:
        """Test CVSS vector parsing."""
        row = {
            "epss_score": 0.1,
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "exposure": "internet-facing",
        }

        result = calculate_bayesian_risk(row)

        self.assertIsInstance(result, BayesianRiskResult)
        # Network attack vector should contribute to risk
        self.assertIn("risk_category", result.to_dict())

    def test_with_custom_assessor(self) -> None:
        """Test using custom assessor."""
        from src.core.bayesian_risk import LikelihoodRatioConfig

        config = LikelihoodRatioConfig(exposure_internet=5.0)  # Higher than default
        assessor = BayesianRiskAssessor(config)

        row = {
            "epss_score": 0.1,
            "exposure": "internet-facing",
        }

        result = calculate_bayesian_risk(row, assessor=assessor)
        self.assertIsInstance(result, BayesianRiskResult)

    def test_missing_values_handled(self) -> None:
        """Test that missing values are handled gracefully."""
        row = {}  # Empty row

        result = calculate_bayesian_risk(row)

        self.assertIsInstance(result, BayesianRiskResult)
        # Should use defaults and not crash


class TestAddBayesianRiskScores(unittest.TestCase):
    """Tests for add_bayesian_risk_scores function."""

    def test_empty_dataframe(self) -> None:
        """Test with empty DataFrame."""
        df = pl.DataFrame()
        result = add_bayesian_risk_scores(df)
        self.assertTrue(result.is_empty())

    def test_basic_dataframe(self) -> None:
        """Test with basic vulnerability DataFrame."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2021-1234", "CVE-2021-5678"],
                "epss_score": [0.1, 0.05],
                "cvss_score": [7.5, 5.0],
                "cvss_vector": [
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
                ],
                "exposure": ["internet-facing", "internal"],
                "asset_value": ["high", "low"],
            }
        )

        result = add_bayesian_risk_scores(df)

        self.assertIn("bayesian_risk_score", result.columns)
        self.assertIn("risk_category", result.columns)
        self.assertIn("ci_low", result.columns)
        self.assertIn("ci_high", result.columns)
        self.assertEqual(len(result), 2)

    def test_with_kev_column(self) -> None:
        """Test with KEV indicator column."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2021-1234", "CVE-2021-5678"],
                "epss_score": [0.1, 0.1],
                "cvss_score": [7.5, 7.5],
                "exposure": ["internet-facing", "internet-facing"],
                "asset_value": ["high", "high"],
                "is_kev": [True, False],
            }
        )

        result = add_bayesian_risk_scores(df)

        # KEV-listed should have higher risk
        kev_row = result.filter(pl.col("is_kev")).to_dicts()[0]
        non_kev_row = result.filter(~pl.col("is_kev")).to_dicts()[0]

        self.assertGreater(
            kev_row["bayesian_risk_score"],
            non_kev_row["bayesian_risk_score"],
        )


class TestCategorizeByBayesianRisk(unittest.TestCase):
    """Tests for categorize_by_bayesian_risk function."""

    def test_empty_dataframe(self) -> None:
        """Test with empty DataFrame."""
        df = pl.DataFrame()
        result = categorize_by_bayesian_risk(df)

        self.assertIn("critical", result)
        self.assertIn("high", result)
        self.assertIn("medium", result)
        self.assertIn("low", result)
        self.assertIn("negligible", result)

        for category in result.values():
            self.assertTrue(category.is_empty())

    def test_categorization(self) -> None:
        """Test that vulnerabilities are categorized correctly."""
        # Create DataFrame with risk_category already set
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
                "risk_category": ["Critical", "High", "Medium", "Low"],
                "bayesian_risk_score": [0.9, 0.6, 0.3, 0.1],
            }
        )

        result = categorize_by_bayesian_risk(df)

        self.assertEqual(len(result["critical"]), 1)
        self.assertEqual(len(result["high"]), 1)
        self.assertEqual(len(result["medium"]), 1)
        self.assertEqual(len(result["low"]), 1)

    def test_sorting(self) -> None:
        """Test that categories are sorted by risk score."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-1", "CVE-2", "CVE-3"],
                "risk_category": ["Critical", "Critical", "Critical"],
                "bayesian_risk_score": [0.7, 0.9, 0.8],
            }
        )

        result = categorize_by_bayesian_risk(df)

        critical = result["critical"]
        scores = critical["bayesian_risk_score"].to_list()

        # Should be sorted descending
        self.assertEqual(scores, sorted(scores, reverse=True))


class TestLegacyInterface(unittest.TestCase):
    """Tests for legacy interface functions."""

    def test_calculate_risk_score_returns_float(self) -> None:
        """Test that legacy function returns float."""
        row = {
            "epss_score": 0.1,
            "cvss_score": 7.5,
        }

        result = calculate_risk_score(row)

        self.assertIsInstance(result, float)
        self.assertGreaterEqual(result, 0)
        self.assertLessEqual(result, 10)

    def test_calculate_risk_score_scales_correctly(self) -> None:
        """Test that risk score is scaled to 0-10."""
        row_low = {
            "epss_score": 0.01,
            "cvss_score": 3.0,
            "exposure": "internal",
        }

        row_high = {
            "epss_score": 0.9,
            "cvss_score": 9.8,
            "exposure": "internet-facing",
            "is_kev": True,
        }

        result_low = calculate_risk_score(row_low)
        result_high = calculate_risk_score(row_high)

        self.assertLess(result_low, result_high)

    def test_calculate_risk_score_handles_missing_values(self) -> None:
        """Test that legacy function handles missing values."""
        row = {}

        result = calculate_risk_score(row)

        self.assertIsInstance(result, float)


if __name__ == "__main__":
    unittest.main()
