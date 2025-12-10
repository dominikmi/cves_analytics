"""Tests for CVSS vector reassessment module."""

import unittest

import pandas as pd

from src.core.cvss_parser import CVSSParser
from src.core.cvss_vector_reassessment import (
    CVSSEPSSReassessment,
    normalize_epss,
    reassess_vulnerabilities,
    validate_cvss_vector,
    validate_risk_factor,
)


class TestCVSSVectorParser(unittest.TestCase):
    """Test cases for CVSSParser vector parsing methods."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = CVSSParser()

    def test_parse_cvss_vector_basic(self):
        """Test parsing basic CVSS vector."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = self.parser.parse_cvss_vector(vector)

        self.assertEqual(result["version"], "3.1")
        self.assertEqual(result["AV"], "N")
        self.assertEqual(result["AC"], "L")
        self.assertEqual(result["PR"], "N")
        self.assertEqual(result["UI"], "N")
        self.assertEqual(result["S"], "U")
        self.assertEqual(result["C"], "H")
        self.assertEqual(result["I"], "H")
        self.assertEqual(result["A"], "H")

    def test_parse_cvss_vector_without_prefix(self):
        """Test parsing CVSS vector without CVSS prefix."""
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = self.parser.parse_cvss_vector(vector)

        self.assertEqual(result["AV"], "N")
        self.assertEqual(result["AC"], "L")
        self.assertEqual(result["PR"], "N")
        self.assertEqual(result["UI"], "N")
        self.assertEqual(result["S"], "U")
        self.assertEqual(result["C"], "H")
        self.assertEqual(result["I"], "H")
        self.assertEqual(result["A"], "H")

    def test_parse_cvss_vector_none_input(self):
        """Test parsing None input."""
        result = self.parser.parse_cvss_vector(None)
        self.assertEqual(result, {})

    def test_parse_cvss_vector_empty_input(self):
        """Test parsing empty string input."""
        result = self.parser.parse_cvss_vector("")
        self.assertEqual(result, {})

    def test_get_attack_vector(self):
        """Test extracting attack vector from components."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        components = self.parser.parse_cvss_vector(vector)
        av = self.parser.get_attack_vector(components)
        self.assertEqual(av, "N")

    def test_get_attack_complexity(self):
        """Test extracting attack complexity from components."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        components = self.parser.parse_cvss_vector(vector)
        ac = self.parser.get_attack_complexity(components)
        self.assertEqual(ac, "L")

    def test_get_scope(self):
        """Test extracting scope from components."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        components = self.parser.parse_cvss_vector(vector)
        scope = self.parser.get_scope(components)
        self.assertEqual(scope, "C")


class TestValidationFunctions(unittest.TestCase):
    """Test cases for validation helper functions."""

    def test_validate_risk_factor_valid(self):
        """Test risk factor validation with valid values."""
        assert validate_risk_factor(1.0) == 1.0
        assert validate_risk_factor(0.5) == 0.5
        assert validate_risk_factor(3.0) == 3.0

    def test_validate_risk_factor_invalid_range(self):
        """Test risk factor validation with out-of-range values."""
        assert validate_risk_factor(0.1) == 1.0  # Below range
        assert validate_risk_factor(10.0) == 1.0  # Above range

    def test_validate_risk_factor_invalid_type(self):
        """Test risk factor validation with invalid type."""
        assert validate_risk_factor("invalid") == 1.0
        assert validate_risk_factor(None) == 1.0

    def test_normalize_epss_valid(self):
        """Test EPSS normalization with valid values."""
        assert normalize_epss(0.5) == 0.5
        assert normalize_epss(0.0) == 0.0
        assert normalize_epss(1.0) == 1.0

    def test_normalize_epss_percentage(self):
        """Test EPSS normalization with percentage values."""
        assert normalize_epss(50.0) == 0.5
        assert normalize_epss(100.0) == 1.0

    def test_normalize_epss_invalid(self):
        """Test EPSS normalization with invalid values."""
        assert normalize_epss(150.0) == 0.0  # Out of range (>100%)
        assert normalize_epss("invalid") == 0.0  # Type error
        assert normalize_epss(None) == 0.0  # None

    def test_validate_cvss_vector_valid(self):
        """Test CVSS vector validation with valid vectors."""
        assert validate_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert validate_cvss_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_validate_cvss_vector_invalid_metric(self):
        """Test CVSS vector validation with invalid metric."""
        assert not validate_cvss_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert not validate_cvss_vector("CVSS:3.1/XX:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_validate_cvss_vector_invalid_value(self):
        """Test CVSS vector validation with invalid value."""
        assert not validate_cvss_vector("CVSS:3.1/AV:N/AC:X/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_validate_cvss_vector_none(self):
        """Test CVSS vector validation with None."""
        assert not validate_cvss_vector(None)
        assert not validate_cvss_vector("")


class TestCVSSEPSSReassessment(unittest.TestCase):
    """Test cases for CVSSEPSSReassessment class."""

    def setUp(self):
        """Set up test fixtures."""
        self.reassessor = CVSSEPSSReassessment()

    def test_reassess_severity_missing_cvss_score(self):
        """Test reassessment with missing CVSS score."""
        severity, reason = self.reassessor.reassess_severity(None, None, None)
        self.assertEqual(severity, "Unknown")
        self.assertEqual(reason, "Missing CVSS score")

    def test_reassess_severity_high_cvss_high_epss(self):
        """Test reassessment with high CVSS and high EPSS - should be Critical."""
        severity, reason = self.reassessor.reassess_severity(
            9.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.6
        )
        self.assertEqual(severity, "Critical")
        self.assertIn("High CVSS", reason)

    def test_reassess_severity_network_rce(self):
        """Test reassessment with network RCE - should be Critical."""
        severity, reason = self.reassessor.reassess_severity(
            8.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.4
        )
        self.assertEqual(severity, "Critical")
        # Check for key parts of the reason text
        self.assertIn("Network RCE", reason)
        self.assertIn("AV:N", reason)
        self.assertIn("AC:L", reason)

    def test_reassess_severity_standard_high(self):
        """Test reassessment with standard high CVSS score."""
        severity, reason = self.reassessor.reassess_severity(
            7.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 0.1
        )
        self.assertEqual(severity, "High")
        self.assertIn("High CVSS score", reason)

    def test_reassess_severity_moderate(self):
        """Test reassessment with moderate CVSS score."""
        severity, reason = self.reassessor.reassess_severity(
            5.5, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", 0.1
        )
        self.assertEqual(severity, "Medium")
        self.assertIn("Moderate CVSS score", reason)

    def test_reassess_severity_kev_critical(self):
        """Test reassessment with KEV and EPSS >= 0.25 - should be Critical."""
        severity, reason = self.reassessor.reassess_severity(
            7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.25, is_kev=True
        )
        self.assertEqual(severity, "Critical")
        self.assertIn("Known Exploited Vulnerability", reason)
        self.assertIn("EPSS>=0.25", reason)

    def test_reassess_severity_kev_below_threshold(self):
        """Test reassessment with KEV but EPSS < 0.25 - should not be Critical."""
        severity, reason = self.reassessor.reassess_severity(
            7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.2, is_kev=True
        )
        # Should not match KEV criterion, but should still be High due to CVSS >= 7.0
        self.assertEqual(severity, "High")

    def test_reassess_severity_invalid_cvss_score(self):
        """Test reassessment with invalid CVSS score."""
        severity, reason = self.reassessor.reassess_severity(
            15.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.5
        )
        self.assertEqual(severity, "Unknown")
        self.assertIn("Invalid CVSS score", reason)

    def test_reassess_severity_invalid_vector(self):
        """Test reassessment with invalid CVSS vector."""
        severity, reason = self.reassessor.reassess_severity(
            7.5, "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.5
        )
        # Should still reassess based on CVSS score, just without vector components
        self.assertEqual(severity, "High")

    def test_reassess_severity_with_risk_factors(self):
        """Test reassessment with environment risk factors."""
        severity, reason = self.reassessor.reassess_severity(
            7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            0.5,
            exposure_risk_factor=1.5,
            asset_value_risk_factor=1.5,
        )
        # CVSS 7.5 * 1.5 * 1.5 = 16.875 capped at 10.0
        self.assertEqual(severity, "Critical")
        self.assertIn("adjusted", reason)


class TestReassessVulnerabilities(unittest.TestCase):
    """Test cases for reassess_vulnerabilities function."""

    # def test_reassess_vulnerabilities_empty_dataframe(self):
    #     """Test reassessment with empty DataFrame."""
    #     df = pd.DataFrame()
    #     result = reassess_vulnerabilities(df)
    #     # Should return empty DataFrame unchanged
    #     self.assertTrue(result.empty)

    def test_reassess_vulnerabilities_with_data(self):
        """Test reassessment with sample data."""
        data = {
            "cvss_score": [9.5, 7.5, 5.5],
            "cvss_vector": [
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
            ],
            "epss_score": [0.6, 0.1, 0.1],
        }
        df = pd.DataFrame(data)
        result = reassess_vulnerabilities(df)

        self.assertIn("severity_reassessed", result.columns)
        self.assertIn("reassessment_reason", result.columns)
        self.assertEqual(len(result), 3)


if __name__ == "__main__":
    unittest.main()
