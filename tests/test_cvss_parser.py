"""Tests for CVSS parser module."""

import unittest

from src.core.cvss_parser import CVSSParser


class TestCVSSParser(unittest.TestCase):
    """Test cases for CVSSParser class."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_impact_data = {
            "baseMetricV3": {
                "cvssV3": {
                    "version": "3.1",
                    "baseScore": 7.5,
                    "baseSeverity": "High",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "attackVector": "NETWORK",
                    "attackComplexity": "LOW",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                    "scope": "UNCHANGED",
                    "confidentialityImpact": "HIGH",
                    "integrityImpact": "NONE",
                    "availabilityImpact": "NONE",
                },
                "exploitabilityScore": 3.9,
                "impactScore": 3.6,
            }
        }

    def test_safe_get_with_valid_keys(self):
        """Test _safe_get with valid nested keys."""
        data = {"a": {"b": {"c": "value"}}}
        result = CVSSParser._safe_get(data, "a", "b", "c")
        assert result == "value"

    def test_safe_get_with_missing_key(self):
        """Test _safe_get with missing key."""
        data = {"a": {"b": {"c": "value"}}}
        result = CVSSParser._safe_get(data, "a", "x", "c")
        assert result is None

    def test_safe_get_with_empty_dict(self):
        """Test _safe_get with empty dictionary."""
        data = {}
        result = CVSSParser._safe_get(data, "a", "b")
        assert result is None

    def test_parse_cvss_v3(self):
        """Test parsing CVSS v3 metrics."""
        result = CVSSParser.parse_cvss_v3(self.sample_impact_data)

        self.assertEqual(result["cvss_version"], "3.1")
        self.assertEqual(result["base_score"], 7.5)
        self.assertEqual(result["base_severity"], "High")
        self.assertEqual(result["attack_vector"], "NETWORK")
        self.assertEqual(result["attack_complexity"], "LOW")
        self.assertEqual(result["confidentiality_impact"], "HIGH")

    def test_parse_cvss_v3_missing_data(self):
        """Test parsing CVSS v3 with missing data."""
        result = CVSSParser.parse_cvss_v3({})
        assert result == {}

    def test_parse_cvss_v2(self):
        """Test parsing CVSS v2 metrics."""
        impact_data = {
            "baseMetricV2": {
                "cvssV2": {
                    "version": "2.0",
                    "baseScore": 5.0,
                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                    "accessVector": "NETWORK",
                    "accessComplexity": "LOW",
                    "authentication": "NONE",
                    "confidentialityImpact": "PARTIAL",
                    "integrityImpact": "NONE",
                    "availabilityImpact": "NONE",
                },
                "severity": "Medium",
                "exploitabilityScore": 10.0,
                "impactScore": 2.9,
                "userInteractionRequired": False,
            }
        }

        result = CVSSParser.parse_cvss_v2(impact_data)

        assert result["cvss_version"] == "2.0"
        assert result["base_score"] == 5.0
        assert result["base_severity"] == "Medium"
        assert result["access_vector"] == "NETWORK"

    def test_parse_cvss_prefers_v3(self):
        """Test that parse_cvss prefers v3 over v2."""
        result = CVSSParser.parse_cvss(self.sample_impact_data)

        # Should return v3 data
        self.assertEqual(result["cvss_version"], "3.1")
        self.assertEqual(result["base_score"], 7.5)

    def test_parse_cvss_falls_back_to_v2(self):
        """Test that parse_cvss falls back to v2 if v3 not available."""
        impact_data = {
            "baseMetricV2": {
                "cvssV2": {
                    "version": "2.0",
                    "baseScore": 5.0,
                    "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                    "accessVector": "NETWORK",
                    "accessComplexity": "LOW",
                    "authentication": "NONE",
                    "confidentialityImpact": "PARTIAL",
                    "integrityImpact": "NONE",
                    "availabilityImpact": "NONE",
                },
                "severity": "Medium",
                "exploitabilityScore": 10.0,
                "impactScore": 2.9,
                "userInteractionRequired": False,
            }
        }

        result = CVSSParser.parse_cvss(impact_data)

        # Should return v2 data
        assert result["cvss_version"] == "2.0"
        assert result["base_score"] == 5.0

    def test_parse_cvss_empty_data(self):
        """Test parse_cvss with empty data."""
        result = CVSSParser.parse_cvss({})
        assert result == {}
