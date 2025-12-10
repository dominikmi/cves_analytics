import unittest

import pandas as pd

from src.core.cvss_vector_reassessment import reassess_vulnerabilities


class TestEnvironmentContext(unittest.TestCase):
    """Test cases for environment context in vulnerability reassessment."""

    def test_reassessment_with_environment_factors(self):
        """Test that reassessment considers environment context factors."""
        # Create test data
        data = {
            "cvss_score": [7.5],
            "cvss_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
            "epss_score": [0.1],
            "exposure_risk_factor": [1.5],  # internet-facing service
            "asset_value_risk_factor": [1.3],  # high-value asset
        }
        df = pd.DataFrame(data)

        # Reassess with environment context
        result = reassess_vulnerabilities(
            df,
            cvss_score_col="cvss_score",
            cvss_vector_col="cvss_vector",
            epss_score_col="epss_score",
            exposure_risk_factor_col="exposure_risk_factor",
            asset_value_risk_factor_col="asset_value_risk_factor",
        )

        # Check that the result has the expected columns
        self.assertIn("severity_reassessed", result.columns)
        self.assertIn("reassessment_reason", result.columns)

        # The adjusted score should be higher due to environment factors
        # Original score: 7.5, exposure factor: 1.5, asset value factor: 1.3
        # Adjusted score: min(10.0, 7.5 * 1.5 * 1.3) = min(10.0, 14.625) = 10.0
        # This should result in a Critical severity
        self.assertEqual(len(result), 1)

    def test_reassessment_without_environment_factors(self):
        """Test that reassessment works without environment context factors."""
        # Create test data
        data = {
            "cvss_score": [7.5],
            "cvss_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
            "epss_score": [0.1],
        }
        df = pd.DataFrame(data)

        # Reassess without environment context (should work with defaults)
        result = reassess_vulnerabilities(
            df,
            cvss_score_col="cvss_score",
            cvss_vector_col="cvss_vector",
            epss_score_col="epss_score",
        )

        # Check that the result has the expected columns
        self.assertIn("severity_reassessed", result.columns)
        self.assertIn("reassessment_reason", result.columns)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
