"""Unit tests for Bayesian risk assessment module.

Tests cover:
- BayesianRiskAssessor initialization and configuration
- EPSS normalization
- Security control likelihood ratios
- Exposure likelihood ratios with gating
- Threat indicator likelihood ratios
- CVSS vector parsing and LR application
- Credible interval calculation
- Risk categorization
- End-to-end assessment
"""

import unittest

import polars as pl

from src.core.bayesian_risk import (
    BayesianRiskAssessor,
    BayesianRiskResult,
    CVSSVectorLR,
    ExposureConditionalControlLR,
    LikelihoodRatioConfig,
    SecurityControlsInput,
    ThreatIndicatorsInput,
    assess_vulnerabilities_bayesian,
    get_control_lr,
    get_exposure_lr,
    get_threat_indicator_lr,
)


class TestLikelihoodRatioConfig(unittest.TestCase):
    """Tests for LikelihoodRatioConfig Pydantic model."""

    def test_default_values(self) -> None:
        """Test that default values are set correctly."""
        config = LikelihoodRatioConfig()
        self.assertEqual(config.network_segmentation, 0.3)
        self.assertEqual(config.mfa, 0.3)
        self.assertEqual(config.exposure_internet, 2.5)
        self.assertEqual(config.kev_listed, 3.0)

    def test_custom_values(self) -> None:
        """Test that custom values can be set."""
        config = LikelihoodRatioConfig(
            network_segmentation=0.5,
            mfa=0.4,
            exposure_internet=3.0,
        )
        self.assertEqual(config.network_segmentation, 0.5)
        self.assertEqual(config.mfa, 0.4)
        self.assertEqual(config.exposure_internet, 3.0)

    def test_validation_bounds(self) -> None:
        """Test that validation bounds are enforced."""
        # Security controls must be <= 1.0
        with self.assertRaises(ValueError):
            LikelihoodRatioConfig(network_segmentation=1.5)

        # Security controls must be >= 0.01
        with self.assertRaises(ValueError):
            LikelihoodRatioConfig(network_segmentation=0.0)

        # Threat indicators must be >= 1.0
        with self.assertRaises(ValueError):
            LikelihoodRatioConfig(kev_listed=0.5)


class TestSecurityControlsInput(unittest.TestCase):
    """Tests for SecurityControlsInput Pydantic model."""

    def test_default_all_false(self) -> None:
        """Test that all controls default to False."""
        controls = SecurityControlsInput()
        self.assertFalse(controls.network_segmentation)
        self.assertFalse(controls.mfa)
        self.assertFalse(controls.waf)

    def test_coerce_bool_from_string(self) -> None:
        """Test that string values are coerced to bool."""
        controls = SecurityControlsInput(
            network_segmentation="true",
            mfa="yes",
            waf="1",
        )
        self.assertTrue(controls.network_segmentation)
        self.assertTrue(controls.mfa)
        self.assertTrue(controls.waf)

    def test_coerce_bool_false_strings(self) -> None:
        """Test that false-like strings are coerced to False."""
        controls = SecurityControlsInput(
            network_segmentation="false",
            mfa="no",
            waf="0",
        )
        self.assertFalse(controls.network_segmentation)
        self.assertFalse(controls.mfa)
        self.assertFalse(controls.waf)


class TestThreatIndicatorsInput(unittest.TestCase):
    """Tests for ThreatIndicatorsInput Pydantic model."""

    def test_default_all_false(self) -> None:
        """Test that all indicators default to False."""
        indicators = ThreatIndicatorsInput()
        self.assertFalse(indicators.is_kev)
        self.assertFalse(indicators.has_public_exploit)
        self.assertFalse(indicators.has_metasploit_module)

    def test_set_indicators(self) -> None:
        """Test setting threat indicators."""
        indicators = ThreatIndicatorsInput(
            is_kev=True,
            has_public_exploit=True,
        )
        self.assertTrue(indicators.is_kev)
        self.assertTrue(indicators.has_public_exploit)
        self.assertFalse(indicators.has_metasploit_module)


class TestExposureConditionalControlLR(unittest.TestCase):
    """Tests for exposure-conditional control likelihood ratios."""

    def test_waf_internet_facing(self) -> None:
        """Test WAF is highly effective for internet-facing."""
        lr = ExposureConditionalControlLR.get_lr("waf", "internet-facing")
        self.assertEqual(lr, 0.3)

    def test_waf_internal(self) -> None:
        """Test WAF has minimal effect internally."""
        lr = ExposureConditionalControlLR.get_lr("waf", "internal")
        self.assertEqual(lr, 0.9)

    def test_network_segmentation_internal(self) -> None:
        """Test network segmentation is effective internally."""
        lr = ExposureConditionalControlLR.get_lr("network_segmentation", "internal")
        self.assertEqual(lr, 0.3)

    def test_unknown_control(self) -> None:
        """Test unknown control returns 1.0 (no effect)."""
        lr = ExposureConditionalControlLR.get_lr("unknown_control", "internet-facing")
        self.assertEqual(lr, 1.0)

    def test_default_lr(self) -> None:
        """Test controls with default LRs."""
        lr = ExposureConditionalControlLR.get_lr("air_gapped", "internal")
        self.assertEqual(lr, 0.05)


class TestBayesianRiskAssessor(unittest.TestCase):
    """Tests for BayesianRiskAssessor class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.assessor = BayesianRiskAssessor()

    def test_initialization_default_config(self) -> None:
        """Test initialization with default config."""
        assessor = BayesianRiskAssessor()
        self.assertIsNotNone(assessor.config)
        self.assertEqual(assessor.config.network_segmentation, 0.3)

    def test_initialization_custom_config(self) -> None:
        """Test initialization with custom config."""
        config = LikelihoodRatioConfig(network_segmentation=0.5)
        assessor = BayesianRiskAssessor(config)
        self.assertEqual(assessor.config.network_segmentation, 0.5)

    def test_normalize_epss_valid(self) -> None:
        """Test EPSS normalization with valid values."""
        self.assertAlmostEqual(self.assessor._normalize_epss(0.5), 0.5)
        self.assertAlmostEqual(self.assessor._normalize_epss(0.01), 0.01)

    def test_normalize_epss_none(self) -> None:
        """Test EPSS normalization with None."""
        self.assertEqual(self.assessor._normalize_epss(None), 0.01)

    def test_normalize_epss_nan(self) -> None:
        """Test EPSS normalization with NaN."""
        self.assertEqual(self.assessor._normalize_epss(float("nan")), 0.01)

    def test_normalize_epss_percentage(self) -> None:
        """Test EPSS normalization with percentage format."""
        # 50% should be converted to 0.5
        self.assertAlmostEqual(self.assessor._normalize_epss(50.0), 0.5)

    def test_normalize_epss_string(self) -> None:
        """Test EPSS normalization with string values."""
        self.assertEqual(self.assessor._normalize_epss("false"), 0.01)
        self.assertEqual(self.assessor._normalize_epss("none"), 0.01)
        self.assertAlmostEqual(self.assessor._normalize_epss("0.5"), 0.5)

    def test_normalize_epss_clamping(self) -> None:
        """Test EPSS is clamped to valid range."""
        # Should clamp to 0.001 minimum
        self.assertGreaterEqual(self.assessor._normalize_epss(0.0), 0.001)
        # Should clamp to 0.999 maximum
        self.assertLessEqual(self.assessor._normalize_epss(1.0), 0.999)

    def test_prob_to_log_odds(self) -> None:
        """Test probability to log-odds conversion."""
        # p=0.5 should give log-odds of 0
        self.assertAlmostEqual(self.assessor._prob_to_log_odds(0.5), 0.0)
        # p=0.9 should give positive log-odds
        self.assertGreater(self.assessor._prob_to_log_odds(0.9), 0)
        # p=0.1 should give negative log-odds
        self.assertLess(self.assessor._prob_to_log_odds(0.1), 0)

    def test_log_odds_to_prob(self) -> None:
        """Test log-odds to probability conversion."""
        # log-odds=0 should give p=0.5
        self.assertAlmostEqual(self.assessor._log_odds_to_prob(0.0), 0.5)
        # Large positive log-odds should give p close to 1
        self.assertGreater(self.assessor._log_odds_to_prob(10), 0.99)
        # Large negative log-odds should give p close to 0
        self.assertLess(self.assessor._log_odds_to_prob(-10), 0.01)

    def test_prob_log_odds_roundtrip(self) -> None:
        """Test that prob -> log-odds -> prob is identity."""
        for p in [0.1, 0.25, 0.5, 0.75, 0.9]:
            log_odds = self.assessor._prob_to_log_odds(p)
            recovered = self.assessor._log_odds_to_prob(log_odds)
            self.assertAlmostEqual(p, recovered, places=10)


class TestBayesianRiskAssessorAssess(unittest.TestCase):
    """Tests for BayesianRiskAssessor.assess() method."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.assessor = BayesianRiskAssessor()

    def test_assess_basic(self) -> None:
        """Test basic assessment with minimal inputs."""
        result = self.assessor.assess(epss_score=0.1)
        self.assertIsInstance(result, BayesianRiskResult)
        self.assertGreater(result.posterior_probability, 0)
        self.assertLess(result.posterior_probability, 1)

    def test_assess_with_security_controls(self) -> None:
        """Test that security controls reduce risk."""
        # Without controls
        result_no_controls = self.assessor.assess(
            epss_score=0.1,
            exposure="internet-facing",
        )

        # With controls
        controls = SecurityControlsInput(
            network_segmentation=True,
            waf=True,
            mfa=True,
        )
        result_with_controls = self.assessor.assess(
            epss_score=0.1,
            exposure="internet-facing",
            security_controls=controls,
        )

        # Controls should reduce posterior probability
        self.assertLess(
            result_with_controls.posterior_probability,
            result_no_controls.posterior_probability,
        )

    def test_assess_with_threat_indicators(self) -> None:
        """Test that threat indicators increase risk."""
        # Without indicators
        result_no_threats = self.assessor.assess(epss_score=0.05)

        # With KEV indicator
        threats = ThreatIndicatorsInput(is_kev=True)
        result_with_threats = self.assessor.assess(
            epss_score=0.05,
            threat_indicators=threats,
        )

        # KEV should increase posterior probability
        self.assertGreater(
            result_with_threats.posterior_probability,
            result_no_threats.posterior_probability,
        )

    def test_assess_kev_minimum_floor(self) -> None:
        """Test that KEV-listed vulns have minimum floor."""
        threats = ThreatIndicatorsInput(is_kev=True)
        controls = SecurityControlsInput(
            network_segmentation=True,
            waf=True,
            mfa=True,
            edr_xdr=True,
            air_gapped=True,
        )

        result = self.assessor.assess(
            epss_score=0.001,  # Very low EPSS
            security_controls=controls,  # Many controls
            threat_indicators=threats,  # But KEV-listed
        )

        # Should still have minimum floor for KEV
        self.assertGreaterEqual(result.posterior_probability, 0.05)

    def test_assess_exposure_gating(self) -> None:
        """Test that exposure amplification is gated by exploitability."""
        # Low EPSS, no exploits - exposure should be capped
        result_low_epss = self.assessor.assess(
            epss_score=0.001,  # Very low EPSS
            exposure="internet-facing",
        )

        # High EPSS - full exposure amplification
        result_high_epss = self.assessor.assess(
            epss_score=0.1,  # High EPSS
            exposure="internet-facing",
        )

        # The ratio of posterior/prior should be higher for high EPSS
        # because exposure amplification is not gated
        ratio_low = result_low_epss.posterior_probability / 0.001
        ratio_high = result_high_epss.posterior_probability / 0.1

        # High EPSS should have higher amplification ratio
        self.assertGreater(ratio_high, ratio_low)

    def test_assess_cvss_vector(self) -> None:
        """Test CVSS vector parsing and LR application."""
        # Network attack vector should increase risk
        result = self.assessor.assess(
            epss_score=0.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exposure="internet-facing",
        )

        self.assertIsInstance(result, BayesianRiskResult)
        # Should have contributing factors from CVSS
        factor_names = [f[0] for f in result.contributing_factors]
        # At least some CVSS factors should be present
        self.assertTrue(
            any("Attack" in name or "Privilege" in name for name in factor_names)
        )

    def test_assess_risk_categories(self) -> None:
        """Test risk categorization."""
        # Very high risk
        result_critical = self.assessor.assess(
            epss_score=0.9,
            threat_indicators=ThreatIndicatorsInput(is_kev=True, is_weaponized=True),
            exposure="internet-facing",
        )
        self.assertEqual(result_critical.risk_category, "Critical")

        # Very low risk
        result_low = self.assessor.assess(
            epss_score=0.001,
            security_controls=SecurityControlsInput(air_gapped=True),
            exposure="restricted",
        )
        self.assertIn(result_low.risk_category, ["Low", "Negligible"])

    def test_assess_credible_interval(self) -> None:
        """Test credible interval calculation."""
        result = self.assessor.assess(epss_score=0.1)

        # CI low should be <= posterior <= CI high
        self.assertLessEqual(result.credible_interval_low, result.posterior_probability)
        self.assertGreaterEqual(
            result.credible_interval_high, result.posterior_probability
        )

        # Uncertainty should be positive
        self.assertGreater(result.uncertainty, 0)

    def test_assess_dict_controls(self) -> None:
        """Test assessment with dict-based controls."""
        controls = {
            "network_segmentation": True,
            "waf": True,
        }
        result = self.assessor.assess(
            epss_score=0.1,
            security_controls=controls,
        )
        self.assertIsInstance(result, BayesianRiskResult)

    def test_assess_dict_threats(self) -> None:
        """Test assessment with dict-based threat indicators."""
        threats = {
            "is_kev": True,
            "has_public_exploit": True,
        }
        result = self.assessor.assess(
            epss_score=0.1,
            threat_indicators=threats,
        )
        self.assertIsInstance(result, BayesianRiskResult)


class TestBayesianRiskResult(unittest.TestCase):
    """Tests for BayesianRiskResult dataclass."""

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        result = BayesianRiskResult(
            posterior_probability=0.15,
            prior_probability=0.1,
            log_likelihood_ratio=0.5,
            credible_interval_low=0.1,
            credible_interval_high=0.2,
            uncertainty=0.1,
            risk_category="Medium",
            contributing_factors=[("Test", 1.5, "test reason")],
            explanation="Test explanation",
        )

        d = result.to_dict()
        self.assertEqual(d["bayesian_risk_score"], 0.15)
        self.assertEqual(d["prior_epss"], 0.1)
        self.assertEqual(d["risk_category"], "Medium")
        self.assertIn("ci_low", d)
        self.assertIn("ci_high", d)


class TestAssessVulnerabilitiesBayesian(unittest.TestCase):
    """Tests for assess_vulnerabilities_bayesian function."""

    def test_single_row_dataframe(self) -> None:
        """Test with single row DataFrame."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2021-1234"],
                "epss_score": [0.1],
            }
        )
        result = assess_vulnerabilities_bayesian(df)
        self.assertEqual(len(result), 1)
        self.assertIn("bayesian_risk_score", result.columns)

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

        result = assess_vulnerabilities_bayesian(df)

        # Should have new columns
        self.assertIn("bayesian_risk_score", result.columns)
        self.assertIn("risk_category", result.columns)
        self.assertIn("ci_low", result.columns)
        self.assertIn("ci_high", result.columns)

        # Should have same number of rows
        self.assertEqual(len(result), 2)

    def test_with_security_posture(self) -> None:
        """Test with security posture column."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2021-1234"],
                "epss_score": [0.1],
                "cvss_score": [7.5],
                "cvss_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"],
                "exposure": ["internet-facing"],
                "asset_value": ["high"],
                "security_posture": [
                    {
                        "network_segmentation": True,
                        "waf": True,
                        "patch_management": "weekly",
                    }
                ],
            }
        )

        result = assess_vulnerabilities_bayesian(df)
        self.assertIn("bayesian_risk_score", result.columns)

    def test_with_kev_column(self) -> None:
        """Test with KEV indicator column."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2021-1234", "CVE-2021-5678"],
                "epss_score": [0.1, 0.1],
                "cvss_score": [7.5, 7.5],
                "cvss_vector": [
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                ],
                "exposure": ["internet-facing", "internet-facing"],
                "asset_value": ["high", "high"],
                "is_kev": [True, False],
            }
        )

        result = assess_vulnerabilities_bayesian(df)

        # KEV-listed should have higher risk
        kev_risk = result.filter(pl.col("is_kev"))["bayesian_risk_score"][0]
        non_kev_risk = result.filter(~pl.col("is_kev"))["bayesian_risk_score"][0]
        self.assertGreater(kev_risk, non_kev_risk)

    def test_missing_columns_handled(self) -> None:
        """Test that missing optional columns are handled gracefully."""
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2021-1234"],
                "epss_score": [0.1],
                # Missing cvss_vector, exposure, asset_value
            }
        )

        # Should not raise, should use defaults
        result = assess_vulnerabilities_bayesian(
            df,
            cvss_vector_col="cvss_vector",  # Column doesn't exist
            exposure_col="exposure",  # Column doesn't exist
        )
        self.assertIn("bayesian_risk_score", result.columns)


class TestSecurityControlLRConfig(unittest.TestCase):
    """Tests for security control LR values from config."""

    def test_controls_reduce_risk(self) -> None:
        """Test that security controls have LR <= 1."""
        controls = ["network_segmentation", "mfa", "waf", "edr_xdr", "firewall"]
        for control in controls:
            lr = get_control_lr(control)
            self.assertLessEqual(lr, 1.0, f"{control} should reduce risk (LR <= 1)")

    def test_network_segmentation_most_effective(self) -> None:
        """Test that network segmentation is highly effective."""
        self.assertEqual(get_control_lr("network_segmentation"), 0.3)


class TestExposureLRConfig(unittest.TestCase):
    """Tests for exposure LR values from config."""

    def test_internet_facing_increases_risk(self) -> None:
        """Test that internet-facing increases risk."""
        self.assertGreater(get_exposure_lr("internet-facing"), 1.0)

    def test_internal_reduces_risk(self) -> None:
        """Test that internal exposure reduces risk."""
        self.assertLess(get_exposure_lr("internal"), 1.0)


class TestThreatIndicatorLRConfig(unittest.TestCase):
    """Tests for threat indicator LR values from config."""

    def test_indicators_increase_risk(self) -> None:
        """Test that threat indicators have LR > 1."""
        indicators = ["kev_listed", "public_exploit", "metasploit_module", "weaponized"]
        for indicator in indicators:
            lr = get_threat_indicator_lr(indicator)
            self.assertGreater(lr, 1.0, f"{indicator} should increase risk (LR > 1)")

    def test_weaponized_highest_risk(self) -> None:
        """Test that weaponized has highest LR."""
        self.assertEqual(get_threat_indicator_lr("weaponized"), 4.0)


class TestCVSSVectorLR(unittest.TestCase):
    """Tests for CVSSVectorLR class."""

    def test_attack_vector_network(self) -> None:
        """Test network attack vector LRs."""
        self.assertEqual(CVSSVectorLR.ATTACK_VECTOR["N"]["internet"], 2.0)
        self.assertEqual(CVSSVectorLR.ATTACK_VECTOR["N"]["internal"], 1.0)

    def test_attack_complexity(self) -> None:
        """Test attack complexity LRs."""
        self.assertEqual(CVSSVectorLR.ATTACK_COMPLEXITY["L"], 1.5)
        self.assertEqual(CVSSVectorLR.ATTACK_COMPLEXITY["H"], 0.5)

    def test_privileges_required(self) -> None:
        """Test privileges required LRs."""
        self.assertEqual(CVSSVectorLR.PRIVILEGES_REQUIRED["N"], 1.8)
        self.assertEqual(CVSSVectorLR.PRIVILEGES_REQUIRED["H"], 0.5)


if __name__ == "__main__":
    unittest.main()
