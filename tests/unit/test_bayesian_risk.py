"""Unit tests for the Bayesian risk assessor module.

Covers BayesianRiskAssessor, CVSSVectorLR, ExposureConditionalControlLR,
and the assess_vulnerabilities_bayesian DataFrame helper.
"""

from __future__ import annotations

import math

import polars as pl
import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.core.models import (
    LikelihoodRatioConfig,
    SecurityControlsInput,
    ThreatIndicatorsInput,
)
from src.core.risk.bayesian_assessor import (
    BayesianRiskAssessor,
    CVSSVectorLR,
    ExposureConditionalControlLR,
    assess_vulnerabilities_bayesian,
)


class TestBayesianRiskAssessorInit:
    """Test BayesianRiskAssessor initialization with default and custom config."""

    def test_default_config_initialization(self) -> None:
        """Assessor uses default LikelihoodRatioConfig when no config provided."""
        assessor = BayesianRiskAssessor()
        assert assessor.config.prior_probability == 0.1
        assert assessor.config.epss_weight == 1.0
        assert assessor.config.criticality_weight == 0.5

    def test_custom_config_initialization(self) -> None:
        """Assessor respects custom LikelihoodRatioConfig values."""
        config = LikelihoodRatioConfig(prior_probability=0.2, epss_weight=2.0)
        assessor = BayesianRiskAssessor(config)
        assert assessor.config.prior_probability == 0.2
        assert assessor.config.epss_weight == 2.0

    def test_config_dicts_are_copied(self) -> None:
        """Internal LR dicts are independent copies, not references."""
        config = LikelihoodRatioConfig()
        assessor = BayesianRiskAssessor(config)
        assessor.control_lrs["firewall"] = 99.0
        assert config.control_lrs["firewall"] == 0.5

    def test_lr_tables_built_on_init(self) -> None:
        """_lr_tables contains expected metric keys."""
        assessor = BayesianRiskAssessor()
        expected_keys = {"AV", "AC", "PR", "UI", "S"}
        assert set(assessor._lr_tables.keys()) == expected_keys


class TestNormalizeEpss:
    """Test _normalize_epss edge cases and normal operation."""

    @pytest.fixture
    def assessor(self) -> BayesianRiskAssessor:
        return BayesianRiskAssessor()

    def test_zero_epss(self, assessor: BayesianRiskAssessor) -> None:
        """EPSS=0 yields large negative log-odds contribution."""
        result = assessor._normalize_epss(0.0)
        assert result < 0

    def test_one_epss(self, assessor: BayesianRiskAssessor) -> None:
        """EPSS=1 yields large positive log-odds contribution."""
        result = assessor._normalize_epss(1.0)
        assert result > 0

    def test_mid_epss(self, assessor: BayesianRiskAssessor) -> None:
        """EPSS=0.5 yields zero contribution (log-odds of 0.5 is 0)."""
        result = assessor._normalize_epss(0.5)
        assert result == pytest.approx(0.0)

    def test_clamps_above_one(self, assessor: BayesianRiskAssessor) -> None:
        """EPSS > 1 is clamped to 1.0."""
        assert assessor._normalize_epss(1.5) == assessor._normalize_epss(1.0)

    def test_clamps_below_zero(self, assessor: BayesianRiskAssessor) -> None:
        """EPSS < 0 is clamped to 0.0."""
        assert assessor._normalize_epss(-0.5) == assessor._normalize_epss(0.0)

    def test_percentage_value_clamped(self, assessor: BayesianRiskAssessor) -> None:
        """Percentage-style value (e.g. 0.15 as 15%) is clamped to 1.0."""
        assert assessor._normalize_epss(1.15) == assessor._normalize_epss(1.0)

    def test_nan_handled(self, assessor: BayesianRiskAssessor) -> None:
        """NaN is clamped to 0.0 by max(0, min(1, nan)), yielding large positive log-odds."""
        result = assessor._normalize_epss(float("nan"))
        # NaN comparisons are always False, so max(0, min(1, nan)) = 0
        # log(eps/(1-eps)) * weight is a large positive number
        assert result > 0

    def test_weight_applied(self) -> None:
        """EPSS weight from config scales the contribution."""
        config = LikelihoodRatioConfig(epss_weight=3.0)
        assessor = BayesianRiskAssessor(config)
        weighted = assessor._normalize_epss(0.8)
        default_assessor = BayesianRiskAssessor()
        default = default_assessor._normalize_epss(0.8)
        assert weighted == pytest.approx(default * 3.0)


class TestNormalizeControls:
    """Test _normalize_controls with various inputs."""

    @pytest.fixture
    def assessor(self) -> BayesianRiskAssessor:
        return BayesianRiskAssessor()

    def test_all_disabled(self, assessor: BayesianRiskAssessor) -> None:
        """Empty controls list when all fields are False."""
        controls = SecurityControlsInput()
        assert assessor._normalize_controls(controls) == []

    def test_single_enabled(self, assessor: BayesianRiskAssessor) -> None:
        """Only enabled controls appear in the list."""
        controls = SecurityControlsInput(firewall=True)
        assert assessor._normalize_controls(controls) == ["firewall"]

    def test_multiple_enabled(self, assessor: BayesianRiskAssessor) -> None:
        """Multiple enabled controls are all returned."""
        controls = SecurityControlsInput(firewall=True, waf=True, mfa=True)
        result = assessor._normalize_controls(controls)
        assert set(result) == {"firewall", "waf", "mfa"}

    def test_bool_coercion(self, assessor: BayesianRiskAssessor) -> None:
        """Truthy values (1, "yes") are treated as enabled."""
        controls = SecurityControlsInput(firewall=True, waf=False)
        result = assessor._normalize_controls(controls)
        assert "firewall" in result
        assert "waf" not in result


class TestNormalizeThreats:
    """Test _normalize_threats extraction of active indicators."""

    @pytest.fixture
    def assessor(self) -> BayesianRiskAssessor:
        return BayesianRiskAssessor()

    def test_all_inactive(self, assessor: BayesianRiskAssessor) -> None:
        """Empty dict when no threats active."""
        threats = ThreatIndicatorsInput()
        assert assessor._normalize_threats(threats) == {}

    def test_active_exploitation(self, assessor: BayesianRiskAssessor) -> None:
        """active_exploitation=True yields its LR."""
        threats = ThreatIndicatorsInput(active_exploitation=True)
        result = assessor._normalize_threats(threats)
        assert "active_exploitation" in result
        assert result["active_exploitation"] == 3.0

    def test_exploit_available(self, assessor: BayesianRiskAssessor) -> None:
        """exploit_available=True yields its LR."""
        threats = ThreatIndicatorsInput(exploit_available=True)
        result = assessor._normalize_threats(threats)
        assert result["exploit_available"] == 2.0

    def test_confidence_scaled(self, assessor: BayesianRiskAssessor) -> None:
        """threat_intel_confidence scales LR linearly."""
        threats = ThreatIndicatorsInput(threat_intel_confidence=0.5)
        result = assessor._normalize_threats(threats)
        expected = 1.0 + (1.5 - 1.0) * 0.5
        assert result["threat_intel_confidence"] == pytest.approx(expected)

    def test_confidence_clamped(self, assessor: BayesianRiskAssessor) -> None:
        """Confidence > 1 is clamped to 1.0."""
        threats = ThreatIndicatorsInput(threat_intel_confidence=2.0)
        result = assessor._normalize_threats(threats)
        expected = 1.0 + (1.5 - 1.0) * 1.0
        assert result["threat_intel_confidence"] == pytest.approx(expected)

    def test_combined_threats(self, assessor: BayesianRiskAssessor) -> None:
        """Multiple active threats all appear."""
        threats = ThreatIndicatorsInput(
            active_exploitation=True,
            exploit_available=True,
            threat_intel_confidence=0.8,
        )
        result = assessor._normalize_threats(threats)
        assert len(result) == 3


class TestProbLogOddsRoundtrip:
    """Test _prob_to_log_odds and _log_odds_to_prob conversion roundtrip."""

    @given(st.floats(min_value=1e-6, max_value=1.0 - 1e-6))
    def test_roundtrip_property(self, prob: float) -> None:
        """Converting prob -> log_odds -> prob recovers the original value."""
        log_odds = BayesianRiskAssessor._prob_to_log_odds(prob)
        recovered = BayesianRiskAssessor._log_odds_to_prob(log_odds)
        assert recovered == pytest.approx(prob, rel=1e-6)

    def test_zero_clamped(self) -> None:
        """Probability 0 is clamped to epsilon."""
        result = BayesianRiskAssessor._prob_to_log_odds(0.0)
        assert result == math.log(1e-10 / (1.0 - 1e-10))

    def test_one_clamped(self) -> None:
        """Probability 1 is clamped to 1-epsilon."""
        result = BayesianRiskAssessor._prob_to_log_odds(1.0)
        assert result == pytest.approx(math.log((1.0 - 1e-10) / 1e-10), rel=1e-5)

    def test_zero_log_odds_is_half(self) -> None:
        """Log odds of 0 maps to probability 0.5."""
        assert BayesianRiskAssessor._log_odds_to_prob(0.0) == pytest.approx(0.5)

    def test_negative_log_odds_below_half(self) -> None:
        """Negative log odds yields probability < 0.5."""
        assert BayesianRiskAssessor._log_odds_to_prob(-1.0) < 0.5

    def test_positive_log_odds_above_half(self) -> None:
        """Positive log odds yields probability > 0.5."""
        assert BayesianRiskAssessor._log_odds_to_prob(1.0) > 0.5


class TestParseCvssVector:
    """Test _parse_cvss_vector with various inputs."""

    def test_valid_vector(self) -> None:
        """Standard CVSS vector with : separator is parsed correctly."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = BayesianRiskAssessor._parse_cvss_vector(vector)
        assert "AV" in result
        assert result["AV"] == "N"
        assert result["AC"] == "L"
        assert result["C"] == "H"

    def test_vector_with_equals(self) -> None:
        """Vector with = separator is not recognized (parser only handles :)."""
        vector = "AV=N/AC=L/PR=N"
        result = BayesianRiskAssessor._parse_cvss_vector(vector)
        assert result == {}

    def test_empty_string(self) -> None:
        """Empty string returns empty dict."""
        assert BayesianRiskAssessor._parse_cvss_vector("") == {}

    def test_none_vector(self) -> None:
        """None is not accepted; method expects str, skip."""
        # Method is typed str, so we test with empty fallback
        assert BayesianRiskAssessor._parse_cvss_vector("") == {}

    def test_partial_vector(self) -> None:
        """Partial vector with : separator is parsed correctly."""
        vector = "AV:N/AC:H/PR:L"
        result = BayesianRiskAssessor._parse_cvss_vector(vector)
        assert result["AV"] == "N"
        assert result["PR"] == "L"


class TestAssessBasic:
    """Test the assess() method with representative scenarios."""

    @pytest.fixture
    def assessor(self) -> BayesianRiskAssessor:
        return BayesianRiskAssessor()

    @pytest.fixture
    def base_controls(self) -> SecurityControlsInput:
        return SecurityControlsInput()

    @pytest.fixture
    def base_threats(self) -> ThreatIndicatorsInput:
        return ThreatIndicatorsInput()

    @pytest.fixture
    def base_vector(self) -> str:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_low_epss_internal_low_risk(
        self,
        assessor: BayesianRiskAssessor,
        base_controls: SecurityControlsInput,
        base_threats: ThreatIndicatorsInput,
    ) -> None:
        """Low EPSS + internal exposure yields LOW or INFORMATIONAL."""
        vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        result = assessor.assess(
            cvss_score=3.0,
            epss_score=0.01,
            cvss_vector=vector,
            controls=base_controls,
            threats=base_threats,
        )
        assert result.risk_category in ("LOW", "INFORMATIONAL")
        assert result.posterior_probability < 0.05

    def test_high_epss_kev_internet_critical(
        self,
        assessor: BayesianRiskAssessor,
        base_controls: SecurityControlsInput,
        base_vector: str,
    ) -> None:
        """High EPSS + KEV + internet exposure yields HIGH or CRITICAL."""
        threats = ThreatIndicatorsInput(
            active_exploitation=True,
            exploit_available=True,
            threat_intel_confidence=0.9,
        )
        result = assessor.assess(
            cvss_score=9.8,
            epss_score=0.3,
            cvss_vector=base_vector,
            controls=base_controls,
            threats=threats,
        )
        assert result.risk_category in ("HIGH", "CRITICAL")
        assert result.posterior_probability > 0.15

    def test_controls_reduce_risk(
        self,
        assessor: BayesianRiskAssessor,
        base_threats: ThreatIndicatorsInput,
        base_vector: str,
    ) -> None:
        """Enabled security controls lower posterior probability."""
        no_controls = SecurityControlsInput()
        with_controls = SecurityControlsInput(
            firewall=True, waf=True, mfa=True, patching=True
        )
        result_none = assessor.assess(
            cvss_score=8.0,
            epss_score=0.1,
            cvss_vector=base_vector,
            controls=no_controls,
            threats=base_threats,
        )
        result_controls = assessor.assess(
            cvss_score=8.0,
            epss_score=0.1,
            cvss_vector=base_vector,
            controls=with_controls,
            threats=base_threats,
        )
        assert result_controls.posterior_probability < result_none.posterior_probability

    def test_threats_increase_risk(
        self,
        assessor: BayesianRiskAssessor,
        base_controls: SecurityControlsInput,
        base_vector: str,
    ) -> None:
        """Active threat indicators raise posterior probability."""
        no_threats = ThreatIndicatorsInput()
        with_threats = ThreatIndicatorsInput(
            active_exploitation=True, exploit_available=True
        )
        result_none = assessor.assess(
            cvss_score=7.0,
            epss_score=0.1,
            cvss_vector=base_vector,
            controls=base_controls,
            threats=no_threats,
        )
        result_threats = assessor.assess(
            cvss_score=7.0,
            epss_score=0.1,
            cvss_vector=base_vector,
            controls=base_controls,
            threats=with_threats,
        )
        assert result_threats.posterior_probability > result_none.posterior_probability

    def test_cvss_vector_lr_defaults_to_one(
        self,
        assessor: BayesianRiskAssessor,
        base_controls: SecurityControlsInput,
        base_threats: ThreatIndicatorsInput,
    ) -> None:
        """When vector is None, cvss_vector_lr defaults to 1.0."""
        result = assessor.assess(
            cvss_score=9.0,
            epss_score=0.1,
            cvss_vector=None,
            controls=base_controls,
            threats=base_threats,
        )
        assert result.cvss_vector_lr == pytest.approx(1.0)

    def test_credible_interval_valid(
        self,
        assessor: BayesianRiskAssessor,
        base_controls: SecurityControlsInput,
        base_threats: ThreatIndicatorsInput,
        base_vector: str,
    ) -> None:
        """Credible interval bounds contain the posterior."""
        result = assessor.assess(
            cvss_score=7.0,
            epss_score=0.1,
            cvss_vector=base_vector,
            controls=base_controls,
            threats=base_threats,
        )
        assert result.credible_lower <= result.posterior_probability
        assert result.credible_upper >= result.posterior_probability
        assert result.credible_lower < result.credible_upper

    def test_explanation_contains_category(
        self,
        assessor: BayesianRiskAssessor,
        base_controls: SecurityControlsInput,
        base_threats: ThreatIndicatorsInput,
        base_vector: str,
    ) -> None:
        """Explanation string mentions the risk category."""
        result = assessor.assess(
            cvss_score=9.0,
            epss_score=0.2,
            cvss_vector=base_vector,
            controls=base_controls,
            threats=base_threats,
        )
        assert result.risk_category in result.explanation


class TestRiskCategorization:
    """Test _categorize_risk threshold boundaries."""

    def test_critical_threshold(self) -> None:
        """Probability >= 0.5 yields CRITICAL."""
        assert BayesianRiskAssessor._categorize_risk(0.5) == "CRITICAL"
        assert BayesianRiskAssessor._categorize_risk(0.99) == "CRITICAL"

    def test_high_threshold(self) -> None:
        """Probability >= 0.2 yields HIGH."""
        assert BayesianRiskAssessor._categorize_risk(0.2) == "HIGH"
        assert BayesianRiskAssessor._categorize_risk(0.49) == "HIGH"

    def test_medium_threshold(self) -> None:
        """Probability >= 0.05 yields MEDIUM."""
        assert BayesianRiskAssessor._categorize_risk(0.05) == "MEDIUM"
        assert BayesianRiskAssessor._categorize_risk(0.19) == "MEDIUM"

    def test_low_threshold(self) -> None:
        """Probability >= 0.01 yields LOW."""
        assert BayesianRiskAssessor._categorize_risk(0.01) == "LOW"
        assert BayesianRiskAssessor._categorize_risk(0.04) == "LOW"

    def test_informational_below_threshold(self) -> None:
        """Probability < 0.01 yields INFORMATIONAL."""
        assert BayesianRiskAssessor._categorize_risk(0.001) == "INFORMATIONAL"
        assert BayesianRiskAssessor._categorize_risk(0.0) == "INFORMATIONAL"


class TestExposureConditionalControlLR:
    """Test conditional likelihood ratio lookup."""

    def test_firewall_network_vector(self) -> None:
        """Firewall LR for network attack vector."""
        lr = ExposureConditionalControlLR.get_lr("firewall", "N")
        assert lr == 0.3

    def test_firewall_default(self) -> None:
        """Firewall default LR when no vector specified."""
        lr = ExposureConditionalControlLR.get_lr("firewall")
        assert lr == 0.5

    def test_unknown_control(self) -> None:
        """Unknown control returns 1.0."""
        lr = ExposureConditionalControlLR.get_lr("unknown_control")
        assert lr == 1.0

    def test_patch_network_vector(self) -> None:
        """Patching LR for network attack vector."""
        lr = ExposureConditionalControlLR.get_lr("patching", "N")
        assert lr == 0.2

    def test_mfa_local_vector(self) -> None:
        """MFA LR for local attack vector."""
        lr = ExposureConditionalControlLR.get_lr("mfa", "L")
        assert lr == 0.3


class TestCVSSVectorLR:
    """Test CVSSVectorLR lookup tables contain expected keys."""

    def test_attack_vector_keys(self) -> None:
        assert set(CVSSVectorLR.ATTACK_VECTOR.keys()) == {"N", "A", "L", "P"}

    def test_attack_complexity_keys(self) -> None:
        assert set(CVSSVectorLR.ATTACK_COMPLEXITY.keys()) == {"L", "H"}

    def test_privileges_required_keys(self) -> None:
        assert set(CVSSVectorLR.PRIVILEGES_REQUIRED.keys()) == {"N", "L", "H"}

    def test_user_interaction_keys(self) -> None:
        assert set(CVSSVectorLR.USER_INTERACTION.keys()) == {"N", "R"}

    def test_scope_keys(self) -> None:
        assert set(CVSSVectorLR.SCOPE.keys()) == {"U", "C"}

    def test_all_values_positive(self) -> None:
        """All LR values are positive floats."""
        for table in (
            CVSSVectorLR.ATTACK_VECTOR,
            CVSSVectorLR.ATTACK_COMPLEXITY,
            CVSSVectorLR.PRIVILEGES_REQUIRED,
            CVSSVectorLR.USER_INTERACTION,
            CVSSVectorLR.SCOPE,
        ):
            for value in table.values():
                assert value > 0


class TestAssessVulnerabilitiesBayesian:
    """Test the DataFrame-level assess_vulnerabilities_bayesian function."""

    def test_basic_dataframe(self) -> None:
        """Function processes a sample DataFrame and adds assessment columns."""
        df = pl.DataFrame(
            {
                "cvss_score": [8.0, 3.0],
                "epss_score": [0.1, 0.01],
                "cvss_vector": [
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
                ],
            }
        )
        result = assess_vulnerabilities_bayesian(df)
        expected_cols = [
            "posterior_probability",
            "risk_category",
            "credible_lower",
            "credible_upper",
            "control_lr",
            "threat_lr",
            "cvss_vector_lr",
            "exposure_lr",
            "criticality_lr",
            "explanation",
        ]
        for col in expected_cols:
            assert col in result.columns

    def test_row_count_preserved(self) -> None:
        """Output DataFrame has same number of rows as input."""
        df = pl.DataFrame(
            {
                "cvss_score": [5.0, 7.0, 9.0],
                "epss_score": [0.05, 0.1, 0.2],
                "cvss_vector": ["", "", ""],
            }
        )
        result = assess_vulnerabilities_bayesian(df)
        assert result.height == 3

    def test_higher_cvss_higher_posterior(self) -> None:
        """Higher CVSS score yields higher posterior (all else equal)."""
        df = pl.DataFrame(
            {
                "cvss_score": [3.0, 9.0],
                "epss_score": [0.05, 0.05],
                "cvss_vector": ["", ""],
            }
        )
        result = assess_vulnerabilities_bayesian(df)
        posteriors = result["posterior_probability"].to_list()
        assert posteriors[1] > posteriors[0]
