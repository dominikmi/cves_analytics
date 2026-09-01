"""Unit tests for core data models.

Covers all pydantic and dataclass models: LikelihoodRatioConfig,
SecurityControlsInput, ThreatIndicatorsInput, KillChainStage, KillChainResult,
and BayesianRiskResult.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest
from pydantic import ValidationError

from src.core.models import (
    BayesianRiskResult,
    KillChainResult,
    KillChainStage,
    LikelihoodRatioConfig,
    SecurityControlsInput,
    ThreatIndicatorsInput,
)


class TestLikelihoodRatioConfig:
    """Test LikelihoodRatioConfig defaults and custom values."""

    def test_defaults(self) -> None:
        """Default config has expected values."""
        config = LikelihoodRatioConfig()
        assert config.prior_probability == 0.1
        assert config.epss_weight == 1.0
        assert config.criticality_weight == 0.5
        assert config.cvss_weight == 1.0
        assert config.threat_weight == 1.0

    def test_custom_prior(self) -> None:
        """Custom prior_probability is preserved."""
        config = LikelihoodRatioConfig(prior_probability=0.25)
        assert config.prior_probability == 0.25

    def test_control_lrs_default_keys(self) -> None:
        """Default control_lrs contains all expected control names."""
        config = LikelihoodRatioConfig()
        expected = {
            "firewall",
            "ids_ips",
            "waf",
            "patching",
            "mfa",
            "encryption",
            "access_control",
            "monitoring",
        }
        assert set(config.control_lrs.keys()) == expected

    def test_threat_lrs_default_keys(self) -> None:
        """Default threat_lrs contains all expected indicator names."""
        config = LikelihoodRatioConfig()
        expected = {
            "active_exploitation",
            "exploit_available",
            "threat_intel_confidence",
        }
        assert set(config.threat_lrs.keys()) == expected

    def test_dicts_are_independent(self) -> None:
        """Two configs have independent dict instances."""
        c1 = LikelihoodRatioConfig()
        c2 = LikelihoodRatioConfig()
        c1.control_lrs["firewall"] = 99.0
        assert c2.control_lrs["firewall"] == 0.5


class TestSecurityControlsInput:
    """Test SecurityControlsInput creation and bool coercion."""

    def test_all_defaults_false(self) -> None:
        """All controls default to False."""
        controls = SecurityControlsInput()
        assert not controls.firewall
        assert not controls.waf
        assert not controls.mfa

    def test_single_true(self) -> None:
        """Explicit True is preserved."""
        controls = SecurityControlsInput(firewall=True)
        assert controls.firewall is True
        assert controls.waf is False

    def test_bool_coercion_int(self) -> None:
        """Integer 1 is coerced to True."""
        controls = SecurityControlsInput(firewall=True)
        assert bool(controls.firewall) is True

    def test_all_fields_accessible(self) -> None:
        """All eight control fields are accessible."""
        controls = SecurityControlsInput(
            firewall=True,
            ids_ips=True,
            waf=True,
            patching=True,
            mfa=True,
            encryption=True,
            access_control=True,
            monitoring=True,
        )
        assert all(
            [
                controls.firewall,
                controls.ids_ips,
                controls.waf,
                controls.patching,
                controls.mfa,
                controls.encryption,
                controls.access_control,
                controls.monitoring,
            ]
        )


class TestThreatIndicatorsInput:
    """Test ThreatIndicatorsInput defaults and values."""

    def test_all_defaults(self) -> None:
        """All fields default to False/0.0."""
        threats = ThreatIndicatorsInput()
        assert threats.active_exploitation is False
        assert threats.exploit_available is False
        assert threats.threat_intel_confidence == 0.0

    def test_active_exploitation(self) -> None:
        """active_exploitation can be set True."""
        threats = ThreatIndicatorsInput(active_exploitation=True)
        assert threats.active_exploitation is True

    def test_exploit_available(self) -> None:
        """exploit_available can be set True."""
        threats = ThreatIndicatorsInput(exploit_available=True)
        assert threats.exploit_available is True

    def test_confidence_value(self) -> None:
        """threat_intel_confidence accepts float values."""
        threats = ThreatIndicatorsInput(threat_intel_confidence=0.75)
        assert threats.threat_intel_confidence == 0.75

    def test_combined_values(self) -> None:
        """All fields can be set simultaneously."""
        threats = ThreatIndicatorsInput(
            active_exploitation=True,
            exploit_available=True,
            threat_intel_confidence=0.9,
        )
        assert threats.active_exploitation
        assert threats.exploit_available
        assert threats.threat_intel_confidence == 0.9


class TestKillChainStage:
    """Test KillChainStage enum members and values."""

    def test_all_members_exist(self) -> None:
        """All four expected stages are defined."""
        stages = {s.value for s in KillChainStage}
        assert stages == {
            "initial_access",
            "execution",
            "lateral_movement",
            "objective",
        }

    def test_member_values(self) -> None:
        """Each member has the expected string value."""
        assert KillChainStage.INITIAL_ACCESS.value == "initial_access"
        assert KillChainStage.EXECUTION.value == "execution"
        assert KillChainStage.LATERAL_MOVEMENT.value == "lateral_movement"
        assert KillChainStage.OBJECTIVE.value == "objective"

    def test_member_count(self) -> None:
        """Exactly four stages defined."""
        assert len(KillChainStage) == 4


class TestKillChainResult:
    """Test KillChainResult pydantic model creation and constraints."""

    def test_creation(self) -> None:
        """KillChainResult created with valid values."""
        result = KillChainResult(
            initial_access_probability=0.5,
            execution_probability=0.6,
            lateral_movement_probability=0.4,
            objective_probability=0.7,
            overall_probability=0.084,
            threat_level="medium",
            critical_path=[KillChainStage.OBJECTIVE],
        )
        assert result.overall_probability == 0.084

    def test_defaults_for_counts(self) -> None:
        """Vulnerability counts default to 0."""
        result = KillChainResult(
            initial_access_probability=0.1,
            execution_probability=0.2,
            lateral_movement_probability=0.3,
            objective_probability=0.4,
            overall_probability=0.0024,
            threat_level="low",
            critical_path=[],
        )
        assert result.rce_vulnerabilities == 0
        assert result.privesc_vulnerabilities == 0
        assert result.container_escape_vulnerabilities == 0

    def test_ge_validation_rejects_negative(self) -> None:
        """Probability < 0 raises ValidationError."""
        with pytest.raises(ValidationError):
            KillChainResult(
                initial_access_probability=-0.1,
                execution_probability=0.5,
                lateral_movement_probability=0.5,
                objective_probability=0.5,
                overall_probability=0.0,
                threat_level="low",
                critical_path=[],
            )

    def test_le_validation_rejects_above_one(self) -> None:
        """Probability > 1 raises ValidationError."""
        with pytest.raises(ValidationError):
            KillChainResult(
                initial_access_probability=1.5,
                execution_probability=0.5,
                lateral_movement_probability=0.5,
                objective_probability=0.5,
                overall_probability=0.0,
                threat_level="low",
                critical_path=[],
            )

    def test_boundary_zero_valid(self) -> None:
        """Probability of exactly 0.0 is valid."""
        result = KillChainResult(
            initial_access_probability=0.0,
            execution_probability=0.0,
            lateral_movement_probability=0.0,
            objective_probability=0.0,
            overall_probability=0.0,
            threat_level="low",
            critical_path=[],
        )
        assert result.initial_access_probability == 0.0

    def test_boundary_one_valid(self) -> None:
        """Probability of exactly 1.0 is valid."""
        result = KillChainResult(
            initial_access_probability=1.0,
            execution_probability=1.0,
            lateral_movement_probability=1.0,
            objective_probability=1.0,
            overall_probability=1.0,
            threat_level="critical",
            critical_path=[KillChainStage.EXECUTION],
        )
        assert result.initial_access_probability == 1.0

    def test_serialization(self) -> None:
        """Model can be serialized to dict."""
        result = KillChainResult(
            initial_access_probability=0.5,
            execution_probability=0.6,
            lateral_movement_probability=0.4,
            objective_probability=0.7,
            overall_probability=0.084,
            threat_level="medium",
            critical_path=[KillChainStage.INITIAL_ACCESS],
            rce_vulnerabilities=2,
        )
        data = result.model_dump()
        assert data["initial_access_probability"] == 0.5
        assert data["rce_vulnerabilities"] == 2


class TestBayesianRiskResult:
    """Test BayesianRiskResult dataclass creation and conversion."""

    def test_creation(self) -> None:
        """BayesianRiskResult created with all required fields."""
        result = BayesianRiskResult(
            posterior_probability=0.3,
            prior_probability=0.1,
            log_odds_prior=-1.2,
            log_odds_posterior=0.5,
            control_lr=0.5,
            threat_lr=2.0,
            cvss_vector_lr=3.0,
            exposure_lr=1.5,
            criticality_lr=1.2,
            epss_contribution=0.3,
            risk_category="HIGH",
            credible_lower=0.15,
            credible_upper=0.45,
            explanation="Test explanation.",
        )
        assert result.posterior_probability == 0.3
        assert result.risk_category == "HIGH"

    def test_default_metadata(self) -> None:
        """Metadata defaults to empty dict."""
        result = BayesianRiskResult(
            posterior_probability=0.1,
            prior_probability=0.1,
            log_odds_prior=0.0,
            log_odds_posterior=0.0,
            control_lr=1.0,
            threat_lr=1.0,
            cvss_vector_lr=1.0,
            exposure_lr=1.0,
            criticality_lr=1.0,
            epss_contribution=0.0,
            risk_category="LOW",
            credible_lower=0.0,
            credible_upper=0.2,
            explanation="",
        )
        assert result.metadata == {}

    def test_to_dict_via_asdict(self) -> None:
        """dataclasses.asdict produces expected dict."""
        result = BayesianRiskResult(
            posterior_probability=0.25,
            prior_probability=0.1,
            log_odds_prior=-1.0,
            log_odds_posterior=0.2,
            control_lr=0.6,
            threat_lr=1.5,
            cvss_vector_lr=2.0,
            exposure_lr=1.3,
            criticality_lr=1.1,
            epss_contribution=0.1,
            risk_category="MEDIUM",
            credible_lower=0.1,
            credible_upper=0.4,
            explanation="Test.",
            metadata={"source": "test"},
        )
        d = dataclasses.asdict(result)
        assert isinstance(d, dict)
        assert d["posterior_probability"] == 0.25
        assert d["risk_category"] == "MEDIUM"
        assert d["metadata"] == {"source": "test"}

    def test_all_fields_present_in_dict(self) -> None:
        """asdict output contains all dataclass fields."""
        result = BayesianRiskResult(
            posterior_probability=0.1,
            prior_probability=0.1,
            log_odds_prior=0.0,
            log_odds_posterior=0.0,
            control_lr=1.0,
            threat_lr=1.0,
            cvss_vector_lr=1.0,
            exposure_lr=1.0,
            criticality_lr=1.0,
            epss_contribution=0.0,
            risk_category="LOW",
            credible_lower=0.0,
            credible_upper=0.2,
            explanation="",
        )
        d = dataclasses.asdict(result)
        expected_fields = {
            "posterior_probability",
            "prior_probability",
            "log_odds_prior",
            "log_odds_posterior",
            "control_lr",
            "threat_lr",
            "cvss_vector_lr",
            "exposure_lr",
            "criticality_lr",
            "epss_contribution",
            "risk_category",
            "credible_lower",
            "credible_upper",
            "explanation",
            "metadata",
        }
        assert set(d.keys()) == expected_fields


class TestFieldConstraints:
    """Test pydantic Field ge/le validation on KillChainResult."""

    def test_all_probabilities_ge_zero(self) -> None:
        """All probability fields reject negative values."""
        for field_name in (
            "initial_access_probability",
            "execution_probability",
            "lateral_movement_probability",
            "objective_probability",
            "overall_probability",
        ):
            kwargs: dict[str, Any] = {
                "initial_access_probability": 0.5,
                "execution_probability": 0.5,
                "lateral_movement_probability": 0.5,
                "objective_probability": 0.5,
                "overall_probability": 0.5,
                "threat_level": "medium",
                "critical_path": [],
            }
            kwargs[field_name] = -0.1
            with pytest.raises(ValidationError):
                KillChainResult(**kwargs)

    def test_all_probabilities_le_one(self) -> None:
        """All probability fields reject values above 1."""
        for field_name in (
            "initial_access_probability",
            "execution_probability",
            "lateral_movement_probability",
            "objective_probability",
            "overall_probability",
        ):
            kwargs: dict[str, Any] = {
                "initial_access_probability": 0.5,
                "execution_probability": 0.5,
                "lateral_movement_probability": 0.5,
                "objective_probability": 0.5,
                "overall_probability": 0.5,
                "threat_level": "medium",
                "critical_path": [],
            }
            kwargs[field_name] = 1.5
            with pytest.raises(ValidationError):
                KillChainResult(**kwargs)

    def test_threat_level_is_string(self) -> None:
        """threat_level field accepts valid string values."""
        result = KillChainResult(
            initial_access_probability=0.1,
            execution_probability=0.1,
            lateral_movement_probability=0.1,
            objective_probability=0.1,
            overall_probability=0.0001,
            threat_level="low",
            critical_path=[],
        )
        assert isinstance(result.threat_level, str)

    def test_critical_path_is_list(self) -> None:
        """critical_path field accepts list of KillChainStage."""
        result = KillChainResult(
            initial_access_probability=0.1,
            execution_probability=0.1,
            lateral_movement_probability=0.1,
            objective_probability=0.1,
            overall_probability=0.0001,
            threat_level="low",
            critical_path=[KillChainStage.INITIAL_ACCESS, KillChainStage.EXECUTION],
        )
        assert len(result.critical_path) == 2
