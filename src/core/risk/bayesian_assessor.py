"""Bayesian risk assessment for CVE vulnerabilities.

Pure-function based Bayesian risk calculator with no external dependencies
beyond math, typing, numpy, and pydantic.
"""

from __future__ import annotations

import math
from typing import Any

import polars as pl

from src.core.models import (
    BayesianRiskResult,
    LikelihoodRatioConfig,
    SecurityControlsInput,
    ThreatIndicatorsInput,
)


class CVSSVectorLR:
    """Likelihood ratio lookup tables for CVSS v3.x vector components."""

    ATTACK_VECTOR: dict[str, float] = {
        "N": 1.8,
        "A": 1.3,
        "L": 0.7,
        "P": 0.4,
    }

    ATTACK_COMPLEXITY: dict[str, float] = {
        "L": 1.6,
        "H": 0.5,
    }

    PRIVILEGES_REQUIRED: dict[str, float] = {
        "N": 1.7,
        "L": 1.1,
        "H": 0.4,
    }

    USER_INTERACTION: dict[str, float] = {
        "N": 1.5,
        "R": 0.6,
    }

    SCOPE: dict[str, float] = {
        "U": 0.8,
        "C": 1.4,
    }


class ExposureConditionalControlLR:
    """Conditional likelihood ratios for security controls given exposure context."""

    CONDITIONAL_LRS: dict[str, dict[str, float]] = {
        "firewall": {"N": 0.3, "A": 0.4, "L": 0.8, "P": 0.9},
        "ids_ips": {"N": 0.4, "A": 0.5, "L": 0.7, "P": 0.9},
        "waf": {"N": 0.3, "A": 0.5, "L": 0.8, "P": 0.95},
        "patching": {"N": 0.2, "A": 0.3, "L": 0.5, "P": 0.7},
        "mfa": {"N": 0.5, "A": 0.5, "L": 0.3, "P": 0.4},
        "encryption": {"N": 0.8, "A": 0.8, "L": 0.6, "P": 0.5},
        "access_control": {"N": 0.6, "A": 0.6, "L": 0.4, "P": 0.3},
        "monitoring": {"N": 0.7, "A": 0.6, "L": 0.5, "P": 0.5},
    }

    DEFAULT_LRS: dict[str, float] = {
        "firewall": 0.5,
        "ids_ips": 0.6,
        "waf": 0.5,
        "patching": 0.3,
        "mfa": 0.4,
        "encryption": 0.7,
        "access_control": 0.5,
        "monitoring": 0.6,
    }

    @classmethod
    def get_lr(cls, control: str, attack_vector: str | None = None) -> float:
        """Return the likelihood ratio for a control, conditional on attack vector.

        Args:
            control: Control name key.
            attack_vector: CVSS attack vector code (N/A/L/P). Falls back to
                default LR when absent or unmatched.

        Returns:
            Likelihood ratio value for the control.
        """
        if attack_vector and control in cls.CONDITIONAL_LRS:
            return cls.CONDITIONAL_LRS[control].get(
                attack_vector, cls.DEFAULT_LRS.get(control, 1.0)
            )
        return cls.DEFAULT_LRS.get(control, 1.0)


class BayesianRiskAssessor:
    """Bayesian risk assessor combining CVSS, EPSS, controls, and threat intelligence.

    Computes a posterior exploitation probability by updating a prior with
    likelihood ratios from multiple evidence sources.
    """

    def __init__(self, config: LikelihoodRatioConfig | None = None) -> None:
        """Initialize the assessor with optional configuration.

        Args:
            config: Likelihood ratio configuration. Uses sensible defaults when
                None.
        """
        self.config = config or LikelihoodRatioConfig()
        self.control_lrs = dict(self.config.control_lrs)
        self.threat_lrs = dict(self.config.threat_lrs)
        self._lr_tables = self._build_lr_tables()

    def assess(
        self,
        cvss_score: float,
        epss_score: float,
        cvss_vector: str,
        controls: SecurityControlsInput,
        threats: ThreatIndicatorsInput,
        asset_criticality: float = 0.5,
        nlp_features: dict[str, float] | None = None,
    ) -> BayesianRiskResult:
        """Compute a full Bayesian risk assessment.

        Updates the prior probability with likelihood ratios from security
        controls, threat indicators, CVSS vector components, EPSS, and asset
        criticality.

        Args:
            cvss_score: Base CVSS v3.x score in [0, 10].
            epss_score: EPSS exploitation probability in [0, 1].
            cvss_vector: Full CVSS vector string (e.g.
                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').
            controls: Enabled security controls on the target asset.
            threats: Observed threat intelligence indicators.
            asset_criticality: Normalized criticality of the affected asset
                in [0, 1].
            nlp_features: Optional NLP-derived feature scores for additional
                signal weighting.

        Returns:
            BayesianRiskResult with posterior probability, component LRs,
            credible interval, risk category, and explanation.
        """
        prior = self.config.prior_probability
        log_odds = self._prob_to_log_odds(prior)

        control_lr = self._apply_control_lrs(controls, cvss_vector)
        threat_lr = self._apply_threat_lrs(threats)
        cvss_lr = self._apply_cvss_vector_lrs(cvss_vector)
        exposure_lr = self._get_gated_exposure_lr(cvss_score, controls)
        criticality_lr = self._get_gated_criticality_lr(asset_criticality)
        epss_contrib = self._normalize_epss(epss_score)

        nlp_lr = self._apply_nlp_features(nlp_features)

        log_odds += math.log(control_lr) if control_lr > 0 else -50
        log_odds += math.log(threat_lr) if threat_lr > 0 else -50
        log_odds += math.log(cvss_lr) if cvss_lr > 0 else -50
        log_odds += math.log(exposure_lr) if exposure_lr > 0 else -50
        log_odds += math.log(criticality_lr) if criticality_lr > 0 else -50
        log_odds += math.log(nlp_lr) if nlp_lr > 0 else -50
        log_odds += epss_contrib

        posterior = self._log_odds_to_prob(log_odds)
        posterior = self._gate_amplification(posterior)

        cred_lower, cred_upper = self._calculate_credible_interval(posterior, log_odds)
        category = self._categorize_risk(posterior)
        explanation = self._generate_explanation(
            posterior,
            prior,
            control_lr,
            threat_lr,
            cvss_lr,
            exposure_lr,
            criticality_lr,
            epss_contrib,
            category,
        )

        return BayesianRiskResult(
            posterior_probability=round(posterior, 6),
            prior_probability=prior,
            log_odds_prior=round(self._prob_to_log_odds(prior), 4),
            log_odds_posterior=round(log_odds, 4),
            control_lr=round(control_lr, 4),
            threat_lr=round(threat_lr, 4),
            cvss_vector_lr=round(cvss_lr, 4),
            exposure_lr=round(exposure_lr, 4),
            criticality_lr=round(criticality_lr, 4),
            epss_contribution=round(epss_contrib, 4),
            risk_category=category,
            credible_lower=round(cred_lower, 6),
            credible_upper=round(cred_upper, 6),
            explanation=explanation,
        )

    def _normalize_epss(self, epss: float) -> float:
        """Convert EPSS score to a log-odds contribution.

        Args:
            epss: EPSS probability in [0, 1].

        Returns:
            Log-odds delta weighted by the EPSS weight from config.
        """
        clamped = max(0.0, min(1.0, epss))
        eps = 1e-10
        log_odds = math.log(max(clamped, eps) / max(1.0 - clamped, eps))
        return log_odds * self.config.epss_weight

    def _normalize_controls(self, controls: SecurityControlsInput) -> list[str]:
        """Return the names of enabled security controls.

        Args:
            controls: Security controls input.

        Returns:
            List of control names that are enabled.
        """
        return [name for name, value in controls.__dict__.items() if value]

    def _normalize_threats(self, threats: ThreatIndicatorsInput) -> dict[str, float]:
        """Extract active threat indicator likelihood ratios.

        Args:
            threats: Threat indicators input.

        Returns:
            Mapping of indicator name to its likelihood ratio value.
        """
        result: dict[str, float] = {}
        if threats.active_exploitation:
            result["active_exploitation"] = self.threat_lrs.get(
                "active_exploitation", 3.0
            )
        if threats.exploit_available:
            result["exploit_available"] = self.threat_lrs.get("exploit_available", 2.0)
        conf = max(0.0, min(1.0, threats.threat_intel_confidence))
        if conf > 0:
            base_lr = self.threat_lrs.get("threat_intel_confidence", 1.5)
            result["threat_intel_confidence"] = 1.0 + (base_lr - 1.0) * conf
        return result

    @staticmethod
    def _prob_to_log_odds(prob: float) -> float:
        """Convert a probability to log odds.

        Args:
            prob: Probability in (0, 1).

        Returns:
            Natural log of odds p / (1 - p).
        """
        eps = 1e-10
        clamped = max(eps, min(1.0 - eps, prob))
        return math.log(clamped / (1.0 - clamped))

    @staticmethod
    def _log_odds_to_prob(log_odds: float) -> float:
        """Convert log odds to a probability.

        Args:
            log_odds: Natural log of odds.

        Returns:
            Probability in (0, 1).
        """
        odds = math.exp(log_odds)
        return odds / (1.0 + odds)

    def _apply_control_lrs(
        self, controls: SecurityControlsInput, cvss_vector: str
    ) -> float:
        """Compute combined likelihood ratio from enabled security controls.

        Uses conditional LRs when the CVSS attack vector is available.

        Args:
            controls: Security controls input.
            cvss_vector: CVSS vector string for conditional lookup.

        Returns:
            Product of per-control likelihood ratios.
        """
        enabled = self._normalize_controls(controls)
        av = self._extract_attack_vector(cvss_vector)
        combined_lr = 1.0
        for control in enabled:
            lr = ExposureConditionalControlLR.get_lr(control, av)
            overridden = self.control_lrs.get(control)
            if overridden is not None:
                lr = overridden
            combined_lr *= lr
        return combined_lr

    def _get_gated_exposure_lr(
        self, cvss_score: float, controls: SecurityControlsInput
    ) -> float:
        """Compute exposure LR gated by CVSS severity and control coverage.

        Higher CVSS scores amplify exposure; more controls reduce it.

        Args:
            cvss_score: CVSS score in [0, 10].
            controls: Security controls input.

        Returns:
            Exposure likelihood ratio.
        """
        normalized_score = max(0.0, min(1.0, cvss_score / 10.0))
        control_count = len(self._normalize_controls(controls))
        control_factor = max(0.3, 1.0 - 0.1 * control_count)
        base_lr = 1.0 + 2.0 * normalized_score
        return base_lr * control_factor

    def _get_gated_criticality_lr(self, asset_criticality: float) -> float:
        """Compute criticality LR scaled by the configured weight.

        Args:
            asset_criticality: Normalized criticality in [0, 1].

        Returns:
            Criticality likelihood ratio.
        """
        normalized = max(0.0, min(1.0, asset_criticality))
        base_lr = 1.0 + 3.0 * normalized
        gated = 1.0 + (base_lr - 1.0) * self.config.criticality_weight
        return gated

    def _apply_cvss_vector_lrs(self, cvss_vector: str) -> float:
        """Compute combined LR from parsed CVSS vector components.

        Args:
            cvss_vector: Full CVSS vector string.

        Returns:
            Product of per-metric likelihood ratios.
        """
        metrics = self._parse_cvss_vector(cvss_vector)
        combined_lr = 1.0
        tables = self._lr_tables
        for metric, value in metrics.items():
            lr = tables.get(metric, {}).get(value, 1.0)
            combined_lr *= lr
        return combined_lr

    @staticmethod
    def _gate_amplification(probability: float) -> float:
        """Cap probability to a valid range and apply soft bounds.

        Prevents extreme values from dominating downstream categorization.

        Args:
            probability: Raw posterior probability.

        Returns:
            Gated probability in [0, 1].
        """
        return max(0.0, min(1.0, probability))

    @staticmethod
    def _parse_cvss_vector(cvss_vector: str) -> dict[str, str]:
        """Parse a CVSS v3.x vector string into metric key-value pairs.

        Handles vectors like
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'.

        Args:
            cvss_vector: CVSS vector string.

        Returns:
            Mapping of metric abbreviation to value code.
        """
        result: dict[str, str] = {}
        if not cvss_vector:
            return result
        parts = cvss_vector.split("/")
        for part in parts:
            if ":" not in part or part.startswith("CVSS"):
                continue
            key, value = part.split(":", 1)
            if key.strip() and value.strip():
                result[key.strip()] = value.strip()
        return result

    def _apply_threat_lrs(self, threats: ThreatIndicatorsInput) -> float:
        """Compute combined LR from active threat indicators.

        Args:
            threats: Threat indicators input.

        Returns:
            Product of per-indicator likelihood ratios.
        """
        indicators = self._normalize_threats(threats)
        combined_lr = 1.0
        for lr in indicators.values():
            combined_lr *= lr
        return combined_lr

    def _apply_nlp_features(self, features: dict[str, float] | None) -> float:
        """Compute LR contribution from NLP-derived features.

        Features are expected to be normalized scores in [0, 1]. Their
        mean is mapped to a likelihood ratio in [0.5, 2.0].

        Args:
            features: Mapping of feature name to normalized score.

        Returns:
            Likelihood ratio from NLP features. Defaults to 1.0 when absent.
        """
        if not features:
            return 1.0
        values = [max(0.0, min(1.0, v)) for v in features.values()]
        if not values:
            return 1.0
        mean_score = sum(values) / len(values)
        return 0.5 + 1.5 * mean_score

    def _get_criticality_lr(self, asset_criticality: float) -> float:
        """Compute raw criticality LR before weight gating.

        Args:
            asset_criticality: Normalized criticality in [0, 1].

        Returns:
            Raw criticality likelihood ratio.
        """
        normalized = max(0.0, min(1.0, asset_criticality))
        return 1.0 + 3.0 * normalized

    def _calculate_credible_interval(
        self, posterior: float, log_odds: float
    ) -> tuple[float, float]:
        """Approximate a 95% credible interval around the posterior.

        Uses a normal approximation on the log-odds scale with a fixed
        width that narrows as |log_odds| increases (more evidence).

        Args:
            posterior: Posterior probability.
            log_odds: Posterior log odds.

        Returns:
            Tuple of (lower_bound, upper_bound) probabilities.
        """
        evidence_strength = abs(log_odds)
        half_width = max(0.5, 2.0 / (1.0 + evidence_strength))
        lower_odds = self._log_odds_to_prob(log_odds - half_width)
        upper_odds = self._log_odds_to_prob(log_odds + half_width)
        return (lower_odds, upper_odds)

    @staticmethod
    def _categorize_risk(probability: float) -> str:
        """Map a posterior probability to a risk category string.

        Thresholds:
            - CRITICAL: >= 0.5
            - HIGH: >= 0.2
            - MEDIUM: >= 0.05
            - LOW: >= 0.01
            - INFORMATIONAL: < 0.01

        Args:
            probability: Posterior exploitation probability.

        Returns:
            Risk category label.
        """
        if probability >= 0.5:
            return "CRITICAL"
        if probability >= 0.2:
            return "HIGH"
        if probability >= 0.05:
            return "MEDIUM"
        if probability >= 0.01:
            return "LOW"
        return "INFORMATIONAL"

    def _generate_explanation(
        self,
        posterior: float,
        prior: float,
        control_lr: float,
        threat_lr: float,
        cvss_lr: float,
        exposure_lr: float,
        criticality_lr: float,
        epss_contrib: float,
        category: str,
    ) -> str:
        """Generate a human-readable explanation of the assessment.

        Args:
            posterior: Posterior exploitation probability.
            prior: Prior probability.
            control_lr: Combined control likelihood ratio.
            threat_lr: Combined threat likelihood ratio.
            cvss_lr: Combined CVSS vector likelihood ratio.
            exposure_lr: Exposure likelihood ratio.
            criticality_lr: Criticality likelihood ratio.
            epss_contrib: EPSS log-odds contribution.
            category: Computed risk category.

        Returns:
            Explanation string summarizing the assessment.
        """
        parts = [
            f"Risk category: {category}.",
            f"Prior: {prior:.4f}, Posterior: {posterior:.4f}.",
            f"Controls LR: {control_lr:.2f}, Threat LR: {threat_lr:.2f}.",
            f"CVSS vector LR: {cvss_lr:.2f}, Exposure LR: {exposure_lr:.2f}.",
            f"Criticality LR: {criticality_lr:.2f}, EPSS delta: {epss_contrib:.2f}.",
        ]

        factors = {
            "Controls": control_lr,
            "Threat intelligence": threat_lr,
            "CVSS severity": cvss_lr,
            "Exposure": exposure_lr,
            "Asset criticality": criticality_lr,
        }
        dominant = max(factors, key=factors.get)  # type: ignore[arg-type]
        parts.append(f"Dominant factor: {dominant}.")

        return " ".join(parts)

    @staticmethod
    def _extract_attack_vector(cvss_vector: str) -> str | None:
        """Extract the attack vector code from a CVSS vector string.

        Args:
            cvss_vector: CVSS vector string.

        Returns:
            Attack vector code (N/A/L/P) or None.
        """
        metrics = BayesianRiskAssessor._parse_cvss_vector(cvss_vector)
        return metrics.get("AV")

    def _build_lr_tables(self) -> dict[str, dict[str, float]]:
        """Build lookup tables for CVSS vector metric LRs.

        Returns:
            Nested mapping of metric name to value-to-LR table.
        """
        return {
            "AV": CVSSVectorLR.ATTACK_VECTOR,
            "AC": CVSSVectorLR.ATTACK_COMPLEXITY,
            "PR": CVSSVectorLR.PRIVILEGES_REQUIRED,
            "UI": CVSSVectorLR.USER_INTERACTION,
            "S": CVSSVectorLR.SCOPE,
        }


def assess_vulnerabilities_bayesian(
    df: pl.DataFrame,
    config: LikelihoodRatioConfig | None = None,
) -> pl.DataFrame:
    """Attach Bayesian risk assessment columns to a vulnerability DataFrame.

    Expects the DataFrame to contain at minimum:
        - cvss_score (float)
        - epss_score (float)
        - cvss_vector (str)

    Optional columns for richer assessment:
        - asset_criticality (float, default 0.5)

    All control and threat indicator columns default to False/0.0 when absent.

        - firewall, ids_ips, waf, patching, mfa, encryption,
          access_control, monitoring (bool)
        - active_exploitation, exploit_available (bool)
        - threat_intel_confidence (float)

    Args:
        df: Polars DataFrame of vulnerability records.
        config: Optional likelihood ratio configuration.

    Returns:
        DataFrame with added columns:
            posterior_probability, risk_category, credible_lower,
            credible_upper, control_lr, threat_lr, cvss_vector_lr,
            exposure_lr, criticality_lr, explanation.
    """
    assessor = BayesianRiskAssessor(config)

    control_fields = [
        "firewall",
        "ids_ips",
        "waf",
        "patching",
        "mfa",
        "encryption",
        "access_control",
        "monitoring",
    ]

    def _row_assess(row: dict[str, Any]) -> dict[str, Any]:
        controls = SecurityControlsInput(
            **{ctrl: bool(row.get(ctrl, False)) for ctrl in control_fields}
        )
        threats = ThreatIndicatorsInput(
            active_exploitation=bool(row.get("active_exploitation", False)),
            exploit_available=bool(row.get("exploit_available", False)),
            threat_intel_confidence=float(row.get("threat_intel_confidence", 0.0)),
        )
        result = assessor.assess(
            cvss_score=float(row.get("cvss_score", 0.0)),
            epss_score=float(row.get("epss_score", 0.0)),
            cvss_vector=str(row.get("cvss_vector", "")),
            controls=controls,
            threats=threats,
            asset_criticality=float(row.get("asset_criticality", 0.5)),
        )
        return {
            "posterior_probability": result.posterior_probability,
            "risk_category": result.risk_category,
            "credible_lower": result.credible_lower,
            "credible_upper": result.credible_upper,
            "control_lr": result.control_lr,
            "threat_lr": result.threat_lr,
            "cvss_vector_lr": result.cvss_vector_lr,
            "exposure_lr": result.exposure_lr,
            "criticality_lr": result.criticality_lr,
            "explanation": result.explanation,
        }

    row_schema = {
        "posterior_probability": pl.Float64,
        "risk_category": pl.String,
        "credible_lower": pl.Float64,
        "credible_upper": pl.Float64,
        "control_lr": pl.Float64,
        "threat_lr": pl.Float64,
        "cvss_vector_lr": pl.Float64,
        "exposure_lr": pl.Float64,
        "criticality_lr": pl.Float64,
        "explanation": pl.String,
    }

    results = [_row_assess(row) for row in df.iter_rows(named=True)]
    assessed = pl.DataFrame(results, schema=row_schema)
    return df.hstack(assessed)
