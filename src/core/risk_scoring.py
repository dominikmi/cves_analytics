"""Risk scoring module for vulnerability prioritization.

This module provides Bayesian risk assessment for vulnerabilities, replacing
the previous multiplicative weight approach with a principled probabilistic
framework.

The Bayesian approach:
- Uses EPSS as the prior probability of exploitation
- Updates the prior using likelihood ratios for security controls, exposure,
  CVSS characteristics, and threat indicators
- Provides uncertainty quantification via credible intervals

For backward compatibility, the legacy functions are preserved but now
delegate to the Bayesian implementation.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from src.core.bayesian_risk import (
    BayesianRiskAssessor,
    BayesianRiskResult,
    LikelihoodRatioConfig,
    SecurityControlsInput,
    ThreatIndicatorsInput,
    assess_vulnerabilities_bayesian,
)
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


# =============================================================================
# BAYESIAN RISK ASSESSMENT (NEW PRIMARY INTERFACE)
# =============================================================================


def calculate_bayesian_risk(
    row: dict[str, Any],
    assessor: BayesianRiskAssessor | None = None,
) -> BayesianRiskResult:
    """Calculate Bayesian risk score for a vulnerability.

    This is the new primary risk scoring function that uses a principled
    Bayesian approach instead of arbitrary multiplicative weights.

    Args:
        row: Dictionary containing vulnerability data with keys:
            - epss_score: EPSS probability (0-1) - serves as prior
            - epss_percentile: EPSS percentile (0-100) - for uncertainty
            - cvss_score: CVSS base score (0-10)
            - cvss_vector: CVSS v3 vector string
            - exposure: 'internet-facing', 'internal', 'restricted', etc.
            - asset_value: 'critical', 'high', 'medium', 'low'
            - security_controls: dict of control name -> bool
            - is_kev: Boolean indicating if in CISA KEV catalog
            - has_public_exploit: Boolean for public exploit availability

    Returns:
        BayesianRiskResult with posterior probability and uncertainty

    """
    if assessor is None:
        assessor = BayesianRiskAssessor()

    # Extract values from row
    epss_score = row.get("epss_score", 0.01)
    epss_percentile = row.get("epss_percentile")
    cvss_score = row.get("cvss_score")
    cvss_vector = row.get("cvss_vector")
    exposure = str(row.get("exposure", "internal"))
    asset_value = str(row.get("asset_value", "medium"))

    # Extract security controls
    security_controls = row.get("security_controls", {})
    if isinstance(security_controls, dict):
        controls = SecurityControlsInput(
            **{
                k: bool(v)
                for k, v in security_controls.items()
                if k in SecurityControlsInput.model_fields
            },
        )
    else:
        controls = None

    # Extract threat indicators (including granular CVSS-BT exploit data)
    threat_indicators = ThreatIndicatorsInput(
        is_kev=bool(row.get("is_kev", False)),
        has_public_exploit=bool(row.get("has_public_exploit", False)),
        has_metasploit_module=bool(row.get("has_metasploit_module", False)),
        is_weaponized=bool(row.get("is_weaponized", False)),
        # Granular exploit indicators from CVSS-BT
        has_exploitdb=bool(row.get("has_exploitdb", False)),
        has_metasploit=bool(row.get("has_metasploit", False)),
        has_nuclei=bool(row.get("has_nuclei", False)),
        has_poc_github=bool(row.get("has_poc_github", False)),
    )

    # Extract NLP features if available
    nlp_features = None
    if "nlp_confidence" in row:
        nlp_features = {
            "nlp_confidence": row.get("nlp_confidence", 0),
            "nlp_primary_attack": row.get("nlp_primary_attack"),
            "nlp_requires_auth": row.get("nlp_requires_auth"),
            "nlp_requires_user_interaction": row.get("nlp_requires_user_interaction"),
            "nlp_network_accessible": row.get("nlp_network_accessible"),
            "nlp_default_config": row.get("nlp_default_config"),
        }

    return assessor.assess(
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        security_controls=controls,
        exposure=exposure,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        threat_indicators=threat_indicators,
        asset_criticality=asset_value,
        nlp_features=nlp_features,
    )


def add_bayesian_risk_scores(
    enriched_results: pd.DataFrame,
    security_controls_col: str | None = "security_controls",
    config: LikelihoodRatioConfig | None = None,
) -> pd.DataFrame:
    """Add Bayesian risk scores to enriched results DataFrame.

    This is the new primary function for adding risk scores. It adds:
    - bayesian_risk_score: P(Exploitation | Evidence) - main risk metric
    - prior_epss: Original EPSS score
    - ci_low, ci_high: 95% credible interval bounds
    - uncertainty: Width of credible interval
    - risk_category: Categorical risk level
    - risk_explanation: Human-readable explanation

    Args:
        enriched_results: DataFrame with vulnerability data
        security_controls_col: Column containing security controls dict
        config: Optional custom likelihood ratio configuration

    Returns:
        DataFrame with added Bayesian risk columns

    """
    if enriched_results.empty:
        return enriched_results

    has_percentile = "epss_percentile" in enriched_results.columns
    percentile_col = "epss_percentile" if has_percentile else None

    return assess_vulnerabilities_bayesian(
        enriched_results,
        epss_score_col="epss_score",
        epss_percentile_col=percentile_col,
        cvss_vector_col="cvss_vector",
        cvss_score_col="cvss_score",
        exposure_col="exposure",
        asset_value_col="asset_value",
        security_posture_col=security_controls_col,
        kev_col="is_kev" if "is_kev" in enriched_results.columns else None,
        config=config,
    )


def categorize_by_bayesian_risk(
    enriched_results: pd.DataFrame,
) -> dict[str, pd.DataFrame]:
    """Categorize vulnerabilities by Bayesian risk category.

    Uses the risk_category column from Bayesian assessment.

    Args:
        enriched_results: DataFrame with 'risk_category' column

    Returns:
        Dictionary with keys 'critical', 'high', 'medium', 'low', 'negligible'

    """
    if enriched_results.empty:
        return {
            "critical": pd.DataFrame(),
            "high": pd.DataFrame(),
            "medium": pd.DataFrame(),
            "low": pd.DataFrame(),
            "negligible": pd.DataFrame(),
        }

    # Ensure Bayesian risk scores exist
    if "risk_category" not in enriched_results.columns:
        enriched_results = add_bayesian_risk_scores(enriched_results)

    has_bayes = "bayesian_risk_score" in enriched_results.columns
    sort_col = "bayesian_risk_score" if has_bayes else "risk_score"

    return {
        "critical": enriched_results[
            enriched_results["risk_category"] == "Critical"
        ].sort_values(sort_col, ascending=False),
        "high": enriched_results[
            enriched_results["risk_category"] == "High"
        ].sort_values(sort_col, ascending=False),
        "medium": enriched_results[
            enriched_results["risk_category"] == "Medium"
        ].sort_values(sort_col, ascending=False),
        "low": enriched_results[enriched_results["risk_category"] == "Low"].sort_values(
            sort_col,
            ascending=False,
        ),
        "negligible": enriched_results[
            enriched_results["risk_category"] == "Negligible"
        ].sort_values(sort_col, ascending=False),
    }


# =============================================================================
# LEGACY INTERFACE (BACKWARD COMPATIBILITY)
# =============================================================================
# These functions are preserved for backward compatibility but now delegate
# to the Bayesian implementation where possible.


def calculate_risk_score(row: dict[str, Any]) -> float:
    """Calculate risk score for a vulnerability (legacy interface).

    DEPRECATED: Use calculate_bayesian_risk() for the new Bayesian approach.

    This function now delegates to the Bayesian implementation and returns
    the posterior probability scaled to 0-10 for backward compatibility.

    Args:
        row: Dictionary containing vulnerability data

    Returns:
        Risk score (0-10) - scaled from Bayesian posterior probability

    """
    try:
        result = calculate_bayesian_risk(row)
        # Scale posterior probability (0-1) to 0-10 for backward compatibility
        return round(result.posterior_probability * 10, 2)
    except Exception as e:
        logger.warning(f"Bayesian risk calculation failed, using fallback: {e}")
        # Fallback to simple calculation
        return _legacy_calculate_risk_score(row)


def _legacy_calculate_risk_score(row: dict[str, Any]) -> float:
    """Legacy risk score calculation (fallback only).

    This is the original multiplicative weight approach, kept as fallback.
    """
    # Normalize CVSS to 0-1 range
    cvss_score = row.get("cvss_score", 5.0)
    if cvss_score is None or pd.isna(cvss_score):
        cvss_score = 5.0
    cvss = float(cvss_score) / 10.0
    cvss = max(0.0, min(1.0, cvss))

    # EPSS is already 0-1
    epss = row.get("epss_score", 0.1)
    if epss is None or pd.isna(epss):
        epss = 0.1
    epss = max(0.0, min(1.0, float(epss)))

    # Exposure multiplier
    exposure_map = {
        "internet-facing": 1.5,
        "external": 1.5,
        "internal": 1.0,
        "isolated": 0.5,
        "unknown": 1.0,
    }
    exposure = exposure_map.get(str(row.get("exposure", "unknown")).lower(), 1.0)

    # Asset value multiplier
    asset_map = {
        "critical": 1.3,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.8,
        "unknown": 1.0,
    }
    asset_value = asset_map.get(str(row.get("asset_value", "unknown")).lower(), 1.0)

    # Threat factor (KEV + exploit availability)
    threat = 1.0
    if row.get("is_kev", False):
        threat *= 1.2
    if row.get("has_exploit_poc", False) or row.get("has_public_exploit", False):
        threat *= 1.1

    # Calculate raw score
    raw_score = cvss * epss * exposure * asset_value * threat

    # Normalize to 0-10
    risk_score = min(10.0, raw_score * 10.0)

    return round(risk_score, 2)


def add_risk_scores(enriched_results: pd.DataFrame) -> pd.DataFrame:
    """Add risk scores to enriched results DataFrame (legacy interface).

    This function now uses the Bayesian approach and adds both:
    - risk_score: Legacy 0-10 scale (for backward compatibility)
    - bayesian_risk_score: Posterior probability (0-1)
    - risk_category: Categorical risk level

    Args:
        enriched_results: DataFrame with vulnerability data

    Returns:
        DataFrame with added risk score columns

    """
    if enriched_results.empty:
        return enriched_results

    try:
        # Use Bayesian approach
        enriched_results = add_bayesian_risk_scores(enriched_results)

        # Add legacy risk_score column (scaled 0-10) for backward compatibility
        if "bayesian_risk_score" in enriched_results.columns:
            enriched_results["risk_score"] = (
                enriched_results["bayesian_risk_score"] * 10
            ).round(2)

        logger.info(
            f"Added Bayesian risk scores to {len(enriched_results)} vulnerabilities",
        )

        # Log risk distribution
        if "risk_category" in enriched_results.columns:
            risk_dist = enriched_results["risk_category"].value_counts().to_dict()
            logger.info(f"Risk distribution: {risk_dist}")

    except Exception as e:
        logger.error(f"Failed to calculate Bayesian risk scores: {e}")
        # Fallback to legacy calculation
        enriched_results["risk_score"] = enriched_results.apply(
            _legacy_calculate_risk_score,
            axis=1,
        )
        enriched_results["risk_category"] = pd.cut(
            enriched_results["risk_score"],
            bins=[0, 1, 5, 15, 40, 100],
            labels=["Negligible", "Low", "Medium", "High", "Critical"],
        )

    return enriched_results


def categorize_by_risk(enriched_results: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Categorize vulnerabilities by risk level (legacy interface).

    This function now uses Bayesian risk categories but maps them to the
    legacy category names for backward compatibility.

    Args:
        enriched_results: DataFrame with risk columns

    Returns:
        Dictionary with keys 'critical', 'important', 'monitor', 'low'

    """
    if enriched_results.empty:
        return {
            "critical": pd.DataFrame(),
            "important": pd.DataFrame(),
            "monitor": pd.DataFrame(),
            "low": pd.DataFrame(),
        }

    # Ensure risk scores exist
    if "risk_category" not in enriched_results.columns:
        enriched_results = add_risk_scores(enriched_results)

    # Use Bayesian categories if available
    if "risk_category" in enriched_results.columns:
        has_bayes = "bayesian_risk_score" in enriched_results.columns
        sort_col = "bayesian_risk_score" if has_bayes else "risk_score"

        # Map Bayesian categories to legacy names
        return {
            "critical": enriched_results[
                enriched_results["risk_category"] == "Critical"
            ].sort_values(sort_col, ascending=False),
            "important": enriched_results[
                enriched_results["risk_category"] == "High"
            ].sort_values(sort_col, ascending=False),
            "monitor": enriched_results[
                enriched_results["risk_category"] == "Medium"
            ].sort_values(sort_col, ascending=False),
            "low": enriched_results[
                enriched_results["risk_category"].isin(["Low", "Negligible"])
            ].sort_values(sort_col, ascending=False),
        }

    # Fallback to legacy score-based categorization
    if "risk_score" not in enriched_results.columns:
        enriched_results = add_risk_scores(enriched_results)

    return {
        "critical": enriched_results[enriched_results["risk_score"] >= 8.0].sort_values(
            "risk_score",
            ascending=False,
        ),
        "important": enriched_results[
            (enriched_results["risk_score"] >= 6.0)
            & (enriched_results["risk_score"] < 8.0)
        ].sort_values("risk_score", ascending=False),
        "monitor": enriched_results[
            (enriched_results["risk_score"] >= 4.0)
            & (enriched_results["risk_score"] < 6.0)
        ].sort_values("risk_score", ascending=False),
        "low": enriched_results[enriched_results["risk_score"] < 4.0].sort_values(
            "risk_score",
            ascending=False,
        ),
    }
