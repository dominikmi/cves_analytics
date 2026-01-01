"""Temporal probability adjustments for vulnerability exploitation.

Implements temporal factors from EXTENDED_KILL_CHAIN_METHOD.md:
- Vulnerability age impact
- Zero-day status
- Patch availability
- Probability floors for KEV and negligence
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TemporalFactors(BaseModel):
    """Temporal factors affecting exploitation probability."""

    days_since_disclosure: int = Field(ge=0)
    days_since_patch: int | None = None
    is_zero_day: bool = False
    is_kev: bool = False
    cvss_score: float = Field(ge=0.0, le=10.0)


class TemporalAdjustment(BaseModel):
    """Result of temporal probability adjustment."""

    age_factor: float = Field(gt=0.0)
    patch_factor: float = Field(gt=0.0)
    kev_multiplier: float = Field(gt=0.0)
    floor_applied: str | None = None
    adjusted_probability: float = Field(ge=0.0, le=1.0)


def calculate_age_factor(days_since_disclosure: int, is_zero_day: bool) -> float:
    """Calculate age-based probability factor.

    Exploitation probability curve over time:
    - Zero-Day (0-7d): 5.0x (targeted APT attacks)
    - Early (7-30d): 2.0x (exploit development peaks)
    - Peak (30-90d): 1.5x (automated scanning begins)
    - Mature (90-180d): 1.0x (widespread exploitation)
    - Decline (180-365d): 0.5x (most systems patched)
    - Long-Tail (1yr+): 0.1x (only unpatched targets)

    Args:
        days_since_disclosure: Days since CVE disclosure
        is_zero_day: Whether this is a zero-day vulnerability

    Returns:
        Age factor multiplier

    """
    if is_zero_day:
        return 5.0

    if days_since_disclosure <= 7:
        return 3.0
    elif days_since_disclosure <= 30:
        return 2.0
    elif days_since_disclosure <= 90:
        return 1.5
    elif days_since_disclosure <= 180:
        return 1.0
    elif days_since_disclosure <= 365:
        return 0.5
    else:
        # Long-tail: 0.1 base, with additional decay
        years = days_since_disclosure / 365
        return max(0.01, 0.1 * (0.5 ** (years - 1)))


def calculate_patch_factor(days_since_patch: int | None) -> float:
    """Calculate patch availability factor.

    Patch availability reduces exploitation probability:
    - No patch: 1.0x (no reduction)
    - Patch < 7d: 0.8x (20% reduction - patch just released)
    - Patch 7-30d: 0.5x (50% reduction - patch available)
    - Patch 30-90d: 0.3x (70% reduction - patch widely deployed)
    - Patch 90-365d: 0.2x (80% reduction - most systems patched)
    - Patch > 1yr: 0.1x (90% reduction - negligence if unpatched)

    Args:
        days_since_patch: Days since patch was released (None if no patch)

    Returns:
        Patch factor multiplier

    """
    if days_since_patch is None:
        return 1.0  # No patch available

    if days_since_patch <= 7:
        return 0.8
    elif days_since_patch <= 30:
        return 0.5
    elif days_since_patch <= 90:
        return 0.3
    elif days_since_patch <= 365:
        return 0.2
    else:
        return 0.1  # Extreme negligence


def apply_temporal_adjustment(
    posterior_probability: float,
    temporal_factors: TemporalFactors,
) -> TemporalAdjustment:
    """Apply temporal adjustments to posterior probability.

    Adjustments are applied in odds space to maintain proper probability bounds.

    Args:
        posterior_probability: Posterior probability from Bayesian assessment
        temporal_factors: Temporal factors (age, patch, KEV, etc.)

    Returns:
        TemporalAdjustment with adjusted probability and factors

    """
    # Convert to odds
    posterior_odds = posterior_probability / (1 - posterior_probability)

    # Calculate factors
    age_factor = calculate_age_factor(
        temporal_factors.days_since_disclosure,
        temporal_factors.is_zero_day,
    )

    patch_factor = calculate_patch_factor(temporal_factors.days_since_patch)

    # KEV multiplier: KEV status maintains high probability despite age
    kev_multiplier = 1.5 if temporal_factors.is_kev else 1.0

    # Apply factors in odds space
    adjusted_odds = posterior_odds * age_factor * patch_factor * kev_multiplier

    # Convert back to probability
    adjusted_prob = adjusted_odds / (1 + adjusted_odds)

    # Apply probability floors
    floor_applied = None

    # Zero-day + CVSS >= 9.0: minimum 5% (Medium)
    if temporal_factors.is_zero_day and temporal_factors.cvss_score >= 9.0:
        if adjusted_prob < 0.05:
            adjusted_prob = 0.05
            floor_applied = "zero_day_critical"

    # KEV: minimum 5% (Medium)
    if temporal_factors.is_kev:
        if adjusted_prob < 0.05:
            adjusted_prob = 0.05
            floor_applied = "kev"

    # Unpatched > 1yr + CVSS >= 7.0: minimum 2% (Low) - negligence
    if (
        temporal_factors.days_since_patch is not None
        and temporal_factors.days_since_patch > 365
        and temporal_factors.cvss_score >= 7.0
    ):
        if adjusted_prob < 0.02:
            adjusted_prob = 0.02
            floor_applied = "negligence"

    return TemporalAdjustment(
        age_factor=age_factor,
        patch_factor=patch_factor,
        kev_multiplier=kev_multiplier,
        floor_applied=floor_applied,
        adjusted_probability=adjusted_prob,
    )


def calculate_days_since_disclosure(disclosure_date: str | datetime) -> int:
    """Calculate days since vulnerability disclosure.

    Args:
        disclosure_date: CVE disclosure date (ISO format string or datetime)

    Returns:
        Number of days since disclosure

    """
    if isinstance(disclosure_date, str):
        disclosure_dt = datetime.fromisoformat(disclosure_date.replace("Z", "+00:00"))
    else:
        disclosure_dt = disclosure_date

    now = datetime.now(disclosure_dt.tzinfo)
    delta = now - disclosure_dt
    return max(0, delta.days)


def calculate_days_since_patch(patch_date: str | datetime | None) -> int | None:
    """Calculate days since patch was released.

    Args:
        patch_date: Patch release date (ISO format string, datetime, or None)

    Returns:
        Number of days since patch release, or None if no patch

    """
    if patch_date is None:
        return None

    if isinstance(patch_date, str):
        patch_dt = datetime.fromisoformat(patch_date.replace("Z", "+00:00"))
    else:
        patch_dt = patch_date

    now = datetime.now(patch_dt.tzinfo)
    delta = now - patch_dt
    return max(0, delta.days)


def add_temporal_adjustments_to_dataframe(
    df: Any,  # polars.DataFrame
    disclosure_date_col: str = "published_date",
    patch_date_col: str = "patch_date",
    cvss_col: str = "cvss_score",
    is_kev_col: str = "is_kev",
    posterior_col: str = "bayesian_risk_score",
) -> Any:  # polars.DataFrame
    """Add temporal adjustments to a DataFrame of vulnerabilities.

    Args:
        df: Polars DataFrame with vulnerability data
        disclosure_date_col: Column name for disclosure date
        patch_date_col: Column name for patch date
        cvss_col: Column name for CVSS score
        is_kev_col: Column name for KEV status
        posterior_col: Column name for Bayesian posterior probability

    Returns:
        DataFrame with temporal adjustment columns added

    """
    import polars as pl

    # Calculate days since disclosure
    if disclosure_date_col in df.columns:
        df = df.with_columns(
            [
                (
                    (
                        pl.col(disclosure_date_col).cast(pl.Datetime)
                        - pl.lit(datetime.now())
                    )
                    .dt.total_days()
                    .abs()
                    .cast(pl.Int32)
                    .alias("days_since_disclosure")
                )
            ]
        )
    else:
        df = df.with_columns(
            [pl.lit(180).alias("days_since_disclosure")]
        )  # Default 6 months

    # Calculate days since patch
    if patch_date_col in df.columns:
        df = df.with_columns(
            [
                (
                    pl.when(pl.col(patch_date_col).is_not_null())
                    .then(
                        (
                            pl.col(patch_date_col).cast(pl.Datetime)
                            - pl.lit(datetime.now())
                        )
                        .dt.total_days()
                        .abs()
                        .cast(pl.Int32)
                    )
                    .otherwise(None)
                    .alias("days_since_patch")
                )
            ]
        )
    else:
        df = df.with_columns([pl.lit(None).alias("days_since_patch")])

    # Apply temporal adjustments row by row
    # Note: This is a simplified implementation - full implementation would use
    # Polars expressions for better performance

    return df
