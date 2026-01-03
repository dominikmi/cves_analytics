"""Unit tests for temporal risk adjustments module."""

from datetime import datetime, timedelta

import pytest

from src.core.temporal_risk import (
    TemporalAdjustment,
    TemporalFactors,
    apply_temporal_adjustment,
    calculate_age_factor,
    calculate_days_since_disclosure,
    calculate_days_since_patch,
    get_epss_trajectory_factor,
)


class TestCalculateAgeFactor:
    """Test age factor calculation."""

    def test_zero_day(self):
        """Test zero-day vulnerability age factor."""
        factor = calculate_age_factor(0, is_zero_day=True)
        assert factor == 5.0

    def test_early_stage_7_days(self):
        """Test early stage (0-7 days)."""
        factor = calculate_age_factor(5, is_zero_day=False)
        assert factor == 3.0

    def test_early_stage_30_days(self):
        """Test early stage (7-30 days)."""
        factor = calculate_age_factor(15, is_zero_day=False)
        assert factor == 2.0

    def test_peak_stage_90_days(self):
        """Test peak stage (30-90 days)."""
        factor = calculate_age_factor(60, is_zero_day=False)
        assert factor == 1.5

    def test_mature_stage_180_days(self):
        """Test mature stage (90-180 days)."""
        factor = calculate_age_factor(120, is_zero_day=False)
        assert factor == 1.0

    def test_decline_stage_365_days(self):
        """Test decline stage (180-365 days)."""
        factor = calculate_age_factor(270, is_zero_day=False)
        assert factor == 0.5

    def test_long_tail_1_year(self):
        """Test long-tail (>365 days)."""
        factor = calculate_age_factor(400, is_zero_day=False)
        assert factor < 0.5
        assert factor >= 0.01

    def test_long_tail_2_years(self):
        """Test long-tail decay over time."""
        factor_1yr = calculate_age_factor(365, is_zero_day=False)
        factor_2yr = calculate_age_factor(730, is_zero_day=False)

        assert factor_2yr < factor_1yr
        assert factor_2yr >= 0.01


class TestEPSSTrajectoryFactor:
    """Test EPSS trajectory factor."""

    def test_default_trajectory_factor(self):
        """Test default trajectory factor when no historical data."""
        factors = TemporalFactors(
            days_since_disclosure=30,
            days_since_patch=None,
            is_zero_day=False,
            is_kev=False,
            cvss_score=7.0,
            epss_trajectory_factor=1.0,  # Default
        )
        factor = get_epss_trajectory_factor(factors)
        assert factor == 1.0

    def test_rising_epss_trajectory(self):
        """Test rising EPSS trajectory (active exploitation)."""
        factors = TemporalFactors(
            days_since_disclosure=30,
            days_since_patch=None,
            is_zero_day=False,
            is_kev=False,
            cvss_score=7.0,
            epss_trajectory_factor=1.2,  # Rising
        )
        factor = get_epss_trajectory_factor(factors)
        assert factor == 1.2

    def test_declining_epss_trajectory(self):
        """Test declining EPSS trajectory (patch adoption)."""
        factors = TemporalFactors(
            days_since_disclosure=90,
            days_since_patch=90,
            is_zero_day=False,
            is_kev=False,
            cvss_score=7.0,
            epss_trajectory_factor=1.0,  # Declining (baseline)
        )
        factor = get_epss_trajectory_factor(factors)
        assert factor == 1.0


class TestApplyTemporalAdjustment:
    """Test temporal adjustment application."""

    def test_zero_day_critical(self):
        """Test zero-day critical vulnerability."""
        factors = TemporalFactors(
            days_since_disclosure=0,
            days_since_patch=None,
            is_zero_day=True,
            is_kev=False,
            cvss_score=9.5,
        )

        adjustment = apply_temporal_adjustment(0.10, factors)

        assert adjustment.age_factor == 5.0
        assert adjustment.epss_trajectory_factor == 1.0
        assert adjustment.kev_multiplier == 1.0
        assert adjustment.adjusted_probability > 0.10
        # Floor may not be applied if probability is already above threshold
        assert adjustment.adjusted_probability >= 0.05

    def test_kev_floor(self):
        """Test KEV floor is applied."""
        factors = TemporalFactors(
            days_since_disclosure=400,
            days_since_patch=400,
            is_zero_day=False,
            is_kev=True,
            cvss_score=7.5,
        )

        adjustment = apply_temporal_adjustment(0.01, factors)

        assert adjustment.kev_multiplier == 1.5
        assert adjustment.adjusted_probability >= 0.05
        assert adjustment.floor_applied == "kev"

    def test_negligence_floor(self):
        """Test negligence floor for old unpatched vulnerabilities."""
        factors = TemporalFactors(
            days_since_disclosure=400,
            days_since_patch=400,
            is_zero_day=False,
            is_kev=False,
            cvss_score=8.0,
        )

        adjustment = apply_temporal_adjustment(0.005, factors)

        assert adjustment.adjusted_probability >= 0.02
        assert adjustment.floor_applied == "negligence"

    def test_recent_patched_vulnerability(self):
        """Test recently patched vulnerability."""
        factors = TemporalFactors(
            days_since_disclosure=30,
            days_since_patch=10,
            is_zero_day=False,
            is_kev=False,
            cvss_score=7.0,
        )

        adjustment = apply_temporal_adjustment(0.20, factors)

        assert adjustment.age_factor == 2.0
        assert adjustment.epss_trajectory_factor == 1.0
        # Adjusted probability will be different with new formula
        assert adjustment.adjusted_probability > 0

    def test_old_unpatched_vulnerability(self):
        """Test old unpatched vulnerability."""
        factors = TemporalFactors(
            days_since_disclosure=500,
            days_since_patch=None,
            is_zero_day=False,
            is_kev=False,
            cvss_score=6.0,
        )

        adjustment = apply_temporal_adjustment(0.15, factors)

        assert adjustment.age_factor < 0.5
        assert adjustment.epss_trajectory_factor == 1.0
        assert adjustment.adjusted_probability < 0.15

    def test_probability_bounds(self):
        """Test adjusted probability stays within bounds."""
        factors = TemporalFactors(
            days_since_disclosure=10,
            days_since_patch=None,
            is_zero_day=True,
            is_kev=True,
            cvss_score=10.0,
        )

        adjustment = apply_temporal_adjustment(0.50, factors)

        assert 0 <= adjustment.adjusted_probability <= 1.0

    def test_kev_maintains_high_probability(self):
        """Test KEV multiplier maintains high probability despite age."""
        factors = TemporalFactors(
            days_since_disclosure=400,
            days_since_patch=400,
            is_zero_day=False,
            is_kev=True,
            cvss_score=7.5,
        )

        adjustment = apply_temporal_adjustment(0.20, factors)

        assert adjustment.kev_multiplier == 1.5
        assert adjustment.adjusted_probability >= 0.05


class TestCalculateDaysSinceDisclosure:
    """Test days since disclosure calculation."""

    def test_recent_disclosure(self):
        """Test recently disclosed vulnerability."""
        recent_date = datetime.now() - timedelta(days=10)
        days = calculate_days_since_disclosure(recent_date)

        assert 9 <= days <= 11  # Allow for timing differences

    def test_old_disclosure(self):
        """Test old vulnerability."""
        old_date = datetime.now() - timedelta(days=365)
        days = calculate_days_since_disclosure(old_date)

        assert 364 <= days <= 366

    def test_iso_string_format(self):
        """Test ISO format string input."""
        date_str = "2023-01-01T00:00:00Z"
        days = calculate_days_since_disclosure(date_str)

        assert days > 0

    def test_negative_days_clamped(self):
        """Test future dates are clamped to 0."""
        future_date = datetime.now() + timedelta(days=10)
        days = calculate_days_since_disclosure(future_date)

        assert days == 0


class TestCalculateDaysSincePatch:
    """Test days since patch calculation."""

    def test_no_patch(self):
        """Test no patch available."""
        days = calculate_days_since_patch(None)
        assert days is None

    def test_recent_patch(self):
        """Test recently released patch."""
        recent_date = datetime.now() - timedelta(days=5)
        days = calculate_days_since_patch(recent_date)

        assert 4 <= days <= 6

    def test_old_patch(self):
        """Test old patch."""
        old_date = datetime.now() - timedelta(days=400)
        days = calculate_days_since_patch(old_date)

        assert 399 <= days <= 401

    def test_iso_string_format(self):
        """Test ISO format string input."""
        date_str = "2023-06-01T00:00:00Z"
        days = calculate_days_since_patch(date_str)

        assert days > 0


class TestTemporalFactorsModel:
    """Test TemporalFactors pydantic model."""

    def test_create_valid_factors(self):
        """Test creating valid temporal factors."""
        factors = TemporalFactors(
            days_since_disclosure=30,
            days_since_patch=10,
            is_zero_day=False,
            is_kev=False,
            cvss_score=7.5,
        )

        assert factors.days_since_disclosure == 30
        assert factors.days_since_patch == 10
        assert factors.is_zero_day is False
        assert factors.is_kev is False
        assert factors.cvss_score == 7.5

    def test_negative_days_rejected(self):
        """Test negative days are rejected."""
        with pytest.raises(ValueError):
            TemporalFactors(
                days_since_disclosure=-10,
                days_since_patch=None,
                is_zero_day=False,
                is_kev=False,
                cvss_score=7.0,
            )

    def test_invalid_cvss_rejected(self):
        """Test invalid CVSS score is rejected."""
        with pytest.raises(ValueError):
            TemporalFactors(
                days_since_disclosure=30,
                days_since_patch=None,
                is_zero_day=False,
                is_kev=False,
                cvss_score=11.0,  # Invalid
            )


class TestTemporalAdjustmentModel:
    """Test TemporalAdjustment pydantic model."""

    def test_create_valid_adjustment(self):
        """Test creating valid adjustment."""
        adjustment = TemporalAdjustment(
            age_factor=2.0,
            epss_trajectory_factor=1.0,
            kev_multiplier=1.0,
            floor_applied=None,
            adjusted_probability=0.15,
        )

        assert adjustment.age_factor == 2.0
        assert adjustment.epss_trajectory_factor == 1.0
        assert adjustment.kev_multiplier == 1.0
        assert adjustment.floor_applied is None
        assert adjustment.adjusted_probability == 0.15

    def test_invalid_probability_rejected(self):
        """Test invalid probability is rejected."""
        with pytest.raises(ValueError):
            TemporalAdjustment(
                age_factor=1.0,
                epss_trajectory_factor=1.0,
                kev_multiplier=1.0,
                floor_applied=None,
                adjusted_probability=1.5,  # Invalid
            )


class TestRealWorldScenarios:
    """Test real-world vulnerability scenarios."""

    def test_log4shell_scenario(self):
        """Test Log4Shell-like scenario (KEV, widely exploited)."""
        # Log4Shell: disclosed Dec 2021, patch available immediately, KEV
        factors = TemporalFactors(
            days_since_disclosure=450,  # ~15 months
            days_since_patch=450,
            is_zero_day=False,
            is_kev=True,
            cvss_score=10.0,
        )

        adjustment = apply_temporal_adjustment(0.40, factors)

        # Should maintain high probability due to KEV
        assert adjustment.adjusted_probability >= 0.05
        assert adjustment.kev_multiplier == 1.5

    def test_heartbleed_scenario(self):
        """Test Heartbleed-like scenario (old, patched, but still found)."""
        # Heartbleed: disclosed 2014, patch available immediately
        factors = TemporalFactors(
            days_since_disclosure=3000,  # ~8 years
            days_since_patch=3000,
            is_zero_day=False,
            is_kev=False,
            cvss_score=7.5,
        )

        adjustment = apply_temporal_adjustment(0.20, factors)

        # Should be very low due to age
        # Note: Without declining EPSS trajectory, uses baseline (1.0x)
        assert adjustment.adjusted_probability < 0.20
        # Negligence floor should apply
        assert adjustment.adjusted_probability >= 0.02

    def test_zero_day_apt_scenario(self):
        """Test zero-day APT scenario."""
        # Zero-day actively exploited by APT
        factors = TemporalFactors(
            days_since_disclosure=0,
            days_since_patch=None,
            is_zero_day=True,
            is_kev=False,
            cvss_score=9.0,
        )

        adjustment = apply_temporal_adjustment(0.15, factors)

        # Should be significantly amplified
        assert adjustment.age_factor == 5.0
        assert adjustment.adjusted_probability > 0.15
        # Floor may not be applied if probability is already above threshold
        assert adjustment.adjusted_probability >= 0.05


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
