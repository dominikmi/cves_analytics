#!/usr/bin/env python3
"""Integration test for EPSS trajectory analysis in temporal risk assessment.

This script tests the end-to-end flow of temporal risk adjustment with
EPSS trajectory analysis without requiring the full pipeline.
"""

import sys

from src.core.bayesian_risk import BayesianRiskAssessor
from src.core.temporal_risk import (
    TemporalFactors,
    apply_temporal_adjustment,
)


def test_temporal_adjustment_integration():
    """Test temporal adjustment with various EPSS trajectory scenarios."""
    print("=" * 80)
    print("EPSS Trajectory Integration Test")
    print("=" * 80)

    # Test scenarios
    scenarios = [
        {
            "name": "Declining EPSS (Patch Adoption)",
            "posterior_prob": 0.30,
            "days_since_disclosure": 90,
            "days_since_patch": 90,
            "is_zero_day": False,
            "is_kev": False,
            "cvss_score": 7.5,
            "epss_trajectory_factor": 1.0,  # Declining EPSS
            "expected_behavior": "Risk should decrease due to age decay",
        },
        {
            "name": "Rising EPSS (Active Exploitation)",
            "posterior_prob": 0.30,
            "days_since_disclosure": 30,
            "days_since_patch": None,
            "is_zero_day": False,
            "is_kev": False,
            "cvss_score": 8.0,
            "epss_trajectory_factor": 1.2,  # Rising EPSS
            "expected_behavior": "Risk should increase due to rising exploitation",
        },
        {
            "name": "KEV with High EPSS",
            "posterior_prob": 0.40,
            "days_since_disclosure": 180,
            "days_since_patch": 180,
            "is_zero_day": False,
            "is_kev": True,
            "cvss_score": 9.0,
            "epss_trajectory_factor": 1.0,  # Stable EPSS
            "expected_behavior": "KEV floor (5%) should apply, KEV multiplier (1.5x)",
        },
        {
            "name": "Zero-Day Critical",
            "posterior_prob": 0.20,
            "days_since_disclosure": 0,
            "days_since_patch": None,
            "is_zero_day": True,
            "is_kev": False,
            "cvss_score": 9.5,
            "epss_trajectory_factor": 1.0,
            "expected_behavior": "High age factor (5.0x), zero-day floor (5%)",
        },
        {
            "name": "Old Unpatched (Negligence)",
            "posterior_prob": 0.05,
            "days_since_disclosure": 500,
            "days_since_patch": 500,
            "is_zero_day": False,
            "is_kev": False,
            "cvss_score": 7.5,
            "epss_trajectory_factor": 1.0,
            "expected_behavior": "Low age factor, negligence floor (2%)",
        },
    ]

    print("\nTesting temporal adjustment scenarios:\n")

    all_passed = True
    for i, scenario in enumerate(scenarios, 1):
        print(f"\n{i}. {scenario['name']}")
        print("-" * 80)

        # Create temporal factors
        factors = TemporalFactors(
            days_since_disclosure=scenario["days_since_disclosure"],
            days_since_patch=scenario["days_since_patch"],
            is_zero_day=scenario["is_zero_day"],
            is_kev=scenario["is_kev"],
            cvss_score=scenario["cvss_score"],
            epss_trajectory_factor=scenario["epss_trajectory_factor"],
        )

        # Apply temporal adjustment
        result = apply_temporal_adjustment(scenario["posterior_prob"], factors)

        # Display results
        print(f"  Input posterior probability: {scenario['posterior_prob']:.4f}")
        print(f"  Age factor: {result.age_factor:.4f}")
        print(f"  EPSS trajectory factor: {result.epss_trajectory_factor:.4f}")
        print(f"  KEV multiplier: {result.kev_multiplier:.4f}")
        print(f"  Floor applied: {result.floor_applied or 'None'}")
        print(f"  Adjusted probability: {result.adjusted_probability:.4f}")
        print(f"  Expected: {scenario['expected_behavior']}")

        # Validation checks
        checks_passed = True

        # Check probability bounds
        if not (0 <= result.adjusted_probability <= 1.0):
            print("  ❌ FAIL: Probability out of bounds!")
            checks_passed = False
            all_passed = False

        # Check KEV floor
        if scenario["is_kev"] and result.adjusted_probability < 0.05:
            print("  ❌ FAIL: KEV floor not applied!")
            checks_passed = False
            all_passed = False

        # Check zero-day floor
        if (
            scenario["is_zero_day"]
            and scenario["cvss_score"] >= 9.0
            and result.adjusted_probability < 0.05
        ):
            print("  ❌ FAIL: Zero-day floor not applied!")
            checks_passed = False
            all_passed = False

        # Check negligence floor
        if (
            scenario["days_since_patch"]
            and scenario["days_since_patch"] > 365
            and scenario["cvss_score"] >= 7.0
            and result.adjusted_probability < 0.02
        ):
            print("  ❌ FAIL: Negligence floor not applied!")
            checks_passed = False
            all_passed = False

        if checks_passed:
            print("  ✅ PASS: All checks passed")

    print("\n" + "=" * 80)
    if all_passed:
        print("✅ ALL INTEGRATION TESTS PASSED")
        print("=" * 80)
        return 0
    else:
        print("❌ SOME INTEGRATION TESTS FAILED")
        print("=" * 80)
        return 1


def test_bayesian_with_temporal():
    """Test Bayesian risk assessment with temporal adjustments."""
    print("\n" + "=" * 80)
    print("Bayesian Risk + Temporal Adjustment Integration Test")
    print("=" * 80)

    # Create assessor
    assessor = BayesianRiskAssessor()

    # Test vulnerability
    print("\nTest Case: High CVSS, Moderate EPSS, Rising Exploitation")
    print("-" * 80)

    # Assess without temporal adjustment
    result = assessor.assess(
        epss_score=0.30,
        cvss_score=8.5,
        exposure="internet-facing",
        asset_criticality="high",
    )

    print(f"Bayesian posterior probability: {result.posterior_probability:.4f}")
    print(f"Risk category: {result.risk_category}")

    # Now apply temporal adjustment with rising EPSS trajectory
    factors = TemporalFactors(
        days_since_disclosure=30,
        days_since_patch=None,
        is_zero_day=False,
        is_kev=False,
        cvss_score=8.5,
        epss_trajectory_factor=1.2,  # Rising EPSS
    )

    temporal_result = apply_temporal_adjustment(result.posterior_probability, factors)

    print("\nAfter temporal adjustment:")
    print(f"  Age factor (30 days): {temporal_result.age_factor:.4f}")
    print(f"  EPSS trajectory (rising): {temporal_result.epss_trajectory_factor:.4f}")
    print(f"  Final adjusted probability: {temporal_result.adjusted_probability:.4f}")

    # Verify rising EPSS increases risk
    if temporal_result.adjusted_probability > result.posterior_probability:
        print("  ✅ PASS: Rising EPSS correctly increased risk")
        print("=" * 80)
        return 0
    else:
        print("  ❌ FAIL: Rising EPSS did not increase risk")
        print("=" * 80)
        return 1


def test_epss_trajectory_module():
    """Test EPSS trajectory module directly."""
    print("\n" + "=" * 80)
    print("EPSS Trajectory Module Test")
    print("=" * 80)

    try:
        from src.core.epss_trajectory import EPSSTrajectory

        trajectory = EPSSTrajectory()
        print("✅ EPSS trajectory module imported successfully")

        # Test trajectory calculations
        test_cases = [
            ("Declining", 0.50, 0.55, 0.60, 1.0),
            ("Rising", 0.70, 0.65, 0.60, 1.2),
            ("Stable", 0.50, 0.50, 0.50, 1.0),
            ("No history", 0.50, None, None, 1.0),
        ]

        all_passed = True
        for name, current, d30, d90, expected in test_cases:
            result = trajectory.calculate_trajectory_factor(current, d30, d90)
            if abs(result - expected) < 0.01:
                print(f"  ✅ {name}: {result:.2f} (expected {expected:.2f})")
            else:
                print(f"  ❌ {name}: {result:.2f} (expected {expected:.2f})")
                all_passed = False

        print("=" * 80)
        return 0 if all_passed else 1

    except ImportError as e:
        print(f"❌ FAIL: Could not import EPSS trajectory module: {e}")
        print("=" * 80)
        return 1


def main():
    """Run all integration tests."""
    print("\n" + "=" * 80)
    print("EPSS TRAJECTORY INTEGRATION TEST SUITE")
    print("Testing temporal risk changes before pipeline deployment")
    print("=" * 80)

    results = []

    # Test 1: EPSS trajectory module
    results.append(test_epss_trajectory_module())

    # Test 2: Temporal adjustment scenarios
    results.append(test_temporal_adjustment_integration())

    # Test 3: Bayesian + temporal integration
    results.append(test_bayesian_with_temporal())

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUITE SUMMARY")
    print("=" * 80)

    total_tests = len(results)
    passed_tests = sum(1 for r in results if r == 0)
    failed_tests = total_tests - passed_tests

    print(f"Total test groups: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")

    if failed_tests == 0:
        print("\n✅ ALL INTEGRATION TESTS PASSED - Ready for pipeline deployment!")
        print("=" * 80)
        return 0
    else:
        print(
            f"\n❌ {failed_tests} TEST GROUP(S) FAILED - Fix issues before deployment"
        )
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
