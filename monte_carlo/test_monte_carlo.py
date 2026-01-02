#!/usr/bin/env python3
"""Test Monte Carlo framework with small dataset.

This script validates the Monte Carlo framework before running full simulations.
"""

import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def test_control_generation():
    """Test control generation without full pipeline."""
    logger.info("=" * 80)
    logger.info("TEST 1: Control Generation")
    logger.info("=" * 80)

    from src.simulation.security_controls import SecurityControlsGenerator

    generator = SecurityControlsGenerator()

    # Generate 10 control sets
    for i in range(10):
        controls = generator.generate(
            maturity="optimizing", industry="financial-services", size="large"
        )
        logger.info(f"Iteration {i + 1}:")
        logger.info(f"  MFA: {controls.mfa_type}")
        logger.info(f"  Firewall: {controls.firewall_type}")
        logger.info(f"  WAF: {controls.waf_type}")

    logger.info("✓ Control generation test passed")


def test_lr_mapping():
    """Test control to LR mapping."""
    logger.info("=" * 80)
    logger.info("TEST 2: LR Mapping")
    logger.info("=" * 80)

    from src.core.control_lr_mapper import get_control_lr_from_security_controls
    from src.simulation.security_controls import SecurityControlsGenerator

    generator = SecurityControlsGenerator()
    controls = generator.generate(
        maturity="optimizing", industry="financial-services", size="large"
    )

    controls_dict = {
        "mfa_type": controls.mfa_type,
        "firewall_type": controls.firewall_type,
        "waf_type": controls.waf_type,
        "endpoint_protection_type": controls.endpoint_protection_type,
        "segmentation_type": controls.segmentation_type,
        "ids_ips_type": controls.ids_ips_type,
        "siem_maturity": controls.siem_maturity,
        "patch_management_quality": controls.patch_management_quality,
    }

    lr_values = get_control_lr_from_security_controls(controls_dict)

    logger.info("Control LR values:")
    for control, lr in lr_values.items():
        logger.info(f"  {control}: {lr}")

    logger.info("✓ LR mapping test passed")


def test_analyzer():
    """Test Bayesian analyzer with mock data."""
    logger.info("=" * 80)
    logger.info("TEST 3: Bayesian Analyzer")
    logger.info("=" * 80)

    import numpy as np

    from monte_carlo.src.analyzer import BayesianAnalyzer

    # Create mock results
    mock_results = {
        "scenario_config": {
            "org_size": "large",
            "industry": "financial-services",
            "maturity": "optimizing",
        },
        "n_iterations": 100,
        "iterations": [],
    }

    # Generate mock iterations
    for i in range(100):
        iteration = {
            "iteration": i,
            "controls": {
                "mfa_type": "advanced",
                "firewall_type": "advanced",
                "waf_type": "advanced",
            },
            "kill_chain": {
                "overall_probability": np.random.beta(2, 5),  # Skewed distribution
                "threat_level": "medium",
            },
            "bayesian_stats": {
                "actionable_vulnerabilities": int(np.random.normal(50, 10)),
                "avg_exploitation_probability": np.random.beta(2, 8),
            },
        }
        mock_results["iterations"].append(iteration)

    # Analyze
    analyzer = BayesianAnalyzer()
    analysis = analyzer.analyze_results(mock_results)

    # Print results
    kc_metrics = analysis["metrics"]["killchain_probability"]
    logger.info("Kill-chain Probability Analysis:")
    logger.info(f"  Mean: {kc_metrics['mean']:.3f}")
    logger.info(
        f"  95% CI: [{kc_metrics['credible_intervals_mean']['95%']['lower']:.3f}, "
        f"{kc_metrics['credible_intervals_mean']['95%']['upper']:.3f}]"
    )
    logger.info(f"  p50: {kc_metrics['percentiles']['p50']:.3f}")
    logger.info(f"  p95: {kc_metrics['percentiles']['p95']:.3f}")

    logger.info("✓ Analyzer test passed")


def test_comparison():
    """Test scenario comparison."""
    logger.info("=" * 80)
    logger.info("TEST 4: Scenario Comparison")
    logger.info("=" * 80)

    import numpy as np

    from monte_carlo.src.analyzer import BayesianAnalyzer

    # Create two mock scenarios
    def create_mock_scenario(maturity, mean_risk):
        return {
            "scenario_config": {
                "org_size": "large",
                "industry": "financial-services",
                "maturity": maturity,
            },
            "n_iterations": 100,
            "iterations": [
                {
                    "iteration": i,
                    "kill_chain": {
                        "overall_probability": np.random.normal(mean_risk, 0.1),
                    },
                    "bayesian_stats": {"actionable_vulnerabilities": 50},
                }
                for i in range(100)
            ],
        }

    scenario1 = create_mock_scenario("initial", 0.45)
    scenario2 = create_mock_scenario("optimizing", 0.15)

    # Compare
    analyzer = BayesianAnalyzer()
    comparison = analyzer.compare_scenarios(scenario1, scenario2)

    logger.info("Comparison Results:")
    logger.info(
        f"  Probability optimizing is better: {comparison['probability_scenario2_better']:.1%}"
    )
    logger.info(f"  Expected difference: {comparison['expected_difference']:.3f}")
    logger.info(
        f"  Relative risk reduction: {comparison['relative_risk_reduction']:.1%}"
    )
    logger.info("\nInterpretation:")
    logger.info(f"  {comparison['interpretation']}")

    logger.info("✓ Comparison test passed")


def test_visualizer():
    """Test visualizer with mock data."""
    logger.info("=" * 80)
    logger.info("TEST 5: Visualizer")
    logger.info("=" * 80)

    import numpy as np

    from monte_carlo.src.visualizer import MonteCarloVisualizer

    # Create mock results
    mock_results = {
        "scenario_config": {
            "org_size": "large",
            "industry": "financial-services",
            "maturity": "test",
        },
        "n_iterations": 100,
        "iterations": [
            {
                "iteration": i,
                "kill_chain": {"overall_probability": np.random.beta(2, 5)},
                "bayesian_stats": {
                    "actionable_vulnerabilities": int(np.random.normal(50, 10))
                },
            }
            for i in range(100)
        ],
    }

    # Create visualizations
    visualizer = MonteCarloVisualizer("monte_carlo/output/test_visualizations")
    visualizer.plot_distribution(mock_results, metric="killchain_probability")

    logger.info("✓ Visualizer test passed")
    logger.info("  Check monte_carlo/output/test_visualizations/ for plots")


def main():
    """Run all tests."""
    logger.info("=" * 80)
    logger.info("MONTE CARLO FRAMEWORK VALIDATION TESTS")
    logger.info("=" * 80)

    tests = [
        ("Control Generation", test_control_generation),
        ("LR Mapping", test_lr_mapping),
        ("Bayesian Analyzer", test_analyzer),
        ("Scenario Comparison", test_comparison),
        ("Visualizer", test_visualizer),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            logger.error(f"✗ {test_name} test failed: {e}", exc_info=True)
            failed += 1

    logger.info("=" * 80)
    logger.info("TEST SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Passed: {passed}/{len(tests)}")
    logger.info(f"Failed: {failed}/{len(tests)}")

    if failed == 0:
        logger.info("✓ All tests passed! Framework is ready for use.")
        return 0
    else:
        logger.error(
            "✗ Some tests failed. Please fix issues before running full simulation."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
