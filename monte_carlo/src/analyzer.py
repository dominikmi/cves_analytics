#!/usr/bin/env python3
"""Bayesian statistical analysis for Monte Carlo simulation results.

Provides pure Bayesian methods for analyzing and comparing Monte Carlo
simulation outcomes without relying on frequentist hypothesis testing.
"""

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class BayesianAnalyzer:
    """Bayesian statistical analyzer for Monte Carlo results.

    Implements pure Bayesian methods for:
    - Descriptive statistics with credible intervals
    - Posterior probability comparisons
    - Risk metric distributions
    - Control effectiveness analysis

    No p-values, no null hypothesis testing - just probability statements.
    """

    def __init__(self, bootstrap_samples: int = 10000):
        """Initialize Bayesian analyzer.

        Args:
            bootstrap_samples: Number of bootstrap samples for credible intervals
        """
        self.bootstrap_samples = bootstrap_samples
        logger.info(
            f"Initialized Bayesian analyzer with {bootstrap_samples} bootstrap samples"
        )

    def analyze_results(self, results: dict[str, Any]) -> dict[str, Any]:
        """Analyze Monte Carlo simulation results.

        Args:
            results: Simulation results from MonteCarloSimulator

        Returns:
            Analysis dict with Bayesian statistics
        """
        iterations = results["iterations"]
        n_iterations = len(iterations)

        logger.info(f"Analyzing {n_iterations} Monte Carlo iterations")

        # Extract metrics
        killchain_probs = [it["kill_chain"]["overall_probability"] for it in iterations]
        actionable_vulns = [
            it["bayesian_stats"].get("actionable_vulnerabilities", 0)
            for it in iterations
        ]
        avg_exploit_probs = [
            it["bayesian_stats"].get("avg_exploitation_probability", 0.0)
            for it in iterations
        ]

        analysis = {
            "scenario": results["scenario_config"],
            "n_iterations": n_iterations,
            "metrics": {
                "killchain_probability": self._analyze_metric(
                    killchain_probs, "Kill-chain Exploitation Probability"
                ),
                "actionable_vulnerabilities": self._analyze_metric(
                    actionable_vulns, "Actionable Vulnerabilities"
                ),
                "avg_exploitation_probability": self._analyze_metric(
                    avg_exploit_probs, "Average Exploitation Probability"
                ),
            },
            "control_analysis": self._analyze_controls(iterations),
        }

        return analysis

    def compare_scenarios(
        self,
        scenario1_results: dict[str, Any],
        scenario2_results: dict[str, Any],
        metric: str = "killchain_probability",
    ) -> dict[str, Any]:
        """Compare two scenarios using Bayesian methods.

        Instead of p-values, calculates:
        - Probability that scenario2 has lower risk than scenario1
        - Credible interval for the difference
        - Expected risk reduction

        Args:
            scenario1_results: First scenario results
            scenario2_results: Second scenario results
            metric: Metric to compare (default: killchain_probability)

        Returns:
            Comparison analysis dict
        """
        logger.info(
            f"Comparing scenarios: {scenario1_results['scenario_config']} vs "
            f"{scenario2_results['scenario_config']}"
        )

        # Extract metric values
        values1 = self._extract_metric(scenario1_results["iterations"], metric)
        values2 = self._extract_metric(scenario2_results["iterations"], metric)

        # Calculate probability that scenario2 is better (lower risk)
        prob_scenario2_better = np.mean(np.array(values2) < np.array(values1))

        # Calculate difference distribution
        differences = np.array(values1) - np.array(values2)

        # Credible intervals for difference
        ci_90 = np.percentile(differences, [5, 95])
        ci_95 = np.percentile(differences, [2.5, 97.5])
        ci_99 = np.percentile(differences, [0.5, 99.5])

        # Expected difference (mean)
        expected_difference = np.mean(differences)
        median_difference = np.median(differences)

        # Relative risk reduction
        mean1 = np.mean(values1)
        mean2 = np.mean(values2)
        relative_reduction = (mean1 - mean2) / mean1 if mean1 > 0 else 0.0

        comparison = {
            "scenario1": scenario1_results["scenario_config"],
            "scenario2": scenario2_results["scenario_config"],
            "metric": metric,
            # Core Bayesian result
            "probability_scenario2_better": float(prob_scenario2_better),
            # Difference statistics
            "expected_difference": float(expected_difference),
            "median_difference": float(median_difference),
            "relative_risk_reduction": float(relative_reduction),
            # Credible intervals
            "credible_intervals": {
                "90%": {"lower": float(ci_90[0]), "upper": float(ci_90[1])},
                "95%": {"lower": float(ci_95[0]), "upper": float(ci_95[1])},
                "99%": {"lower": float(ci_99[0]), "upper": float(ci_99[1])},
            },
            # Descriptive stats
            "scenario1_stats": {
                "mean": float(mean1),
                "median": float(np.median(values1)),
                "std": float(np.std(values1)),
            },
            "scenario2_stats": {
                "mean": float(mean2),
                "median": float(np.median(values2)),
                "std": float(np.std(values2)),
            },
            # Interpretation
            "interpretation": self._interpret_comparison(
                prob_scenario2_better,
                expected_difference,
                relative_reduction,
                scenario1_results["scenario_config"],
                scenario2_results["scenario_config"],
            ),
        }

        return comparison

    def _analyze_metric(self, values: list[float], name: str) -> dict[str, Any]:
        """Analyze a single metric with Bayesian statistics.

        Args:
            values: List of metric values from iterations
            name: Metric name

        Returns:
            Analysis dict with descriptive stats and credible intervals
        """
        values_array = np.array(values)

        # Descriptive statistics
        mean = np.mean(values_array)
        median = np.median(values_array)
        std = np.std(values_array)

        # Percentiles
        percentiles = {
            "p5": np.percentile(values_array, 5),
            "p25": np.percentile(values_array, 25),
            "p50": np.percentile(values_array, 50),
            "p75": np.percentile(values_array, 75),
            "p95": np.percentile(values_array, 95),
            "p99": np.percentile(values_array, 99),
        }

        # Bootstrap credible intervals for mean
        bootstrap_means = self._bootstrap(values_array, np.mean)
        ci_90 = np.percentile(bootstrap_means, [5, 95])
        ci_95 = np.percentile(bootstrap_means, [2.5, 97.5])
        ci_99 = np.percentile(bootstrap_means, [0.5, 99.5])

        return {
            "name": name,
            "n_samples": len(values),
            "mean": float(mean),
            "median": float(median),
            "std": float(std),
            "min": float(np.min(values_array)),
            "max": float(np.max(values_array)),
            "percentiles": {k: float(v) for k, v in percentiles.items()},
            "credible_intervals_mean": {
                "90%": {"lower": float(ci_90[0]), "upper": float(ci_90[1])},
                "95%": {"lower": float(ci_95[0]), "upper": float(ci_95[1])},
                "99%": {"lower": float(ci_99[0]), "upper": float(ci_99[1])},
            },
        }

    def _analyze_controls(self, iterations: list[dict]) -> dict[str, Any]:
        """Analyze control effectiveness across iterations.

        Args:
            iterations: List of iteration results

        Returns:
            Control analysis dict
        """
        # Extract control types and associated risks
        control_risks = {}

        for iteration in iterations:
            controls = iteration["controls"]
            risk = iteration["kill_chain"]["overall_probability"]

            for control_type, control_value in controls.items():
                if control_type not in control_risks:
                    control_risks[control_type] = {}

                if control_value not in control_risks[control_type]:
                    control_risks[control_type][control_value] = []

                control_risks[control_type][control_value].append(risk)

        # Analyze each control type
        control_analysis = {}

        for control_type, value_risks in control_risks.items():
            control_analysis[control_type] = {}

            for value, risks in value_risks.items():
                control_analysis[control_type][value] = {
                    "count": len(risks),
                    "mean_risk": float(np.mean(risks)),
                    "median_risk": float(np.median(risks)),
                    "std_risk": float(np.std(risks)),
                }

        return control_analysis

    def _extract_metric(self, iterations: list[dict], metric: str) -> list[float]:
        """Extract metric values from iterations.

        Args:
            iterations: List of iteration results
            metric: Metric name to extract

        Returns:
            List of metric values
        """
        if metric == "killchain_probability":
            return [it["kill_chain"]["overall_probability"] for it in iterations]
        elif metric == "actionable_vulnerabilities":
            return [
                it["bayesian_stats"].get("actionable_vulnerabilities", 0)
                for it in iterations
            ]
        elif metric == "avg_exploitation_probability":
            return [
                it["bayesian_stats"].get("avg_exploitation_probability", 0.0)
                for it in iterations
            ]
        else:
            raise ValueError(f"Unknown metric: {metric}")

    def _bootstrap(
        self, data: np.ndarray, statistic_func: callable, n_samples: int | None = None
    ) -> np.ndarray:
        """Bootstrap resampling for credible intervals.

        Args:
            data: Original data
            statistic_func: Function to calculate statistic (e.g., np.mean)
            n_samples: Number of bootstrap samples (default: self.bootstrap_samples)

        Returns:
            Array of bootstrap statistics
        """
        if n_samples is None:
            n_samples = self.bootstrap_samples

        bootstrap_stats = np.zeros(n_samples)
        n = len(data)

        for i in range(n_samples):
            # Resample with replacement
            sample = np.random.choice(data, size=n, replace=True)
            bootstrap_stats[i] = statistic_func(sample)

        return bootstrap_stats

    def _interpret_comparison(
        self,
        prob_better: float,
        expected_diff: float,
        relative_reduction: float,
        scenario1_config: dict,
        scenario2_config: dict,
    ) -> str:
        """Generate human-readable interpretation of comparison.

        Args:
            prob_better: Probability scenario2 is better
            expected_diff: Expected difference
            relative_reduction: Relative risk reduction
            scenario1_config: First scenario configuration
            scenario2_config: Second scenario configuration

        Returns:
            Interpretation string
        """
        s1_name = f"{scenario1_config['maturity']} maturity"
        s2_name = f"{scenario2_config['maturity']} maturity"

        # Determine strength of evidence
        if prob_better >= 0.99:
            strength = "very strong evidence"
        elif prob_better >= 0.95:
            strength = "strong evidence"
        elif prob_better >= 0.90:
            strength = "moderate evidence"
        elif prob_better >= 0.80:
            strength = "weak evidence"
        else:
            strength = "insufficient evidence"

        # Direction
        if prob_better > 0.5:
            direction = "lower"
            better = s2_name
        else:
            direction = "higher"
            better = s1_name
            prob_better = 1 - prob_better

        interpretation = (
            f"There is {strength} ({prob_better:.1%} probability) that "
            f"{better} has {direction} risk than the alternative. "
            f"Expected risk reduction: {abs(relative_reduction):.1%} "
            f"(absolute difference: {abs(expected_diff):.3f})."
        )

        return interpretation


def analyze_results(results: dict[str, Any]) -> dict[str, Any]:
    """Convenience function to analyze Monte Carlo results.

    Args:
        results: Simulation results from MonteCarloSimulator

    Returns:
        Analysis dict
    """
    analyzer = BayesianAnalyzer()
    return analyzer.analyze_results(results)


def compare_scenarios(
    scenario1_results: dict[str, Any],
    scenario2_results: dict[str, Any],
    metric: str = "killchain_probability",
) -> dict[str, Any]:
    """Convenience function to compare two scenarios.

    Args:
        scenario1_results: First scenario results
        scenario2_results: Second scenario results
        metric: Metric to compare

    Returns:
        Comparison analysis dict
    """
    analyzer = BayesianAnalyzer()
    return analyzer.compare_scenarios(scenario1_results, scenario2_results, metric)
