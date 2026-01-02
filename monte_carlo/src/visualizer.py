#!/usr/bin/env python3
"""Visualization tools for Monte Carlo simulation results.

Provides publication-quality plots using matplotlib and seaborn for:
- Distribution analysis (histograms, density plots, box plots)
- Scenario comparisons
- Control effectiveness
- Credible interval visualization
"""

import logging
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

logger = logging.getLogger(__name__)

sns.set_theme(style="whitegrid")
plt.rcParams["figure.figsize"] = (14, 10)
plt.rcParams["figure.dpi"] = 300
plt.rcParams["font.size"] = 11
plt.rcParams["axes.labelsize"] = 12
plt.rcParams["axes.titlesize"] = 14
plt.rcParams["xtick.labelsize"] = 10
plt.rcParams["ytick.labelsize"] = 10
plt.rcParams["legend.fontsize"] = 10


class MonteCarloVisualizer:
    """Visualization tools for Monte Carlo simulation results.

    Creates publication-quality plots for:
    - Risk distributions
    - Scenario comparisons
    - Control effectiveness
    - Credible intervals

    Uses matplotlib and seaborn for static, high-quality plots.
    """

    def __init__(self, output_dir: str | Path = "monte_carlo/output/visualizations"):
        """Initialize visualizer.

        Args:
            output_dir: Directory to save plots
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Initialized visualizer, output dir: {self.output_dir}")

    def plot_distribution(
        self,
        results: dict[str, Any],
        metric: str = "killchain_probability",
        bins: int = 50,
        save: bool = True,
    ) -> None:
        """Plot distribution comparing WITH controls vs WITHOUT controls.

        Args:
            results: Simulation results
            metric: Metric to plot
            bins: Number of histogram bins
            save: Whether to save plot to file
        """
        # Extract controlled values
        values_with_controls = self._extract_metric(results["iterations"], metric)

        # FIX #1: Use REAL EPSS baseline data from cache (not synthetic)
        # Extract the actual EPSS scores from the first iteration
        # (they're stored in bayesian_stats for all iterations)
        first_iter = results["iterations"][0]
        baseline_values = first_iter["bayesian_stats"].get("baseline_epss_values", [])

        # If baseline values not available (old data), fall back to extraction
        if not baseline_values:
            logger.warning("No baseline EPSS values found, using fallback")
            baseline_values = [0.547] * first_iter["bayesian_stats"]["high_risk_vulnerabilities"]

        # Extract kill-chain probabilities for 3rd panel
        killchain_values = self._extract_metric(results["iterations"], "killchain_probability")

        # Create 3-panel plot: baseline, controlled, kill-chain
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(14, 16))

        # Top plot: WITHOUT controls (baseline)
        mean_baseline = np.mean(baseline_values)
        median_baseline = np.median(baseline_values)
        ax1.hist(
            baseline_values,
            bins=30,
            alpha=0.7,
            color="red",
            edgecolor="black",
            label="Without Controls",
        )
        ax1.axvline(
            median_baseline,
            color="darkred",
            linestyle="--",
            linewidth=2.5,
            label=f"Median: {median_baseline:.2%}",
        )
        ax1.axvline(
            mean_baseline,
            color="orange",
            linestyle=":",
            linewidth=2,
            label=f"Mean: {mean_baseline:.2%}",
        )
        ax1.set_xlabel("Exploitation Probability", fontsize=13, fontweight="bold")
        ax1.set_ylabel("Frequency", fontsize=13, fontweight="bold")
        ax1.set_title(
            "Baseline Risk WITHOUT Security Controls\n"
            f"Average EPSS of {results['iterations'][0]['bayesian_stats']['high_risk_vulnerabilities']} "
            "High-Risk Vulnerabilities (EPSS > 10% AND Critical/High)",
            fontsize=14,
            fontweight="bold",
            pad=15,
        )
        ax1.legend(loc="upper right", fontsize=11)
        ax1.grid(True, alpha=0.3, linestyle="--")
        ax1.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:.0%}"))

        # Bottom plot: WITH controls
        mean_controlled = np.mean(values_with_controls)
        median_controlled = np.median(values_with_controls)
        std_controlled = np.std(values_with_controls)
        p95_controlled = np.percentile(values_with_controls, 95)

        ax2.hist(
            values_with_controls,
            bins=bins,
            alpha=0.7,
            color="green",
            edgecolor="black",
            label="With Controls",
        )
        ax2.axvline(
            mean_controlled,
            color="darkgreen",
            linestyle="--",
            linewidth=2.5,
            label=f"Mean: {mean_controlled:.2%}",
        )
        ax2.axvline(
            median_controlled,
            color="blue",
            linestyle="--",
            linewidth=2.5,
            label=f"Median: {median_controlled:.2%}",
        )

        # Add credible interval for controlled
        ci_95_controlled = np.percentile(values_with_controls, [2.5, 97.5])
        ax2.axvspan(
            ci_95_controlled[0],
            ci_95_controlled[1],
            alpha=0.2,
            color="gray",
            label=f"95% CI: [{ci_95_controlled[0]:.1%}, {ci_95_controlled[1]:.1%}]",
        )

        scenario = results["scenario_config"]
        n_iters = results.get("n_iterations", len(results["iterations"]))
        n_vulns = results["iterations"][0]["bayesian_stats"].get(
            "high_risk_vulnerabilities", 0
        )

        ax2.set_xlabel("Exploitation Probability", fontsize=13, fontweight="bold")
        ax2.set_ylabel("Frequency", fontsize=13, fontweight="bold")
        org = scenario["org_size"].title()
        mat = scenario["maturity"].title()
        ax2.set_title(
            f"Risk WITH Security Controls ({mat} Maturity)\n"
            f"{n_iters:,} Monte Carlo iterations with varying control configurations",
            fontsize=14,
            fontweight="bold",
            pad=15,
        )
        ax2.legend(loc="upper right", fontsize=11)
        ax2.grid(True, alpha=0.3, linestyle="--")
        # Use more precision for x-axis labels (1 decimal place)
        ax2.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:.1%}"))

        # Bottom plot: Kill-chain probability (full attack chain)
        mean_killchain = np.mean(killchain_values)
        median_killchain = np.median(killchain_values)
        std_killchain = np.std(killchain_values)
        
        ax3.hist(
            killchain_values,
            bins=bins,
            alpha=0.7,
            color="purple",
            edgecolor="black",
            label="Kill-Chain Probability",
        )
        ax3.axvline(
            mean_killchain,
            color="darkviolet",
            linestyle="--",
            linewidth=2.5,
            label=f"Mean: {mean_killchain:.2%}",
        )
        ax3.axvline(
            median_killchain,
            color="indigo",
            linestyle="--",
            linewidth=2.5,
            label=f"Median: {median_killchain:.2%}",
        )
        
        # Add credible interval for kill-chain
        ci_95_killchain = np.percentile(killchain_values, [2.5, 97.5])
        ax3.axvspan(
            ci_95_killchain[0],
            ci_95_killchain[1],
            alpha=0.2,
            color="gray",
            label=f"95% CI: [{ci_95_killchain[0]:.2%}, {ci_95_killchain[1]:.2%}]",
        )

        ax3.set_xlabel("Kill-Chain Probability", fontsize=13, fontweight="bold")
        ax3.set_ylabel("Frequency", fontsize=13, fontweight="bold")
        ax3.set_title(
            f"Full Attack Chain Probability ({mat} Maturity)\n"
            f"Conditional probability through all 10 attack stages",
            fontsize=14,
            fontweight="bold",
            pad=15,
        )
        ax3.legend(loc="upper right", fontsize=11)
        ax3.grid(True, alpha=0.3, linestyle="--")
        # Use high precision for kill-chain (very small values)
        ax3.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:.2%}"))

        # Add overall comparison text (using median for robustness to outliers)
        risk_reduction = ((median_baseline - median_controlled) / median_baseline) * 100
        attack_reduction = ((median_controlled - median_killchain) / median_controlled) * 100
        fig.suptitle(
            f"Three-Level Risk Analysis\n"
            f"Baseline: {median_baseline:.2%} → Controlled: {median_controlled:.2%} ({risk_reduction:.1f}% reduction) "
            f"→ Kill-Chain: {median_killchain:.2%} ({attack_reduction:.1f}% further reduction)",
            fontsize=15,
            fontweight="bold",
            y=0.995,
        )

        plt.tight_layout(rect=[0, 0, 1, 0.98])

        if save:
            filename = (
                f"dist_{metric}_{scenario['org_size']}_{scenario['maturity']}.png"
            )
            filepath = self.output_dir / filename
            plt.savefig(filepath, dpi=300, bbox_inches="tight")
            logger.info(f"Saved distribution plot to {filepath}")

        plt.close()

    def plot_comparison(
        self,
        scenario1_results: dict[str, Any],
        scenario2_results: dict[str, Any],
        metric: str = "killchain_probability",
        save: bool = True,
    ) -> None:
        """Plot side-by-side comparison of two scenarios.

        Args:
            scenario1_results: First scenario results
            scenario2_results: Second scenario results
            metric: Metric to compare
            save: Whether to save plot
        """
        values1 = self._extract_metric(scenario1_results["iterations"], metric)
        values2 = self._extract_metric(scenario2_results["iterations"], metric)

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))

        # Scenario names
        s1_config = scenario1_results["scenario_config"]
        s2_config = scenario2_results["scenario_config"]
        s1_name = f"{s1_config['maturity'].title()}"
        s2_name = f"{s2_config['maturity'].title()}"

        # 1. Overlapping histograms
        ax = axes[0, 0]
        ax.hist(
            values1, bins=40, alpha=0.6, color="red", label=s1_name, edgecolor="black"
        )
        ax.hist(
            values2, bins=40, alpha=0.6, color="blue", label=s2_name, edgecolor="black"
        )
        ax.set_xlabel(metric.replace("_", " ").title(), fontsize=11)
        ax.set_ylabel("Frequency", fontsize=11)
        ax.set_title("Distribution Comparison", fontsize=12, fontweight="bold")
        ax.legend(fontsize=10)
        ax.grid(True, alpha=0.3)

        # 2. Box plots
        ax = axes[0, 1]
        data_to_plot = [values1, values2]
        bp = ax.boxplot(
            data_to_plot,
            labels=[s1_name, s2_name],
            patch_artist=True,
            notch=True,
            showmeans=True,
        )
        bp["boxes"][0].set_facecolor("red")
        bp["boxes"][1].set_facecolor("blue")
        ax.set_ylabel(metric.replace("_", " ").title(), fontsize=11)
        ax.set_title("Box Plot Comparison", fontsize=12, fontweight="bold")
        ax.grid(True, alpha=0.3, axis="y")

        # 3. Violin plots
        ax = axes[1, 0]
        ax.violinplot(data_to_plot, positions=[1, 2], showmeans=True, showmedians=True)
        ax.set_xticks([1, 2])
        ax.set_xticklabels([s1_name, s2_name])
        ax.set_ylabel(metric.replace("_", " ").title(), fontsize=11)
        ax.set_title("Violin Plot Comparison", fontsize=12, fontweight="bold")
        ax.grid(True, alpha=0.3, axis="y")

        # 4. Cumulative distribution
        ax = axes[1, 1]
        sorted1 = np.sort(values1)
        sorted2 = np.sort(values2)
        y1 = np.arange(1, len(sorted1) + 1) / len(sorted1)
        y2 = np.arange(1, len(sorted2) + 1) / len(sorted2)

        ax.plot(sorted1, y1, color="red", linewidth=2, label=s1_name)
        ax.plot(sorted2, y2, color="blue", linewidth=2, label=s2_name)
        ax.set_xlabel(metric.replace("_", " ").title(), fontsize=11)
        ax.set_ylabel("Cumulative Probability", fontsize=11)
        ax.set_title("Cumulative Distribution Function", fontsize=12, fontweight="bold")
        ax.legend(fontsize=10)
        ax.grid(True, alpha=0.3)

        # Overall title
        fig.suptitle(
            f"Scenario Comparison: {s1_name} vs {s2_name}",
            fontsize=16,
            fontweight="bold",
            y=0.995,
        )

        plt.tight_layout()

        if save:
            s1_mat = s1_config["maturity"]
            s2_mat = s2_config["maturity"]
            filename = f"comparison_{metric}_{s1_mat}_vs_{s2_mat}.png"
            filepath = self.output_dir / filename
            plt.savefig(filepath, dpi=300, bbox_inches="tight")
            logger.info(f"Saved comparison plot to {filepath}")

        plt.close()

    def plot_credible_intervals(
        self, comparison: dict[str, Any], save: bool = True
    ) -> None:
        """Plot credible intervals for scenario comparison.

        Args:
            comparison: Comparison results from BayesianAnalyzer
            save: Whether to save plot
        """
        fig, ax = plt.subplots(figsize=(12, 8))

        # Extract data
        expected_diff = comparison["expected_difference"]
        ci_90 = comparison["credible_intervals"]["90%"]
        ci_95 = comparison["credible_intervals"]["95%"]
        ci_99 = comparison["credible_intervals"]["99%"]

        # Plot credible intervals as horizontal bars
        y_pos = [3, 2, 1]
        intervals = [
            (ci_90["lower"], ci_90["upper"]),
            (ci_95["lower"], ci_95["upper"]),
            (ci_99["lower"], ci_99["upper"]),
        ]
        labels = ["90% CI", "95% CI", "99% CI"]
        colors = ["lightblue", "steelblue", "darkblue"]

        for y, (lower, upper), label, color in zip(
            y_pos, intervals, labels, colors, strict=True
        ):
            ax.barh(
                y,
                upper - lower,
                left=lower,
                height=0.5,
                color=color,
                alpha=0.7,
                label=label,
            )

        # Add expected difference line
        ax.axvline(
            expected_diff,
            color="red",
            linestyle="--",
            linewidth=2,
            label="Expected Difference",
        )
        ax.axvline(0, color="black", linestyle="-", linewidth=1, alpha=0.5)

        # Labels
        s1_name = comparison["scenario1"]["maturity"].title()
        s2_name = comparison["scenario2"]["maturity"].title()

        ax.set_yticks(y_pos)
        ax.set_yticklabels(labels)
        ax.set_xlabel("Risk Difference", fontsize=12)
        ax.set_title(
            f"Credible Intervals for Risk Difference\n{s1_name} vs {s2_name}",
            fontsize=14,
            fontweight="bold",
        )
        ax.legend(fontsize=10)
        ax.grid(True, alpha=0.3, axis="x")

        # Add interpretation text
        prob = comparison["probability_scenario2_better"]
        reduction = comparison["relative_risk_reduction"]

        text = f"Probability {s2_name} is better: {prob:.1%}\n"
        text += f"Relative risk reduction: {reduction:.1%}"

        ax.text(
            0.02,
            0.98,
            text,
            transform=ax.transAxes,
            fontsize=11,
            verticalalignment="top",
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
        )

        plt.tight_layout()

        if save:
            filename = f"credible_intervals_{s1_name}_vs_{s2_name}.png"
            filepath = self.output_dir / filename
            plt.savefig(filepath, dpi=300, bbox_inches="tight")
            logger.info(f"Saved credible intervals plot to {filepath}")

        plt.close()

    def plot_control_effectiveness(
        self, analysis: dict[str, Any], control_type: str, save: bool = True
    ) -> None:
        """Plot control effectiveness analysis.

        Args:
            analysis: Analysis results from BayesianAnalyzer
            control_type: Control type to plot (e.g., 'mfa_type')
            save: Whether to save plot
        """
        if control_type not in analysis["control_analysis"]:
            logger.warning(f"Control type '{control_type}' not found in analysis")
            return

        control_data = analysis["control_analysis"][control_type]

        # Extract data
        control_values = list(control_data.keys())
        mean_risks = [control_data[v]["mean_risk"] for v in control_values]
        std_risks = [control_data[v]["std_risk"] for v in control_values]
        counts = [control_data[v]["count"] for v in control_values]

        # Sort by mean risk
        sorted_indices = np.argsort(mean_risks)
        control_values = [control_values[i] for i in sorted_indices]
        mean_risks = [mean_risks[i] for i in sorted_indices]
        std_risks = [std_risks[i] for i in sorted_indices]
        counts = [counts[i] for i in sorted_indices]

        # Create figure - vertical layout for better readability
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))

        # Plot setup
        y_pos = np.arange(len(control_values))
        colors = plt.cm.RdYlGn_r(np.linspace(0.2, 0.8, len(control_values)))
        control_name = control_type.replace("_", " ").title()

        # Top plot: Effectiveness
        ax1.barh(
            y_pos,
            mean_risks,
            xerr=std_risks,
            color=colors,
            alpha=0.7,
            edgecolor="black",
        )
        ax1.set_yticks(y_pos)
        ax1.set_yticklabels(control_values, fontsize=11)
        ax1.set_xlabel("Exploitation Probability", fontsize=12, fontweight="bold")
        ax1.set_title(
            f"{control_name} - Effectiveness (Lower = Better)",
            fontsize=13,
            fontweight="bold",
        )
        ax1.grid(True, alpha=0.3, axis="x")
        ax1.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f"{x:.0%}"))

        # Add value labels
        for i, risk in enumerate(mean_risks):
            ax1.text(risk * 1.05, i, f"{risk:.1%}", va="center", ha="left", fontsize=10)

        # Bottom plot: Frequency
        ax2.barh(y_pos, counts, color=colors, alpha=0.7, edgecolor="black")
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels(control_values, fontsize=11)
        ax2.set_xlabel("Selection Count", fontsize=12, fontweight="bold")
        ax2.set_title(
            f"{control_name} - Selection Frequency", fontsize=13, fontweight="bold"
        )
        ax2.grid(True, alpha=0.3, axis="x")

        # Add count labels
        for i, count in enumerate(counts):
            ax2.text(count * 1.02, i, f"{count}", va="center", ha="left", fontsize=10)

        plt.tight_layout()

        if save:
            scenario = analysis["scenario"]
            filename = (
                f"control_effectiveness_{control_type}_{scenario['maturity']}.png"
            )
            filepath = self.output_dir / filename
            plt.savefig(filepath, dpi=300, bbox_inches="tight")
            logger.info(f"Saved control effectiveness plot to {filepath}")

        plt.close()

    def plot_multi_scenario_comparison(
        self,
        results_list: list[dict[str, Any]],
        metric: str = "killchain_probability",
        save: bool = True,
    ) -> None:
        """Plot comparison of multiple scenarios.

        Args:
            results_list: List of scenario results
            metric: Metric to compare
            save: Whether to save plot
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

        # Extract data
        all_values = []
        labels = []
        colors = plt.cm.viridis(np.linspace(0, 1, len(results_list)))

        for results in results_list:
            values = self._extract_metric(results["iterations"], metric)
            all_values.append(values)
            config = results["scenario_config"]
            labels.append(f"{config['maturity'].title()}")

        # 1. Box plot comparison
        bp = ax1.boxplot(
            all_values, labels=labels, patch_artist=True, notch=True, showmeans=True
        )

        for patch, color in zip(bp["boxes"], colors, strict=True):
            patch.set_facecolor(color)

        ax1.set_ylabel(metric.replace("_", " ").title(), fontsize=12)
        ax1.set_title(
            "Multi-Scenario Box Plot Comparison", fontsize=13, fontweight="bold"
        )
        ax1.grid(True, alpha=0.3, axis="y")
        plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha="right")

        # 2. Violin plot comparison
        ax2.violinplot(
            all_values,
            positions=range(1, len(all_values) + 1),
            showmeans=True,
            showmedians=True,
        )

        ax2.set_xticks(range(1, len(labels) + 1))
        ax2.set_xticklabels(labels)
        ax2.set_ylabel(metric.replace("_", " ").title(), fontsize=12)
        ax2.set_title(
            "Multi-Scenario Violin Plot Comparison", fontsize=13, fontweight="bold"
        )
        ax2.grid(True, alpha=0.3, axis="y")
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha="right")

        plt.tight_layout()

        if save:
            filename = f"multi_scenario_{metric}.png"
            filepath = self.output_dir / filename
            plt.savefig(filepath, dpi=300, bbox_inches="tight")
            logger.info(f"Saved multi-scenario comparison to {filepath}")

        plt.close()

    def _extract_metric(self, iterations: list[dict], metric: str) -> list[float]:
        """Extract metric values from iterations.

        Args:
            iterations: List of iteration results
            metric: Metric name

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


def plot_distribution(
    results: dict[str, Any],
    metric: str = "killchain_probability",
    output_dir: str | Path = "monte_carlo/output/visualizations",
) -> None:
    """Convenience function to plot distribution.

    Args:
        results: Simulation results
        metric: Metric to plot
        output_dir: Output directory
    """
    visualizer = MonteCarloVisualizer(output_dir)
    visualizer.plot_distribution(results, metric)


def plot_comparison(
    scenario1_results: dict[str, Any],
    scenario2_results: dict[str, Any],
    metric: str = "killchain_probability",
    output_dir: str | Path = "monte_carlo/output/visualizations",
) -> None:
    """Convenience function to plot comparison.

    Args:
        scenario1_results: First scenario results
        scenario2_results: Second scenario results
        metric: Metric to compare
        output_dir: Output directory
    """
    visualizer = MonteCarloVisualizer(output_dir)
    visualizer.plot_comparison(scenario1_results, scenario2_results, metric)
