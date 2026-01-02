#!/usr/bin/env python3
"""Run Monte Carlo simulation for vulnerability risk assessment.

This script integrates the Monte Carlo framework with the main pipeline
to run probabilistic risk analysis.
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from monte_carlo.src.analyzer import BayesianAnalyzer
from monte_carlo.src.simulator import MonteCarloSimulator
from monte_carlo.src.visualizer import MonteCarloVisualizer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    """Run Monte Carlo simulation."""
    parser = argparse.ArgumentParser(
        description="Run Monte Carlo simulation for vulnerability risk assessment"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of Monte Carlo iterations (default: 1000)",
    )
    parser.add_argument(
        "--org-size",
        type=str,
        default="large",
        choices=["small", "medium", "large"],
        help="Organization size (default: large)",
    )
    parser.add_argument(
        "--industry",
        type=str,
        default="financial-services",
        help="Industry type (default: financial-services)",
    )
    parser.add_argument(
        "--maturity",
        type=str,
        default="optimizing",
        choices=["initial", "managed", "optimizing"],
        help="Security maturity level (default: optimizing)",
    )
    parser.add_argument(
        "--environment",
        type=str,
        default="prod",
        choices=["dev", "test", "prod"],
        help="Environment (default: prod)",
    )
    parser.add_argument(
        "--seed", type=int, default=None, help="Random seed for reproducibility"
    )
    parser.add_argument(
        "--force-cache-rebuild",
        action="store_true",
        help="Force rebuild of cache (default: use existing cache)",
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Skip analysis and visualization (default: run analysis)",
    )
    parser.add_argument(
        "--skip-visualization",
        action="store_true",
        help="Skip visualization (default: create plots)",
    )

    args = parser.parse_args()

    logger.info("=" * 80)
    logger.info("MONTE CARLO VULNERABILITY RISK ASSESSMENT")
    logger.info("=" * 80)
    logger.info("Configuration:")
    logger.info(f"  Iterations: {args.iterations}")
    logger.info(f"  Organization: {args.org_size}, {args.industry}")
    logger.info(f"  Maturity: {args.maturity}")
    logger.info(f"  Environment: {args.environment}")
    logger.info(f"  Random seed: {args.seed}")
    logger.info("=" * 80)

    # Initialize simulator
    simulator = MonteCarloSimulator(
        n_iterations=args.iterations,
        cache_dir="monte_carlo/output/cache",
        output_dir="monte_carlo/output/runs",
        random_seed=args.seed,
    )

    # Run simulation
    try:
        results = simulator.run(
            org_size=args.org_size,
            industry=args.industry,
            maturity=args.maturity,
            environment=args.environment,
            force_cache_rebuild=args.force_cache_rebuild,
        )

        logger.info("=" * 80)
        logger.info("SIMULATION COMPLETE")
        logger.info("=" * 80)

        # Quick summary
        killchain_probs = [
            it["kill_chain"]["overall_probability"] for it in results["iterations"]
        ]
        import numpy as np

        logger.info("Kill-chain probability statistics:")
        logger.info(f"  Mean: {np.mean(killchain_probs):.3f}")
        logger.info(f"  Median: {np.median(killchain_probs):.3f}")
        logger.info(f"  Std: {np.std(killchain_probs):.3f}")
        logger.info(f"  p95: {np.percentile(killchain_probs, 95):.3f}")
        logger.info(f"  p99: {np.percentile(killchain_probs, 99):.3f}")

        # Analysis
        if not args.skip_analysis:
            logger.info("=" * 80)
            logger.info("RUNNING BAYESIAN ANALYSIS")
            logger.info("=" * 80)

            analyzer = BayesianAnalyzer()
            analysis = analyzer.analyze_results(results)

            # Save analysis
            analysis_file = (
                Path("monte_carlo/output/runs")
                / f"analysis_{args.maturity}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(analysis_file, "w") as f:
                json.dump(analysis, f, indent=2)
            logger.info(f"Analysis saved to {analysis_file}")

            # Print key metrics
            kc_metrics = analysis["metrics"]["killchain_probability"]
            logger.info("\nKill-chain Probability Analysis:")
            logger.info(f"  Mean: {kc_metrics['mean']:.3f}")
            logger.info(
                f"  95% Credible Interval: [{kc_metrics['credible_intervals_mean']['95%']['lower']:.3f}, "
                f"{kc_metrics['credible_intervals_mean']['95%']['upper']:.3f}]"
            )
            logger.info(f"  p50: {kc_metrics['percentiles']['p50']:.3f}")
            logger.info(f"  p95: {kc_metrics['percentiles']['p95']:.3f}")

        # Visualization
        if not args.skip_visualization:
            logger.info("=" * 80)
            logger.info("GENERATING VISUALIZATIONS")
            logger.info("=" * 80)

            visualizer = MonteCarloVisualizer("monte_carlo/output/visualizations")

            # Distribution plot
            logger.info("Creating distribution plot...")
            visualizer.plot_distribution(results, metric="killchain_probability")

            # Control effectiveness plots
            if not args.skip_analysis:
                logger.info("Creating control effectiveness plots...")
                for control_type in [
                    "mfa_type",
                    "firewall_type",
                    "waf_type",
                    "endpoint_protection_type",
                ]:
                    try:
                        visualizer.plot_control_effectiveness(
                            analysis, control_type=control_type
                        )
                    except Exception as e:
                        logger.warning(f"Could not create plot for {control_type}: {e}")

            logger.info("Visualizations saved to monte_carlo/output/visualizations/")

        logger.info("=" * 80)
        logger.info("MONTE CARLO SIMULATION COMPLETE")
        logger.info("=" * 80)

    except Exception as e:
        logger.error(f"Simulation failed: {e}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
