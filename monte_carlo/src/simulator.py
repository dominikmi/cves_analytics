#!/usr/bin/env python3
"""Monte Carlo simulator for vulnerability risk assessment.

Runs multiple pipeline iterations with varying security controls to generate
probability distributions of risk metrics. Uses caching to achieve ~670x speedup.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import polars as pl

from monte_carlo.src.cache_manager import SimulationCache
from src.core.bayesian_risk import BayesianRiskAssessor
from src.core.control_lr_mapper import get_control_lr_from_security_controls
from src.core.kill_chain_calculator import KillChainCalculator
from src.simulation.security_controls import SecurityControlsGenerator

logger = logging.getLogger(__name__)


class MonteCarloSimulator:
    """Monte Carlo simulator for vulnerability risk assessment.

    Architecture:
    1. One-time setup: Build cache (Docker scans, CVE data) - ~10 min
    2. Fast iterations: Generate controls, calculate risk - ~1-5 sec per iteration

    This separation provides ~670x speedup compared to running full pipeline
    for each iteration.

    Attributes:
        n_iterations: Number of Monte Carlo iterations
        cache_manager: Cache manager instance
        controls_generator: Security controls generator
        output_dir: Directory for results
    """

    def __init__(
        self,
        n_iterations: int = 1000,
        cache_dir: str | Path = "monte_carlo/output/cache",
        output_dir: str | Path = "monte_carlo/output/runs",
        random_seed: int | None = None,
    ):
        """Initialize Monte Carlo simulator.

        Args:
            n_iterations: Number of iterations to run
            cache_dir: Directory for cache storage
            output_dir: Directory for output storage
            random_seed: Random seed for reproducibility (None for random)
        """
        self.n_iterations = n_iterations
        self.cache_manager = SimulationCache(cache_dir)
        self.controls_generator = SecurityControlsGenerator()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.random_seed = random_seed

        logger.info(
            f"Initialized Monte Carlo simulator: {n_iterations} iterations, "
            f"seed={random_seed}"
        )

    def run(
        self,
        org_size: str,
        industry: str,
        maturity: str,
        environment: str = "prod",
        force_cache_rebuild: bool = False,
    ) -> dict[str, Any]:
        """Run Monte Carlo simulation.

        Args:
            org_size: Organization size (small/medium/large)
            industry: Industry type
            maturity: Security maturity level
            environment: Environment (dev/test/prod)
            force_cache_rebuild: Force cache rebuild

        Returns:
            Simulation results dict with all iterations
        """
        scenario_config = {
            "org_size": org_size,
            "industry": industry,
            "maturity": maturity,
            "environment": environment,
        }

        logger.info(f"Starting Monte Carlo simulation: {scenario_config}")
        start_time = datetime.now()

        # Phase 1: Build cache (one-time, expensive)
        logger.info("=" * 80)
        logger.info("PHASE 1: CACHE SETUP (one-time, ~10 minutes)")
        logger.info("=" * 80)
        cache = self.cache_manager.build_cache(
            scenario_config, force_rebuild=force_cache_rebuild
        )
        cache_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Cache setup completed in {cache_time:.1f} seconds")

        # Phase 2: Fast iterations
        logger.info("=" * 80)
        logger.info(f"PHASE 2: MONTE CARLO ITERATIONS ({self.n_iterations}x)")
        logger.info("=" * 80)

        results = []
        iteration_start = datetime.now()

        for i in range(self.n_iterations):
            if i > 0 and i % 100 == 0:
                elapsed = (datetime.now() - iteration_start).total_seconds()
                avg_time = elapsed / i
                remaining = avg_time * (self.n_iterations - i)
                logger.info(
                    f"Progress: {i}/{self.n_iterations} "
                    f"({i / self.n_iterations * 100:.1f}%) - "
                    f"Avg: {avg_time:.2f}s/iter - "
                    f"ETA: {remaining:.0f}s"
                )

            # Generate new controls (fast, probabilistic)
            seed = self.random_seed + i if self.random_seed else None
            iteration_result = self._run_iteration(
                iteration_num=i, scenario_config=scenario_config, cache=cache, seed=seed
            )
            results.append(iteration_result)

        iteration_time = (datetime.now() - iteration_start).total_seconds()
        total_time = (datetime.now() - start_time).total_seconds()

        logger.info("=" * 80)
        logger.info("SIMULATION COMPLETE")
        logger.info("=" * 80)
        logger.info(f"Cache setup time: {cache_time:.1f}s")
        logger.info(f"Iterations time: {iteration_time:.1f}s")
        logger.info(f"Total time: {total_time:.1f}s")
        logger.info(f"Average per iteration: {iteration_time / self.n_iterations:.2f}s")

        # Package results
        simulation_results = {
            "scenario_config": scenario_config,
            "n_iterations": self.n_iterations,
            "random_seed": self.random_seed,
            "timing": {
                "cache_setup_seconds": cache_time,
                "iterations_seconds": iteration_time,
                "total_seconds": total_time,
                "avg_per_iteration_seconds": iteration_time / self.n_iterations,
            },
            "iterations": results,
            "timestamp": datetime.now().isoformat(),
        }

        # Save results
        self._save_results(simulation_results)

        return simulation_results

    def _run_iteration(
        self,
        iteration_num: int,
        scenario_config: dict[str, Any],
        cache: dict[str, Any],
        seed: int | None = None,
    ) -> dict[str, Any]:
        """Run single Monte Carlo iteration.

        This is the fast part - uses cached vulnerability data and only
        regenerates controls and recalculates risk.

        Args:
            iteration_num: Iteration number
            scenario_config: Scenario configuration
            cache: Cached data
            seed: Random seed for this iteration

        Returns:
            Iteration results dict
        """
        # Step 1: Generate new security controls (fast, ~0.1s)
        controls = self.controls_generator.generate(
            maturity=scenario_config["maturity"],
            industry=scenario_config["industry"],
            size=scenario_config["org_size"],
            environment=scenario_config["environment"],
        )

        # Step 2: Map controls to likelihood ratios (fast, ~0.01s)
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

        # Step 3: Apply Bayesian risk assessment with new LRs (fast, ~0.5s)
        # Use cached vulnerability data
        enriched_cves = cache["enriched_cves"]

        # Reconstruct DataFrame from cached dict
        if enriched_cves:
            df = pl.DataFrame(enriched_cves)

            # Apply Bayesian reassessment with new control LRs
            bayesian = BayesianRiskAssessor()
            reassessed_df = bayesian.reassess_with_controls(df, lr_values)

            # Calculate statistics
            bayesian_stats = self._calculate_bayesian_stats(reassessed_df)
        else:
            bayesian_stats = {}

        # Step 4: Calculate kill-chain probability (fast, ~0.1s)
        architecture = cache.get("architecture", {})
        kill_chain_calc = KillChainCalculator(
            architecture=architecture, security_controls=controls
        )

        kill_chain_result = kill_chain_calc.calculate()

        # Package iteration results
        return {
            "iteration": iteration_num,
            "seed": seed,
            "controls": {
                "mfa_type": controls.mfa_type,
                "firewall_type": controls.firewall_type,
                "waf_type": controls.waf_type,
                "endpoint_protection_type": controls.endpoint_protection_type,
                "segmentation_type": controls.segmentation_type,
                "ids_ips_type": controls.ids_ips_type,
                "siem_maturity": controls.siem_maturity,
                "patch_management_quality": controls.patch_management_quality,
            },
            "lr_values": lr_values,
            "bayesian_stats": bayesian_stats,
            "kill_chain": {
                "overall_probability": kill_chain_result.overall_probability,
                "threat_level": kill_chain_result.threat_level,
                "stage_probabilities": kill_chain_result.stage_probabilities,
            },
        }

    def _calculate_bayesian_stats(self, df: pl.DataFrame) -> dict[str, Any]:
        """Calculate Bayesian risk statistics.

        Args:
            df: Reassessed vulnerability DataFrame

        Returns:
            Statistics dict
        """
        if df.is_empty():
            return {}

        # Count by severity
        severity_counts = (
            df.group_by("severity_reassessed").agg(pl.count()).to_dict(as_series=False)
        )

        # Calculate average exploitation probability
        avg_exploit_prob = (
            df["epss_score"].mean() if "epss_score" in df.columns else 0.0
        )

        # Count actionable vulnerabilities
        actionable = len(
            df.filter(pl.col("severity_reassessed").is_in(["Critical", "High"]))
        )

        return {
            "severity_counts": severity_counts,
            "avg_exploitation_probability": float(avg_exploit_prob),
            "actionable_vulnerabilities": actionable,
            "total_vulnerabilities": len(df),
        }

    def _save_results(self, results: dict[str, Any]) -> None:
        """Save simulation results to file.

        Args:
            results: Simulation results dict
        """
        import json

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scenario = results["scenario_config"]
        filename = (
            f"mc_{scenario['org_size']}_{scenario['maturity']}_"
            f"{self.n_iterations}iter_{timestamp}.json"
        )

        output_file = self.output_dir / filename
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"Results saved to {output_file}")
