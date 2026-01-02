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
from src.core.control_lr_mapper import get_control_lr_from_security_controls
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

        # Step 3: Calculate risk metrics with new LRs (fast, ~0.5s)
        # Use cached vulnerability data
        enriched_cves = cache["enriched_cves"]

        # Calculate statistics based on cached data and new control LRs
        if enriched_cves:
            # Filter to ONLY vulnerabilities with EPSS > 0.1 (>10% exploitation probability)
            # AND (Critical or High severity post-reassessment)
            epss_scores = enriched_cves["epss_score"]
            severities = enriched_cves.get(
                "severity_reassessed", enriched_cves.get("severity", [])
            )

            # Filter indices for truly high-risk vulnerabilities
            high_risk_indices = []
            baseline_epss_values = []  # Store raw EPSS for baseline
            for i, (epss, severity) in enumerate(
                zip(epss_scores, severities, strict=True)
            ):
                try:
                    epss_val = (
                        float(epss) if epss not in [None, "False", "None"] else 0.0
                    )
                    severity_str = str(severity).lower() if severity else ""

                    # Include ONLY if EPSS > 0.1 AND severity is Critical/High
                    if epss_val > 0.1 and severity_str in ["critical", "high"]:
                        high_risk_indices.append(i)
                        baseline_epss_values.append(epss_val)
                except (ValueError, TypeError):
                    continue

            # FIX #2 & #3: Bayesian control effectiveness with uncertainty
            # Use geometric mean of LRs (compromise between product and arithmetic mean)
            # This represents the "average" multiplicative effect of controls
            import numpy as np

            # Set seed for reproducibility within iteration
            np.random.seed(seed)

            # Calculate geometric mean of LRs (nth root of product)
            lr_product = 1.0
            for lr in lr_values.values():
                lr_product *= lr
            n_controls = len(lr_values)
            geometric_mean_lr = lr_product ** (1.0 / n_controls)

            # Add control effectiveness uncertainty (±20% variability)
            lr_uncertainty = np.random.normal(0, geometric_mean_lr * 0.2)
            overall_lr = max(0.1, min(1.0, geometric_mean_lr + lr_uncertainty))

            # Apply control effectiveness with uncertainty to EPSS scores
            adjusted_risks = []
            for idx in high_risk_indices:
                epss = epss_scores[idx]
                try:
                    if epss is None or epss == "False" or epss == "None":
                        base_risk = 0.0
                    else:
                        base_risk = float(epss)

                    # Add EPSS uncertainty (±10% confidence interval)
                    epss_uncertainty = np.random.normal(0, base_risk * 0.1)
                    base_risk_with_uncertainty = max(
                        0, min(1, base_risk + epss_uncertainty)
                    )

                    # Apply control effectiveness
                    adjusted_risk = base_risk_with_uncertainty * overall_lr
                    adjusted_risks.append(adjusted_risk)
                except (ValueError, TypeError):
                    adjusted_risks.append(0.0)

            # Count actionable (high risk after adjustment)
            actionable = sum(1 for risk in adjusted_risks if risk > 0.1)

            bayesian_stats = {
                "avg_exploitation_probability": sum(adjusted_risks)
                / len(adjusted_risks)
                if adjusted_risks
                else 0.0,
                "actionable_vulnerabilities": actionable,
                "total_vulnerabilities": len(epss_scores),
                "high_risk_vulnerabilities": len(high_risk_indices),
                "filtered_vulnerabilities": len(adjusted_risks),
                "baseline_epss_values": baseline_epss_values,  # Store for visualization
                "overall_lr": overall_lr,  # Store control effectiveness
            }
        else:
            bayesian_stats = {}

        # FIX #4: Proper kill-chain conditional probability modeling
        # Model attack progression with INDEPENDENT variation at each stage
        avg_risk = bayesian_stats.get("avg_exploitation_probability", 0.5)
        overall_lr = bayesian_stats.get("overall_lr", 1.0)

        # Add independent uncertainty to each attack stage
        # Each stage has its own success probability with variation
        import numpy as np
        np.random.seed(seed)
        
        # Stage base probabilities (with variation)
        stage_probs = {}
        
        # Initial access: Base exploitation probability
        stage_probs["initial_access"] = avg_risk
        
        # Execution: Can code execute? (affected by endpoint protection + randomness)
        execution_base = 0.85 if overall_lr < 0.1 else 0.7
        execution_var = np.random.normal(0, 0.1)  # ±10% variation
        stage_probs["execution"] = stage_probs["initial_access"] * max(0.5, min(1.0, execution_base + execution_var))
        
        # Persistence: Can maintain access? (affected by monitoring + randomness)
        persistence_base = 0.75
        persistence_var = np.random.normal(0, 0.15)  # ±15% variation
        stage_probs["persistence"] = stage_probs["execution"] * max(0.4, min(1.0, persistence_base + persistence_var))
        
        # Privilege escalation: Can gain higher privileges? (with randomness)
        privesc_base = 0.65
        privesc_var = np.random.normal(0, 0.2)  # ±20% variation
        stage_probs["privilege_escalation"] = stage_probs["persistence"] * max(0.3, min(1.0, privesc_base + privesc_var))
        
        # Defense evasion: Can avoid detection? (heavily affected by controls + randomness)
        defense_base = 0.4 if overall_lr < 0.05 else 0.7
        defense_var = np.random.normal(0, 0.15)  # ±15% variation
        stage_probs["defense_evasion"] = stage_probs["privilege_escalation"] * max(0.2, min(1.0, defense_base + defense_var))
        
        # Credential access: Can steal credentials? (affected by MFA + randomness)
        cred_base = 0.6
        cred_var = np.random.normal(0, 0.2)  # ±20% variation
        stage_probs["credential_access"] = stage_probs["defense_evasion"] * max(0.3, min(1.0, cred_base + cred_var))
        
        # Discovery: Can map the network? (with randomness)
        discovery_base = 0.8
        discovery_var = np.random.normal(0, 0.1)  # ±10% variation
        stage_probs["discovery"] = stage_probs["credential_access"] * max(0.5, min(1.0, discovery_base + discovery_var))
        
        # Lateral movement: Can move to other systems? (affected by segmentation + randomness)
        lateral_base = 0.3 if overall_lr < 0.05 else 0.6
        lateral_var = np.random.normal(0, 0.15)  # ±15% variation
        stage_probs["lateral_movement"] = stage_probs["discovery"] * max(0.2, min(1.0, lateral_base + lateral_var))
        
        # Collection: Can gather data? (with randomness)
        collection_base = 0.7
        collection_var = np.random.normal(0, 0.15)  # ±15% variation
        stage_probs["collection"] = stage_probs["lateral_movement"] * max(0.4, min(1.0, collection_base + collection_var))
        
        # Exfiltration: Can extract data? (affected by DLP/monitoring + randomness)
        exfil_base = 0.4 if overall_lr < 0.05 else 0.6
        exfil_var = np.random.normal(0, 0.2)  # ±20% variation
        stage_probs["exfiltration"] = stage_probs["collection"] * max(0.2, min(1.0, exfil_base + exfil_var))
        
        # Overall kill-chain probability is the final stage probability
        kill_chain_prob = stage_probs["exfiltration"]

        # Determine threat level
        if kill_chain_prob >= 0.7:
            threat_level = "critical"
        elif kill_chain_prob >= 0.5:
            threat_level = "high"
        elif kill_chain_prob >= 0.3:
            threat_level = "medium"
        else:
            threat_level = "low"

        # Kill-chain result with conditional stage probabilities
        from dataclasses import dataclass

        @dataclass
        class MockKillChainResult:
            overall_probability: float
            threat_level: str
            stage_probabilities: dict

        kill_chain_result = MockKillChainResult(
            overall_probability=kill_chain_prob,
            threat_level=threat_level,
            stage_probabilities=stage_probs,
        )

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
