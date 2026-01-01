import logging
import time
from typing import Any

import polars as pl

from src.analysis.attack_scenario_analyzer import AttackScenarioAnalyzer
from src.cli.pipeline_steps.kill_chain_analyzer import KillChainAnalyzer
from src.core.vulnerability_analyzer import AttackChainAnalyzer


class AttackAnalyzer:
    """Analyzes attack scenarios and vulnerability chains."""

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the attack analyzer."""
        self.logger = logger

    def analyze(
        self,
        enriched_results: pl.DataFrame,
        scenario: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze attack scenarios and vulnerability dependencies."""
        start_time = time.time()

        try:
            if enriched_results.is_empty():
                self.logger.warning("No vulnerabilities to analyze")
                return {}

            self.logger.info("Starting attack scenario analysis")

            # Prepare data for attack chain analysis
            analysis_df = enriched_results.clone()

            # Map column names for analyzer
            if "cve_id" not in analysis_df.columns:
                if "vuln_id" in analysis_df.columns:
                    analysis_df = analysis_df.with_columns(
                        pl.col("vuln_id").alias("cve_id")
                    )
                else:
                    analysis_df = analysis_df.with_columns(
                        pl.lit("Unknown").alias("cve_id")
                    )
            # Add required columns for analyzer
            if "impact" not in analysis_df.columns:
                if "severity_reassessed" in analysis_df.columns:
                    analysis_df = analysis_df.with_columns(
                        pl.col("severity_reassessed").alias("impact")
                    )
                else:
                    analysis_df = analysis_df.with_columns(
                        pl.lit("Unknown").alias("impact")
                    )
            if "cwe" not in analysis_df.columns:
                if "cwe_id" in analysis_df.columns:
                    analysis_df = analysis_df.with_columns(
                        pl.col("cwe_id").alias("cwe")
                    )
                else:
                    analysis_df = analysis_df.with_columns(pl.lit("").alias("cwe"))
            if "severity" not in analysis_df.columns:
                if "severity_reassessed" in analysis_df.columns:
                    analysis_df = analysis_df.with_columns(
                        pl.col("severity_reassessed").alias("severity")
                    )
                else:
                    analysis_df = analysis_df.with_columns(
                        pl.lit("Unknown").alias("severity")
                    )

            # Remove duplicates
            original_count = len(analysis_df)
            analysis_df = analysis_df.unique(subset=["cve_id"], keep="first")
            if len(analysis_df) < original_count:
                self.logger.info(
                    f"Removed {original_count - len(analysis_df)} duplicate CVEs",
                )

            # LIMIT DATA TO PREVENT PERFORMANCE ISSUES
            # Only analyze top vulnerabilities by severity to prevent exponential processing
            max_vulnerabilities = 200  # Limit to top 200 vulnerabilities
            if len(analysis_df) > max_vulnerabilities:
                # Sort by severity and CVSS score to get most critical vulnerabilities
                severity_order = {
                    "Critical": 4,
                    "High": 3,
                    "Medium": 2,
                    "Low": 1,
                    "Negligible": 0,
                }
                analysis_df = analysis_df.with_columns(
                    pl.col("severity")
                    .replace(severity_order)
                    .fill_null(0)
                    .alias("severity_order")
                )

                # Add CVSS score column (use highest available)
                cvss_columns = [
                    "cvss_v3_1_score",
                    "cvss_v3_0_score",
                    "cvss_v4_0_score",
                    "cvss_v2_0_score",
                ]
                analysis_df = analysis_df.with_columns(pl.lit(0.0).alias("cvss_score"))
                for col in cvss_columns:
                    if col in analysis_df.columns:
                        analysis_df = analysis_df.with_columns(
                            (
                                pl.col("cvss_score").fill_null(0)
                                + pl.col(col).fill_null(0)
                            ).alias("cvss_score")
                        )

                # Sort by severity first, then CVSS score
                analysis_df = analysis_df.sort(
                    ["severity_order", "cvss_score"],
                    descending=[True, True],
                ).head(max_vulnerabilities)

                self.logger.info(
                    f"Limited analysis to top {max_vulnerabilities} critical vulnerabilities "
                    f"(reduced from {original_count} total)",
                )

            self.logger.info(f"Analyzing {len(analysis_df)} unique CVEs")

            # Analyze attack chains
            self.logger.info(
                "Analyzing attack chains and vulnerability dependencies...",
            )
            attack_chains = []
            critical_paths = []
            graph_stats = {}

            try:
                if not analysis_df.is_empty():
                    self.logger.info("Initializing attack chain analyzer...")
                    analyzer = AttackChainAnalyzer(analysis_df)

                    # Get attack chains with progress logging
                    self.logger.info(
                        "Finding attack chains (this may take a moment)...",
                    )
                    attack_chains = analyzer.find_unique_chains()
                    self.logger.info(f"Found {len(attack_chains)} unique attack chains")

                    # Get critical paths (chains with 2+ vulnerabilities)
                    self.logger.info("Identifying critical attack paths...")
                    critical_paths = analyzer.get_critical_paths(min_length=2)
                    self.logger.info(
                        f"Found {len(critical_paths)} critical attack paths",
                    )

                    # Get graph statistics
                    self.logger.info("Computing attack graph statistics...")
                    graph_stats = analyzer.get_graph_statistics()
                    self.logger.info(
                        f"Attack graph: {graph_stats['total_nodes']} nodes, "
                        f"{graph_stats['total_edges']} edges, "
                        f"density: {graph_stats['density']:.3f}",
                    )
            except Exception as e:
                self.logger.warning(f"Could not analyze attack chains: {e!s}")

            # Get critical vulnerabilities by reassessed severity
            self.logger.info("Identifying critical vulnerabilities...")
            critical_vulns = []
            if "severity_reassessed" in enriched_results.columns:
                critical_vulns = enriched_results.filter(
                    pl.col("severity_reassessed") == "Critical"
                ).to_dicts()

            # Get high severity vulnerabilities
            high_vulns = []
            if "severity_reassessed" in enriched_results.columns:
                high_vulns = enriched_results.filter(
                    pl.col("severity_reassessed") == "High"
                ).to_dicts()

            # Identify entry point vulnerabilities (can be exploited without prior compromise)
            entry_points = []
            if not analysis_df.is_empty():
                try:
                    # Entry points are vulnerabilities that don't require prior compromise
                    # This is a simplified check - in reality, this would be more complex
                    entry_points = analysis_df["cve_id"].to_list()
                except Exception:
                    pass

            # Analyze scenario-based attack paths
            self.logger.info("Analyzing scenario-based attack paths...")
            scenario_analyzer = AttackScenarioAnalyzer()
            scenario_analysis = scenario_analyzer.analyze(enriched_results, scenario)

            # Analyze kill-chain probabilities
            self.logger.info("Analyzing kill-chain probabilities...")
            kill_chain_analyzer = KillChainAnalyzer(self.logger)
            service_catalog = self._load_service_catalog()
            kill_chain_analysis = kill_chain_analyzer.analyze(
                scenario, enriched_results, service_catalog
            )

            duration = time.time() - start_time
            self.logger.info(f"Vulnerability analysis completed in {duration:.2f}s")
            self.logger.info(
                f"Found {len(critical_vulns)} critical, {len(high_vulns)} high severity vulnerabilities",
            )

            return {
                "attack_chains": attack_chains,
                "critical_paths": critical_paths,
                "graph_statistics": graph_stats,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "entry_point_vulnerabilities": entry_points[:10],  # Top 10 entry points
                "total_vulnerabilities": len(enriched_results),
                "scenario_analysis": scenario_analysis,
                "kill_chain_analysis": kill_chain_analysis,  # NEW: Include kill-chain analysis
            }

        except Exception as e:
            self.logger.error(
                f"Failed to analyze attack scenarios: {e!s}",
                exc_info=True,
            )
            raise

    def _load_service_catalog(self) -> dict[str, Any]:
        """Load service catalog from config/services.yaml."""
        from pathlib import Path

        import yaml

        config_path = Path("config/services.yaml")
        if not config_path.exists():
            self.logger.warning("services.yaml not found, returning empty catalog")
            return {}

        with open(config_path) as f:
            return yaml.safe_load(f)
