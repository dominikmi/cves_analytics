import logging
import time
from typing import Any

import pandas as pd

from src.analysis.attack_scenario_analyzer import AttackScenarioAnalyzer
from src.core.vulnerability_analyzer import AttackChainAnalyzer


class AttackAnalyzer:
    """Analyzes attack scenarios and vulnerability chains."""

    def __init__(self, logger: logging.Logger):
        """Initialize the attack analyzer."""
        self.logger = logger

    def analyze(
        self,
        enriched_results: pd.DataFrame,
        scenario: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze attack scenarios and vulnerability dependencies."""
        start_time = time.time()

        try:
            if enriched_results.empty:
                self.logger.warning("No vulnerabilities to analyze")
                return {}

            self.logger.info("Starting attack scenario analysis")

            # Prepare data for attack chain analysis
            analysis_df = enriched_results.copy()

            # Map column names for analyzer
            if "cve_id" not in analysis_df.columns:
                analysis_df["cve_id"] = analysis_df.get("vuln_id", "Unknown")
            # Add required columns for analyzer
            if "impact" not in analysis_df.columns:
                analysis_df["impact"] = analysis_df.get(
                    "severity_reassessed",
                    "Unknown",
                )
            if "cwe" not in analysis_df.columns:
                analysis_df["cwe"] = analysis_df.get("cwe_id", "")
            if "severity" not in analysis_df.columns:
                analysis_df["severity"] = analysis_df.get(
                    "severity_reassessed",
                    "Unknown",
                )

            # Remove duplicates
            original_count = len(analysis_df)
            analysis_df = analysis_df.drop_duplicates(subset=["cve_id"], keep="first")
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
                analysis_df["severity_order"] = (
                    analysis_df["severity"].map(severity_order).fillna(0)
                )

                # Add CVSS score column (use highest available)
                cvss_columns = [
                    "cvss_v3_1_score",
                    "cvss_v3_0_score",
                    "cvss_v4_0_score",
                    "cvss_v2_0_score",
                ]
                analysis_df["cvss_score"] = 0
                for col in cvss_columns:
                    if col in analysis_df.columns:
                        analysis_df["cvss_score"] = analysis_df["cvss_score"].fillna(
                            0,
                        ) + analysis_df[col].fillna(0)

                # Sort by severity first, then CVSS score
                analysis_df = analysis_df.sort_values(
                    ["severity_order", "cvss_score"],
                    ascending=[False, False],
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
                if not analysis_df.empty:
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
                critical_vulns = enriched_results[
                    enriched_results["severity_reassessed"] == "Critical"
                ].to_dict("records")

            # Get high severity vulnerabilities
            high_vulns = []
            if "severity_reassessed" in enriched_results.columns:
                high_vulns = enriched_results[
                    enriched_results["severity_reassessed"] == "High"
                ].to_dict("records")

            # Identify entry point vulnerabilities (can be exploited without prior compromise)
            entry_points = []
            if not analysis_df.empty:
                try:
                    for _, row in analysis_df.iterrows():
                        cve_id = row["cve_id"]
                        # Entry points are vulnerabilities that don't require prior compromise
                        # This is a simplified check - in reality, this would be more complex
                        entry_points.append(cve_id)
                except Exception:
                    pass

            # NEW: Analyze scenario-based attack paths
            self.logger.info("Analyzing scenario-based attack paths...")
            scenario_analyzer = AttackScenarioAnalyzer()
            scenario_analysis = scenario_analyzer.analyze(enriched_results, scenario)

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
                "scenario_analysis": scenario_analysis,  # NEW: Include scenario analysis
            }

        except Exception as e:
            self.logger.error(
                f"Failed to analyze attack scenarios: {e!s}",
                exc_info=True,
            )
            raise
