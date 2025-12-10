import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from src.core.remediation_planner import RemediationPlanner
from src.core.risk_scoring import add_risk_scores, categorize_by_risk
from src.core.threat_intelligence import add_threat_indicators, get_threat_summary


class ReportGenerator:
    """Generates vulnerability assessment reports."""

    def __init__(self, logger: logging.Logger):
        """Initialize the report generator."""
        self.logger = logger
        self.remediation_planner = RemediationPlanner()

    def generate(
        self,
        scenario: dict[str, Any],
        scan_results: pd.DataFrame,
        enriched_results: pd.DataFrame,
        attack_analysis: dict[str, Any],
        output_dir: str,
    ) -> str:
        """Generate a comprehensive vulnerability assessment report."""
        start_time = time.time()

        try:
            self.logger.info("Generating vulnerability assessment report")

            report = []

            # Prepare enriched results with risk scores and threat indicators
            enriched_results = add_risk_scores(enriched_results)
            enriched_results = add_threat_indicators(enriched_results)

            # Report header
            report.append("=" * 80)
            report.append("VULNERABILITY ASSESSMENT REPORT")
            report.append("=" * 80)
            report.append(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )

            # PHASE 1: Executive Summary
            report.extend(
                self._generate_executive_summary(enriched_results, attack_analysis)
            )
            report.append("")

            # PHASE 1: Risk-Based Prioritization
            report.extend(self._generate_risk_prioritization(enriched_results))
            report.append("")

            # PHASE 1: Remediation Roadmap
            report.extend(self._generate_remediation_roadmap(enriched_results))
            report.append("")

            # Environment Summary
            report.append("ENVIRONMENT SUMMARY")
            report.append("-" * 80)
            metadata = scenario.get("metadata", {})
            report.append(f"Organization Size: {metadata.get('size', 'unknown')}")
            report.append(f"Geographic Reach: {metadata.get('reach', 'unknown')}")
            report.append(f"Industry: {metadata.get('industry', 'unknown')}")
            report.append(f"Environment: {metadata.get('environment', 'unknown')}")
            report.append(f"Total Services: {len(scenario.get('services', []))}")
            report.append(f"Total Hosts: {len(scenario.get('hosts', []))}")
            report.append("")

            # Scan Results Summary
            report.append("SCAN RESULTS SUMMARY")
            report.append("-" * 80)

            if not scan_results.empty:
                # Vulnerability count
                report.append(f"Total Vulnerabilities Found: {len(scan_results)}\n")

                # Severity distribution
                if "severity" in scan_results.columns:
                    severity_dist = scan_results["severity"].value_counts()
                    report.append("Vulnerability Severity Distribution:")
                    for severity, count in severity_dist.items():
                        report.append(f"  {severity}: {count}")

                # Bayesian risk by original severity (shows how Bayesian assessment differs)
                if (
                    "severity" in enriched_results.columns
                    and "risk_category" in enriched_results.columns
                ):
                    report.append("\nOriginal Severity → Bayesian Risk Assessment:")
                    transition_matrix = pd.crosstab(
                        enriched_results["severity"],
                        enriched_results["risk_category"],
                        margins=True,
                        margins_name="Total",
                    )
                    for row_label in transition_matrix.index:
                        row_data = transition_matrix.loc[row_label]
                        row_str = f"  {row_label}: " + ", ".join(
                            [f"{col}({val})" for col, val in row_data.items()]
                        )
                        report.append(row_str)

                # Top affected images
                if "image" in scan_results.columns:
                    top_images = scan_results["image"].value_counts().head(5)
                    if not top_images.empty:
                        report.append("\nTop Affected Images:")
                        for idx, (image, count) in enumerate(top_images.items(), 1):
                            report.append(f"  {idx}. {image}: {count} vulnerabilities")

            report.append("")

            # Attack Scenario Analysis
            report.append("ATTACK SCENARIO & VULNERABILITY ANALYSIS")
            report.append("-" * 80)

            if attack_analysis:
                report.append(
                    f"Total Vulnerabilities: {attack_analysis.get('total_vulnerabilities', 0)}\n"
                )

                # Graph statistics
                graph_stats = attack_analysis.get("graph_statistics", {})
                if graph_stats:
                    report.append("Attack Graph Statistics:")
                    report.append(
                        f"  Nodes (CVEs): {graph_stats.get('total_nodes', 0)}"
                    )
                    report.append(
                        f"  Edges (Dependencies): {graph_stats.get('total_edges', 0)}"
                    )
                    report.append(
                        f"  Graph Density: {graph_stats.get('density', 0):.3f}"
                    )
                    report.append(f"  Is DAG: {graph_stats.get('is_dag', False)}\n")

                # Scenario-based attack paths
                scenario_analysis = attack_analysis.get("scenario_analysis", {})
                attack_paths = (
                    scenario_analysis.get("attack_paths", [])
                    if scenario_analysis
                    else []
                )
                if attack_paths:
                    report.append(
                        f"Identified {len(attack_paths)} potential attack paths:"
                    )
                    for idx, path in enumerate(attack_paths[:10], 1):
                        report.append(
                            f"  {idx}. {path.get('description', 'Unknown attack path')}"
                        )

                        # Add team and asset context if available
                        steps = path.get("steps", [])
                        if steps:
                            step_info = steps[0]  # Get first step for context
                            service_name = step_info.get("service_name", "Unknown")
                            ownership = "Unknown"
                            # Try to find ownership from enriched results if available
                            if (
                                not enriched_results.empty
                                and "service_name" in enriched_results.columns
                                and "ownership" in enriched_results.columns
                            ):
                                ownership_match = (
                                    enriched_results[
                                        enriched_results["service_name"] == service_name
                                    ]["ownership"].iloc[0]
                                    if not enriched_results[
                                        enriched_results["service_name"] == service_name
                                    ].empty
                                    else "Unknown"
                                )
                                if pd.notna(ownership_match):
                                    ownership = ownership_match

                            report.append(
                                f"     Target Asset: {service_name} (Team: {ownership})"
                            )

                        risk_score = path.get("risk_score", "N/A")
                        likelihood = path.get("likelihood", "N/A")
                        impact = path.get("impact", "N/A")
                        report.append(
                            f"     Risk Score: {risk_score}, Likelihood: {likelihood}, Impact: {impact}"
                        )

                # Note: Attack chains and critical paths from graph analysis
                # are informational - prioritization is based on Bayesian risk

            report.append("")

            # Top Vulnerabilities by Bayesian Risk
            report.append("TOP VULNERABILITIES BY BAYESIAN RISK")
            report.append("-" * 80)

            if not enriched_results.empty:
                # Find the CVE column
                cve_col = None
                for col in ["cve_id", "vuln_id"]:
                    if col in enriched_results.columns:
                        cve_col = col
                        break

                image_col = None
                for col in ["image", "image_name", "container"]:
                    if col in enriched_results.columns:
                        image_col = col
                        break

                if cve_col:
                    # Sort by Bayesian risk score (primary), fallback to CVSS
                    if "bayesian_risk_score" in enriched_results.columns:
                        enriched_results["risk_sort"] = enriched_results[
                            "bayesian_risk_score"
                        ].fillna(-1)
                        top_vulns = enriched_results.nlargest(20, "risk_sort")
                    elif "cvss_score" in enriched_results.columns:
                        enriched_results["risk_sort"] = enriched_results[
                            "cvss_score"
                        ].fillna(-1)
                        top_vulns = enriched_results.nlargest(20, "risk_sort")
                    else:
                        top_vulns = enriched_results.head(20)

                    for idx, (_, row) in enumerate(top_vulns.iterrows(), 1):
                        img = row.get(image_col, "unknown") if image_col else "unknown"
                        service_name = row.get("service_name", "unknown")
                        cve_id = row[cve_col]

                        # Bayesian risk info first
                        bayes_risk = row.get("bayesian_risk_score", 0) or 0
                        risk_cat = row.get("risk_category", "Unknown")
                        ci_low = row.get("ci_low", 0) or 0
                        ci_high = row.get("ci_high", 0) or 0

                        report.append(f"{idx}. {cve_id} in {service_name} ({img})")
                        report.append(
                            f"   Bayesian Risk: {risk_cat} - P(Exploit): {bayes_risk:.1%} [{ci_low:.1%}-{ci_high:.1%}]"
                        )

                        # EPSS (prior probability)
                        if pd.notna(row.get("epss_score")):
                            epss = row["epss_score"]
                            report.append(f"   EPSS (Prior): {epss:.2%}")

                        # NLP-extracted attack category (explains why it's a top vuln)
                        nlp_attack_types = row.get("nlp_attack_types", [])
                        if (
                            nlp_attack_types
                            and isinstance(nlp_attack_types, list)
                            and len(nlp_attack_types) > 0
                        ):
                            attack_types_str = ", ".join(nlp_attack_types)
                            report.append(f"   Attack Category: {attack_types_str}")

                        nlp_context = row.get("nlp_context", [])
                        if (
                            nlp_context
                            and isinstance(nlp_context, list)
                            and len(nlp_context) > 0
                        ):
                            context_str = ", ".join(nlp_context)
                            report.append(f"   Attack Context: {context_str}")

                        # CVSS Details
                        if pd.notna(row.get("cvss_score")):
                            score = row["cvss_score"]
                            report.append(f"   CVSS Score: {score}")

                        # Add CWE if available
                        if pd.notna(row.get("cwe_id")):
                            cwe = row["cwe_id"]
                            report.append(f"   CWE: {cwe}")

                        # Add environment context if available
                        if pd.notna(row.get("exposure")):
                            exposure = row["exposure"]
                            report.append(f"   Exposure: {exposure}")

                        if pd.notna(row.get("asset_value")):
                            asset_value = row["asset_value"]
                            report.append(f"   Asset Value: {asset_value}")

                        if pd.notna(row.get("service_role")):
                            service_role = row["service_role"]
                            report.append(f"   Service Role: {service_role}")

                        # Add ownership if available
                        if pd.notna(row.get("ownership")):
                            ownership = row["ownership"]
                            report.append(f"   Ownership: {ownership}")

                        report.append("")  # Blank line for readability
                else:
                    report.append("No vulnerability data available")
            else:
                report.append("No vulnerabilities to report")

            report.append("")

            # Team-based Bayesian Risk Heatmap
            report.append("TEAM-BASED BAYESIAN RISK HEATMAP")
            report.append("-" * 80)

            if (
                not enriched_results.empty
                and "ownership" in enriched_results.columns
                and "risk_category" in enriched_results.columns
            ):
                try:
                    # Create a cross-tabulation of ownership vs Bayesian risk category
                    heatmap_data = pd.crosstab(
                        enriched_results["ownership"],
                        enriched_results["risk_category"],
                        margins=True,
                        margins_name="Total",
                    )

                    # Reorder columns to show risk categories in order
                    col_order = [
                        c
                        for c in [
                            "Critical",
                            "High",
                            "Medium",
                            "Low",
                            "Negligible",
                            "Total",
                        ]
                        if c in heatmap_data.columns
                    ]
                    heatmap_data = heatmap_data[col_order]

                    # Format and add to report
                    report.append(
                        "Ownership\\Risk".ljust(20)
                        + " ".join(str(col).ljust(10) for col in heatmap_data.columns)
                    )
                    for row_label in heatmap_data.index:
                        row_data = heatmap_data.loc[row_label]
                        row_str = str(row_label).ljust(20) + " ".join(
                            str(int(val)).ljust(10) for val in row_data
                        )
                        report.append(row_str)
                except Exception as e:
                    report.append(f"Error generating heatmap: {str(e)}")
            else:
                report.append("Team-based vulnerability data not available")

            report.append("")
            report.append("=" * 80)

            # Save report
            report_text = "\n".join(report)
            timestamp_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            report_path = Path(output_dir) / f"report_{timestamp_file}.txt"

            with open(report_path, "w") as f:
                f.write(report_text)

            duration = time.time() - start_time
            self.logger.info(f"Report generated in {duration:.2f}s")
            self.logger.info(f"Report saved to {report_path}")

            return str(report_path)

        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}", exc_info=True)
            raise

    def _generate_executive_summary(
        self, enriched_results: pd.DataFrame, attack_analysis: dict[str, Any]
    ) -> list[str]:
        """Generate executive summary section."""
        report = []
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 80)

        if enriched_results.empty:
            report.append("No vulnerability data available")
            return report

        # Calculate metrics using Bayesian risk_category
        total_vulns = len(enriched_results)

        # Use Bayesian risk_category if available, fallback to severity_reassessed
        if "risk_category" in enriched_results.columns:
            critical_count = (enriched_results["risk_category"] == "Critical").sum()
            high_count = (enriched_results["risk_category"] == "High").sum()
        elif "severity_reassessed" in enriched_results.columns:
            critical_count = (
                enriched_results["severity_reassessed"] == "Critical"
            ).sum()
            high_count = (enriched_results["severity_reassessed"] == "High").sum()
        else:
            critical_count = 0
            high_count = 0

        critical_high_count = critical_count + high_count
        critical_high_pct = (
            (critical_high_count / total_vulns * 100) if total_vulns > 0 else 0
        )

        # Effort estimates
        effort = self.remediation_planner.estimate_total_effort(enriched_results)
        estimated_hours = effort["total_hours"]
        estimated_weeks = effort["total_weeks"]

        # Risk assessment - use Bayesian risk score if available
        if "bayesian_risk_score" in enriched_results.columns:
            avg_risk_score = (
                enriched_results["bayesian_risk_score"].mean() * 10
            )  # Scale to 0-10
            avg_uncertainty = (
                enriched_results["uncertainty"].mean()
                if "uncertainty" in enriched_results.columns
                else 0
            )
        else:
            avg_risk_score = (
                enriched_results["risk_score"].mean()
                if "risk_score" in enriched_results.columns
                else 5.0
            )
            avg_uncertainty = 0

        if avg_risk_score >= 4.0:  # Bayesian: 40%+ exploitation probability
            business_risk = "CRITICAL"
        elif avg_risk_score >= 1.5:  # 15%+ exploitation probability
            business_risk = "HIGH"
        elif avg_risk_score >= 0.5:  # 5%+ exploitation probability
            business_risk = "MEDIUM"
        else:
            business_risk = "LOW"

        # Threat intelligence
        threat_summary = get_threat_summary(enriched_results)

        # Format output - Bayesian Risk focused
        report.append(f"Total Vulnerabilities Scanned: {total_vulns}")
        report.append(f"Average Exploitation Probability: {avg_risk_score:.2f}%")
        if avg_uncertainty > 0:
            report.append(f"Average Uncertainty: ±{avg_uncertainty:.2%}")
        report.append(f"Business Risk Level: {business_risk}")

        # Bayesian risk distribution (primary metric)
        if "risk_category" in enriched_results.columns:
            report.append("")
            report.append("Bayesian Risk Assessment:")
            risk_dist = enriched_results["risk_category"].value_counts()
            for category in ["Critical", "High", "Medium", "Low", "Negligible"]:
                count = risk_dist.get(category, 0)
                pct = (count / total_vulns * 100) if total_vulns > 0 else 0
                report.append(f"  {category}: {count} ({pct:.1f}%)")
            report.append("")
            report.append(
                f"Actionable Vulnerabilities (Critical+High+Medium): {critical_high_count + (enriched_results['risk_category'] == 'Medium').sum()}"
            )
            report.append(
                f"Critical/High Requiring Immediate Action: {critical_high_count} ({critical_high_pct:.1f}%)"
            )
        report.append("")
        report.append(
            f"Estimated Remediation Effort: {estimated_hours:.0f} person-hours"
        )
        report.append(f"Recommended Timeline: {estimated_weeks} weeks")
        report.append("")
        report.append(
            f"Known Exploited Vulnerabilities (KEV): {threat_summary['kev_count']}"
        )
        report.append(
            f"Public Exploits Available: {threat_summary['exploit_poc_count']}"
        )
        report.append(f"Metasploit Modules: {threat_summary['metasploit_count']}")
        report.append(
            f"High Exploitation Probability (EPSS>=0.5): {threat_summary['high_epss_count']}"
        )

        return report

    def _generate_risk_prioritization(
        self, enriched_results: pd.DataFrame
    ) -> list[str]:
        """Generate risk-based prioritization section using Bayesian risk assessment."""
        report = []
        report.append("RISK-BASED PRIORITIZATION (Bayesian)")
        report.append("-" * 80)

        if enriched_results.empty:
            report.append("No vulnerability data available")
            return report

        # Categorize by risk
        risk_categories = categorize_by_risk(enriched_results)

        # Check if we have Bayesian risk scores
        has_bayesian = "bayesian_risk_score" in enriched_results.columns

        # Critical vulnerabilities
        critical = risk_categories["critical"].head(10)
        report.append(
            f"CRITICAL (Fix ASAP): {len(risk_categories['critical'])} vulnerabilities"
        )
        if not critical.empty:
            for idx, (_, row) in enumerate(critical.iterrows(), 1):
                cve_id = row.get("cve_id", "unknown")
                service = row.get("service_name", "unknown")
                cvss = row.get("cvss_score", 0) or 0
                epss = row.get("epss_score", 0) or 0

                if has_bayesian:
                    bayes_risk = row.get("bayesian_risk_score", 0) or 0
                    ci_low = row.get("ci_low", 0) or 0
                    ci_high = row.get("ci_high", 0) or 0
                    report.append(
                        f"  {idx}. {cve_id} - P(Exploit): {bayes_risk:.1%} [{ci_low:.1%}-{ci_high:.1%}] in {service}"
                    )
                    report.append(f"      CVSS: {cvss:.1f}, EPSS: {epss:.2%}")
                else:
                    risk_score = row.get("risk_score", 0) or 0
                    report.append(
                        f"  {idx}. {cve_id} - Risk: {risk_score:.1f} (CVSS:{cvss:.1f} EPSS:{epss:.2f}) in {service}"
                    )
        report.append("")

        # Important/High vulnerabilities
        important = risk_categories["important"].head(10)
        report.append(
            f"HIGH PRIORITY (This Sprint): {len(risk_categories['important'])} vulnerabilities"
        )
        if not important.empty:
            for idx, (_, row) in enumerate(important.iterrows(), 1):
                cve_id = row.get("cve_id", "unknown")
                service = row.get("service_name", "unknown")

                if has_bayesian:
                    bayes_risk = row.get("bayesian_risk_score", 0) or 0
                    report.append(
                        f"  {idx}. {cve_id} - P(Exploit): {bayes_risk:.1%} in {service}"
                    )
                else:
                    risk_score = row.get("risk_score", 0) or 0
                    report.append(
                        f"  {idx}. {cve_id} - Risk: {risk_score:.1f} in {service}"
                    )
        report.append("")

        # Monitor/Medium vulnerabilities
        monitor = risk_categories["monitor"].head(5)
        report.append(
            f"MEDIUM PRIORITY (Plan Fix): {len(risk_categories['monitor'])} vulnerabilities"
        )
        if not monitor.empty:
            for idx, (_, row) in enumerate(monitor.iterrows(), 1):
                cve_id = row.get("cve_id", "unknown")
                if has_bayesian:
                    bayes_risk = row.get("bayesian_risk_score", 0) or 0
                    report.append(f"  {idx}. {cve_id} - P(Exploit): {bayes_risk:.1%}")
                else:
                    risk_score = row.get("risk_score", 0) or 0
                    report.append(f"  {idx}. {cve_id} - Risk: {risk_score:.1f}")
        report.append("")

        # Low priority
        report.append(
            f"LOW PRIORITY (Backlog): {len(risk_categories['low'])} vulnerabilities"
        )

        return report

    def _generate_remediation_roadmap(
        self, enriched_results: pd.DataFrame
    ) -> list[str]:
        """Generate remediation roadmap section."""
        report = []
        report.append("REMEDIATION ROADMAP")
        report.append("-" * 80)

        if enriched_results.empty:
            report.append("No vulnerability data available")
            return report

        # Create roadmap
        roadmap = self.remediation_planner.create_remediation_roadmap(enriched_results)

        # Phase 1
        phase1 = roadmap["phase1"]
        report.append(f"PHASE 1: Emergency ({phase1['timeline']})")
        report.append(f"  Vulnerabilities: {phase1['count']}")
        report.append(
            f"  Estimated Effort: {phase1['effort_hours']:.0f} hours ({phase1['timeline_weeks']} weeks)"
        )
        report.append(f"  Severity: {phase1['severity']}")
        if not phase1["vulns"].empty:
            for idx, (_, row) in enumerate(phase1["vulns"].head(5).iterrows(), 1):
                cve_id = row.get("cve_id", "unknown")
                service = row.get("service_name", "unknown")
                report.append(f"    {idx}. {cve_id} in {service}")
            if len(phase1["vulns"]) > 5:
                report.append(f"    ... and {len(phase1['vulns']) - 5} more")
        report.append("")

        # Phase 2
        phase2 = roadmap["phase2"]
        report.append(f"PHASE 2: High Priority ({phase2['timeline']})")
        report.append(f"  Vulnerabilities: {phase2['count']}")
        report.append(
            f"  Estimated Effort: {phase2['effort_hours']:.0f} hours ({phase2['timeline_weeks']} weeks)"
        )
        report.append(f"  Severity: {phase2['severity']}")
        report.append("")

        # Phase 3
        phase3 = roadmap["phase3"]
        report.append(f"PHASE 3: Medium Priority ({phase3['timeline']})")
        report.append(f"  Vulnerabilities: {phase3['count']}")
        report.append(
            f"  Estimated Effort: {phase3['effort_hours']:.0f} hours ({phase3['timeline_weeks']} weeks)"
        )
        report.append(f"  Severity: {phase3['severity']}")

        return report

    def generate_pdf_report(
        self,
        scenario: dict[str, Any],
        scan_results: pd.DataFrame,
        enriched_results: pd.DataFrame,
        attack_analysis: dict[str, Any],
        output_dir: str,
        plots_dir: str = None,
    ) -> str:
        """Generate a comprehensive PDF vulnerability assessment report with plots."""
        start_time = time.time()

        try:
            self.logger.info("Generating PDF vulnerability assessment report")

            # Import PDF generation libraries
            import os
            from pathlib import Path

            import matplotlib.pyplot as plt
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                Image,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )

            # Function to generate team-based vulnerability heatmap
            def generate_team_heatmap(
                enriched_results: pd.DataFrame, plots_dir: str
            ) -> str:
                """Generate a heatmap showing reassessed severities per team."""
                if (
                    not enriched_results.empty
                    and "ownership" in enriched_results.columns
                    and "severity_reassessed" in enriched_results.columns
                ):
                    try:
                        # Create a cross-tabulation of ownership vs reassessed severity
                        heatmap_data = pd.crosstab(
                            enriched_results["ownership"],
                            enriched_results["severity_reassessed"],
                        )

                        # Create the heatmap plot
                        plt.figure(figsize=(10, 6))

                        # Since seaborn is not available, use matplotlib's imshow
                        import numpy as np

                        # Create heatmap using matplotlib
                        fig, ax = plt.subplots(figsize=(10, 6))

                        # Create heatmap data matrix
                        teams = list(heatmap_data.index)
                        severities = list(heatmap_data.columns)
                        data_matrix = heatmap_data.values

                        # Create heatmap
                        im = ax.imshow(data_matrix, cmap="YlOrRd", aspect="auto")

                        # Set ticks and labels
                        ax.set_xticks(np.arange(len(severities)))
                        ax.set_yticks(np.arange(len(teams)))
                        ax.set_xticklabels(severities)
                        ax.set_yticklabels(teams)

                        # Rotate the tick labels and set their alignment
                        plt.setp(
                            ax.get_xticklabels(),
                            rotation=45,
                            ha="right",
                            rotation_mode="anchor",
                        )

                        # Loop over data dimensions and create text annotations
                        for i in range(len(teams)):
                            for j in range(len(severities)):
                                ax.text(
                                    j,
                                    i,
                                    str(data_matrix[i, j]),
                                    ha="center",
                                    va="center",
                                    color="black",
                                )

                        ax.set_title("Vulnerability Distribution by Team and Severity")
                        ax.set_xlabel("Reassessed Severity")
                        ax.set_ylabel("Team Ownership")

                        # Add colorbar
                        cbar = plt.colorbar(im, ax=ax)
                        cbar.set_label("Number of Vulnerabilities")

                        plt.tight_layout()

                        # Save the plot
                        heatmap_path = os.path.join(
                            plots_dir, "team_vulnerability_heatmap.png"
                        )
                        plt.savefig(heatmap_path, dpi=300, bbox_inches="tight")
                        plt.close()

                        return heatmap_path
                    except Exception as e:
                        print(f"Error generating heatmap: {str(e)}")
                        return None
                return None

            # Create PDF document
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            pdf_path = (
                Path(output_dir) / f"vulnerability_assessment_report_{timestamp}.pdf"
            )
            doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)

            # Create styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                spaceAfter=30,
                alignment=1,  # Center alignment
            )
            heading_style = ParagraphStyle(
                "CustomHeading",
                parent=styles["Heading2"],
                fontSize=16,
                spaceAfter=12,
                spaceBefore=20,
            )
            subheading_style = ParagraphStyle(
                "CustomSubHeading",
                parent=styles["Heading3"],
                fontSize=14,
                spaceAfter=10,
                spaceBefore=15,
            )
            normal_style = ParagraphStyle(
                "CustomNormal", parent=styles["Normal"], fontSize=10, spaceAfter=6
            )
            code_style = ParagraphStyle(
                "CustomCode",
                parent=styles["Normal"],
                fontSize=8,
                fontName="Courier",
                spaceAfter=4,
            )

            # Build story (content) for PDF
            story = []

            # Title
            story.append(Paragraph("VULNERABILITY ASSESSMENT REPORT", title_style))
            story.append(
                Paragraph(
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    normal_style,
                )
            )
            story.append(Spacer(1, 0.2 * inch))

            # Environment Summary
            story.append(Paragraph("ENVIRONMENT SUMMARY", heading_style))
            metadata = scenario.get("metadata", {})
            env_data = [
                ["Organization Size:", metadata.get("size", "unknown")],
                ["Geographic Reach:", metadata.get("reach", "unknown")],
                ["Industry:", metadata.get("industry", "unknown")],
                ["Environment:", metadata.get("environment", "unknown")],
                ["Total Services:", str(len(scenario.get("services", [])))],
                ["Total Hosts:", str(len(scenario.get("hosts", [])))],
            ]
            env_table = Table(env_data, colWidths=[2 * inch, 3 * inch])
            env_table.setStyle(
                TableStyle(
                    [
                        ("ALIGN", (0, 0), (0, -1), "LEFT"),
                        ("ALIGN", (1, 0), (1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                        ("FONTSIZE", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.append(env_table)
            story.append(Spacer(1, 0.2 * inch))

            # Scan Results Summary
            story.append(Paragraph("SCAN RESULTS SUMMARY", heading_style))
            if not scan_results.empty:
                total_vulns = len(scan_results)
                severity_counts = (
                    scan_results["severity"].value_counts()
                    if "severity" in scan_results.columns
                    else {}
                )
                story.append(
                    Paragraph(
                        f"Total Vulnerabilities Found: {total_vulns}", normal_style
                    )
                )

                # Severity distribution table
                severity_data = [["Severity", "Count"]]
                for severity, count in severity_counts.items():
                    severity_data.append([severity, str(count)])

                severity_table = Table(severity_data, colWidths=[2 * inch, 1 * inch])
                severity_table.setStyle(
                    TableStyle(
                        [
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ]
                    )
                )
                story.append(severity_table)
            else:
                story.append(Paragraph("No scan results available", normal_style))

            story.append(Spacer(1, 0.2 * inch))

            # Vulnerability Severity Distribution
            story.append(
                Paragraph("VULNERABILITY SEVERITY DISTRIBUTION", heading_style)
            )
            if not enriched_results.empty:
                reassessed_counts = (
                    enriched_results["severity_reassessed"].value_counts()
                    if "severity_reassessed" in enriched_results.columns
                    else {}
                )
                story.append(
                    Paragraph(
                        f"Total Reassessed Vulnerabilities: {len(enriched_results)}",
                        normal_style,
                    )
                )

                # Reassessed severity distribution table
                reassessed_data = [["Reassessed Severity", "Count"]]
                for severity, count in reassessed_counts.items():
                    reassessed_data.append([severity, str(count)])

                reassessed_table = Table(
                    reassessed_data, colWidths=[2 * inch, 1 * inch]
                )
                reassessed_table.setStyle(
                    TableStyle(
                        [
                            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ]
                    )
                )
                story.append(reassessed_table)
            else:
                story.append(Paragraph("No enriched results available", normal_style))

            story.append(Spacer(1, 0.2 * inch))

            # Severity Transition Matrix
            story.append(
                Paragraph(
                    "SEVERITY TRANSITION MATRIX (Original → Reassessed)", heading_style
                )
            )
            if (
                not enriched_results.empty
                and "severity" in enriched_results.columns
                and "severity_reassessed" in enriched_results.columns
            ):
                # Create a cross-tabulation of original vs reassessed severity
                transition_matrix = pd.crosstab(
                    enriched_results["severity"],
                    enriched_results["severity_reassessed"],
                    margins=True,
                    margins_name="Total",
                )

                # Convert to table data
                matrix_data = [
                    ["Original → Reassessed"] + list(transition_matrix.columns)
                ]
                for row_label in transition_matrix.index:
                    row_data = transition_matrix.loc[row_label]
                    matrix_data.append(
                        [str(row_label)] + [str(val) for val in row_data]
                    )

                matrix_table = Table(
                    matrix_data,
                    colWidths=[1.2 * inch]
                    + [0.8 * inch] * (len(transition_matrix.columns)),
                )
                matrix_table.setStyle(
                    TableStyle(
                        [
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                        ]
                    )
                )
                story.append(matrix_table)
            else:
                story.append(
                    Paragraph("Severity transition data not available", normal_style)
                )

            story.append(Spacer(1, 0.3 * inch))

            # Attack Scenario & Vulnerability Analysis
            story.append(
                Paragraph("ATTACK SCENARIO & VULNERABILITY ANALYSIS", heading_style)
            )

            # Try to get scenario analysis from the nested structure
            scenario_analysis = {}
            if attack_analysis and isinstance(attack_analysis, dict):
                # Check if it's the new format with nested scenario_analysis
                if "scenario_analysis" in attack_analysis:
                    scenario_analysis = attack_analysis.get("scenario_analysis", {})
                else:
                    # Fallback to direct attack analysis
                    scenario_analysis = attack_analysis

            attack_paths = scenario_analysis.get("attack_paths", [])
            if attack_paths:
                story.append(
                    Paragraph(
                        f"Identified {len(attack_paths)} potential attack paths:",
                        normal_style,
                    )
                )
                # Show top 10 attack paths
                for idx, path in enumerate(attack_paths[:10], 1):
                    story.append(
                        Paragraph(
                            f"{idx}. {path.get('description', 'Unknown attack path')}",
                            normal_style,
                        )
                    )

                    # Add team and asset context if available
                    steps = path.get("steps", [])
                    if steps:
                        step_info = steps[0]  # Get first step for context
                        service_name = step_info.get("service_name", "Unknown")
                        ownership = "Unknown"
                        # Try to find ownership from enriched results if available
                        if (
                            not enriched_results.empty
                            and "service_name" in enriched_results.columns
                            and "ownership" in enriched_results.columns
                        ):
                            ownership_match = (
                                enriched_results[
                                    enriched_results["service_name"] == service_name
                                ]["ownership"].iloc[0]
                                if not enriched_results[
                                    enriched_results["service_name"] == service_name
                                ].empty
                                else "Unknown"
                            )
                            if pd.notna(ownership_match):
                                ownership = ownership_match

                        story.append(
                            Paragraph(
                                f"   Target Asset: {service_name} (Team: {ownership})",
                                code_style,
                            )
                        )

                    risk_score = path.get("risk_score", "N/A")
                    story.append(Paragraph(f"   Risk Score: {risk_score}", code_style))
                    likelihood = path.get("likelihood", "N/A")
                    impact = path.get("impact", "N/A")
                    story.append(
                        Paragraph(
                            f"   Likelihood: {likelihood}, Impact: {impact}", code_style
                        )
                    )
            else:
                # Show existing attack chain analysis if available
                if attack_analysis and isinstance(attack_analysis, dict):
                    # Existing attack chain information
                    critical_paths = attack_analysis.get("critical_paths", [])
                    attack_chains = attack_analysis.get("attack_chains", [])
                    entry_points = attack_analysis.get(
                        "entry_point_vulnerabilities", []
                    )

                    if critical_paths or attack_chains or entry_points:
                        story.append(Paragraph("Attack Chain Analysis:", normal_style))
                        if critical_paths:
                            story.append(
                                Paragraph(
                                    f"  Critical Attack Paths: {len(critical_paths)}",
                                    code_style,
                                )
                            )
                        if attack_chains:
                            story.append(
                                Paragraph(
                                    f"  Total Attack Chains: {len(attack_chains)}",
                                    code_style,
                                )
                            )
                        if entry_points:
                            story.append(
                                Paragraph(
                                    f"  Entry Point Vulnerabilities: {len(entry_points)}",
                                    code_style,
                                )
                            )
                    else:
                        story.append(
                            Paragraph("No attack scenarios identified", normal_style)
                        )
                else:
                    story.append(
                        Paragraph("No attack scenarios identified", normal_style)
                    )

            story.append(Spacer(1, 0.3 * inch))

            # Team-based Vulnerability Heatmap
            story.append(Paragraph("TEAM-BASED VULNERABILITY HEATMAP", heading_style))
            if (
                not enriched_results.empty
                and "ownership" in enriched_results.columns
                and "severity_reassessed" in enriched_results.columns
            ):
                # Create a cross-tabulation of ownership vs reassessed severity
                try:
                    heatmap_data = pd.crosstab(
                        enriched_results["ownership"],
                        enriched_results["severity_reassessed"],
                        margins=True,
                        margins_name="Total",
                    )

                    # Convert to table data
                    heatmap_table_data = [
                        ["Ownership \\ Severity"] + list(heatmap_data.columns)
                    ]
                    for row_label in heatmap_data.index:
                        row_data = heatmap_data.loc[row_label]
                        heatmap_table_data.append(
                            [str(row_label)] + [str(int(val)) for val in row_data]
                        )

                    heatmap_table = Table(
                        heatmap_table_data,
                        colWidths=[1.2 * inch]
                        + [0.8 * inch] * (len(heatmap_data.columns)),
                    )
                    heatmap_table.setStyle(
                        TableStyle(
                            [
                                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                                ("FONTSIZE", (0, 0), (-1, -1), 9),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                                ("GRID", (0, 0), (-1, -1), 1, colors.black),
                                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                            ]
                        )
                    )
                    story.append(heatmap_table)
                except Exception as e:
                    story.append(
                        Paragraph(f"Error generating heatmap: {str(e)}", normal_style)
                    )
            else:
                story.append(
                    Paragraph(
                        "Team-based vulnerability data not available", normal_style
                    )
                )

            story.append(Spacer(1, 0.3 * inch))

            # Generate and add team heatmap
            heatmap_path = None
            if plots_dir and os.path.exists(plots_dir):
                heatmap_path = generate_team_heatmap(enriched_results, plots_dir)

            # Add plots if directory is provided
            if plots_dir and os.path.exists(plots_dir):
                plot_files = [
                    "severity_distribution.png",
                    "cvss_distribution.png",
                    "top_vulnerable_images.png",
                    "reassessed_severity_vs_epss_violin.png",
                    "cvss_vs_epss_by_reassessed_severity.png",
                    "severity_transition_heatmap.png",
                    "epss_distribution_original_vs_reassessed.png",
                ]

                # Add team heatmap if generated
                if heatmap_path and os.path.exists(heatmap_path):
                    plot_files.insert(0, "team_vulnerability_heatmap.png")

                story.append(Paragraph("DATA VISUALIZATIONS", heading_style))

                for plot_file in plot_files:
                    plot_path = os.path.join(plots_dir, plot_file)
                    if os.path.exists(plot_path):
                        # Add plot title
                        title = plot_file.replace(".png", "").replace("_", " ").title()
                        story.append(Paragraph(title, subheading_style))

                        # Add image
                        try:
                            story.append(
                                Image(plot_path, width=6 * inch, height=4 * inch)
                            )
                        except Exception as e:
                            story.append(
                                Paragraph(f"Error loading plot: {str(e)}", normal_style)
                            )

                        story.append(Spacer(1, 0.2 * inch))

            # Top Vulnerabilities - Detailed Assessment
            story.append(
                Paragraph("TOP VULNERABILITIES - DETAILED ASSESSMENT", heading_style)
            )
            if not enriched_results.empty:
                # Sort by CVSS score or severity
                if "cvss_score" in enriched_results.columns:
                    enriched_results_sorted = enriched_results.nlargest(
                        20, "cvss_score"
                    )
                else:
                    severity_order = {
                        "Critical": 5,
                        "High": 4,
                        "Medium": 3,
                        "Low": 2,
                        "Negligible": 1,
                        "Unknown": 0,
                    }
                    sev_col = enriched_results.get("severity", "Unknown")
                    enriched_results["severity_rank"] = sev_col.map(
                        lambda x: severity_order.get(x, 0)
                    )
                    enriched_results_sorted = enriched_results.nlargest(
                        20, "severity_rank"
                    )

                # Add detailed vulnerability information
                for idx, (_, row) in enumerate(enriched_results_sorted.iterrows(), 1):
                    cve_id = row.get("cve_id", row.get("vuln_id", "N/A"))
                    image = row.get("image_name", "N/A")
                    service_name = row.get("service_name", "N/A")

                    title = f"{idx}. {cve_id} in {service_name} ({image})"
                    story.append(Paragraph(title, normal_style))

                    # Original severity
                    original_severity = row.get("severity", "Unknown")
                    story.append(
                        Paragraph(
                            f"   Original Severity: {original_severity}", code_style
                        )
                    )

                    # CVSS Details
                    if pd.notna(row.get("cvss_score")):
                        score = row["cvss_score"]
                        version = row.get("cvss_version", "Unknown")
                        story.append(
                            Paragraph(f"   CVSS {version}: {score}", code_style)
                        )

                        # Add vector if available
                        if pd.notna(row.get("cvss_vector")):
                            vector = row["cvss_vector"]
                            story.append(Paragraph(f"   Vector: {vector}", code_style))

                    # Reassessed severity with justification
                    if pd.notna(row.get("severity_reassessed")):
                        reassessed = row["severity_reassessed"]
                        story.append(
                            Paragraph(f"   Reassessed: {reassessed}", code_style)
                        )

                        # Add reassessment reason/criteria
                        if pd.notna(row.get("reassessment_reason")):
                            reason = row["reassessment_reason"]
                            story.append(Paragraph(f"   Reason: {reason}", code_style))

                    # Add EPSS if available
                    if pd.notna(row.get("epss_score")):
                        epss = row["epss_score"]
                        story.append(Paragraph(f"   EPSS Score: {epss}", code_style))

                    # Add CWE if available
                    if pd.notna(row.get("cwe_id")):
                        cwe = row["cwe_id"]
                        story.append(Paragraph(f"   CWE: {cwe}", code_style))

                    # Add environment context if available
                    if pd.notna(row.get("exposure")):
                        exposure = row["exposure"]
                        story.append(Paragraph(f"   Exposure: {exposure}", code_style))

                    if pd.notna(row.get("asset_value")):
                        asset_value = row["asset_value"]
                        story.append(
                            Paragraph(f"   Asset Value: {asset_value}", code_style)
                        )

                    if pd.notna(row.get("service_role")):
                        service_role = row["service_role"]
                        story.append(
                            Paragraph(f"   Service Role: {service_role}", code_style)
                        )

                    # Add ownership if available
                    if pd.notna(row.get("ownership")):
                        ownership = row["ownership"]
                        story.append(
                            Paragraph(f"   Ownership: {ownership}", code_style)
                        )

                    story.append(Spacer(1, 0.1 * inch))
            else:
                story.append(Paragraph("No vulnerability data available", normal_style))

            # Build PDF
            doc.build(story)

            duration = time.time() - start_time
            self.logger.info(f"PDF report generated in {duration:.2f}s")
            self.logger.info(f"PDF report saved to {pdf_path}")

            return str(pdf_path)

        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {str(e)}", exc_info=True)
            raise
