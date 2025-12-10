"""Attack scenario analyzer for vulnerability assessment pipeline."""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


class AttackVector(Enum):
    """Common attack vectors."""

    NETWORK = "network"
    REMOTE_CODE_EXECUTION = "rce"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    AUTHENTICATION_BYPASS = "auth_bypass"


class ServiceRole(Enum):
    """Common service roles."""

    WEB_SERVER = "web_server"
    DATABASE = "database"
    LOAD_BALANCER = "load_balancer"
    MESSAGE_BROKER = "message_broker"
    CACHE = "cache"
    API_SERVER = "api_server"
    APP_SERVER = "app_server"
    CI_CD = "cicd"
    MONITORING = "monitoring"
    REGISTRY = "registry"


@dataclass
class AttackStep:
    """Represents a single step in an attack path."""

    service_name: str
    service_role: str
    vulnerability_id: str
    cve_id: str
    attack_vector: str
    description: str
    cvss_score: float
    epss_score: float


@dataclass
class AttackPath:
    """Represents a complete attack path."""

    steps: list[AttackStep]
    risk_score: float
    description: str
    likelihood: float  # 0.0 to 1.0
    impact: float  # 0.0 to 1.0


class AttackScenarioAnalyzer:
    """Analyzes vulnerability data to identify potential attack scenarios."""

    def __init__(self):
        """Initialize the attack scenario analyzer."""
        self.logger = logging.getLogger(self.__class__.__name__)

    def analyze(
        self, enriched_results: pd.DataFrame, scenario: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze vulnerability data to identify potential attack scenarios."""
        try:
            self.logger.info("Starting attack scenario analysis")

            if enriched_results.empty:
                self.logger.warning("No enriched results to analyze")
                return {"attack_paths": []}

            # Identify potential attack paths
            attack_paths = []

            # 1. Find internet-facing services with critical vulnerabilities
            internet_attack_paths = self._find_internet_attack_paths(enriched_results)
            attack_paths.extend(internet_attack_paths)

            # 2. Find privilege escalation opportunities
            priv_esc_paths = self._find_privilege_escalation_paths(enriched_results)
            attack_paths.extend(priv_esc_paths)

            # 3. Find lateral movement opportunities
            lateral_paths = self._find_lateral_movement_paths(enriched_results)
            attack_paths.extend(lateral_paths)

            # 4. Find data exfiltration paths
            data_paths = self._find_data_exfiltration_paths(enriched_results)
            attack_paths.extend(data_paths)

            # Remove duplicates and sort by risk score
            unique_paths = self._deduplicate_attack_paths(attack_paths)
            unique_paths.sort(key=lambda x: x.risk_score, reverse=True)

            result = {
                "attack_paths": [
                    self._path_to_dict(path) for path in unique_paths[:10]
                ],  # Top 10
                "total_identified_paths": len(unique_paths),
                "high_risk_paths": len(
                    [p for p in unique_paths if p.risk_score >= 8.0]
                ),
                "medium_risk_paths": len(
                    [p for p in unique_paths if 5.0 <= p.risk_score < 8.0]
                ),
                "low_risk_paths": len([p for p in unique_paths if p.risk_score < 5.0]),
            }

            self.logger.info(f"Identified {len(unique_paths)} potential attack paths")
            self.logger.info(
                f"High risk: {result['high_risk_paths']}, "
                f"Medium risk: {result['medium_risk_paths']}, "
                f"Low risk: {result['low_risk_paths']}"
            )

            return result

        except Exception as e:
            self.logger.error(
                f"Failed to analyze attack scenarios: {str(e)}", exc_info=True
            )
            return {"attack_paths": [], "error": str(e)}

    def _find_internet_attack_paths(
        self, enriched_results: pd.DataFrame
    ) -> list[AttackPath]:
        """Find attack paths starting from internet-facing services."""
        paths = []

        # Filter for internet-facing services with Bayesian-critical risk
        # Prefer risk_category (Bayesian) over severity_reassessed
        if "risk_category" in enriched_results.columns:
            internet_vulns = enriched_results[
                (enriched_results["exposure"] == "internet-facing")
                & (enriched_results["risk_category"] == "Critical")
            ]
        else:
            # Fallback to severity_reassessed
            internet_vulns = enriched_results[
                (enriched_results["exposure"] == "internet-facing")
                & (enriched_results["severity_reassessed"].isin(["Critical", "High"]))
            ]

        for _, row in internet_vulns.iterrows():
            try:
                cvss_score = (
                    float(row.get("cvss_score", 0))
                    if pd.notna(row.get("cvss_score"))
                    else 0
                )
                epss_score = (
                    float(row.get("epss_score", 0))
                    if pd.notna(row.get("epss_score"))
                    else 0
                )

                # Calculate risk factors
                exposure_factor = (
                    1.5 if row.get("exposure") == "internet-facing" else 1.0
                )
                asset_value_factor = {
                    "critical": 1.5,
                    "high": 1.3,
                    "medium": 1.0,
                    "low": 0.8,
                }.get(str(row.get("asset_value", "medium")).lower(), 1.0)

                # Risk score calculation
                base_risk = max(
                    cvss_score, epss_score * 10
                )  # Normalize EPSS to 0-10 scale
                risk_score = min(10.0, base_risk * exposure_factor * asset_value_factor)

                # Create attack step
                step = AttackStep(
                    service_name=str(row.get("service_name", "unknown")),
                    service_role=str(row.get("service_role", "service")),
                    vulnerability_id=str(
                        row.get("cve_id", row.get("vuln_id", "unknown"))
                    ),
                    cve_id=str(row.get("cve_id", row.get("vuln_id", "unknown"))),
                    attack_vector=self._determine_attack_vector(row),
                    description=f"{row.get('cve_id', row.get('vuln_id', 'unknown'))} in {row.get('service_name', 'unknown')} ({row.get('service_role', 'service')})",
                    cvss_score=cvss_score,
                    epss_score=epss_score,
                )

                # Create attack path
                path = AttackPath(
                    steps=[step],
                    risk_score=risk_score,
                    description=f"Direct internet attack on {row.get('service_name', 'unknown')} via {row.get('cve_id', row.get('vuln_id', 'unknown'))}",
                    likelihood=min(1.0, epss_score * 5),  # Scale EPSS to likelihood
                    impact=min(1.0, cvss_score / 10.0),
                )

                paths.append(path)

            except Exception as e:
                self.logger.debug(f"Error processing internet attack path: {str(e)}")
                continue

        return paths

    def _find_privilege_escalation_paths(
        self, enriched_results: pd.DataFrame
    ) -> list[AttackPath]:
        """Find privilege escalation opportunities."""
        paths = []

        # Look for vulnerabilities that could lead to privilege escalation
        # Common CWEs for privilege escalation
        priv_esc_cwes = ["CWE-264", "CWE-269", "CWE-274", "CWE-284", "CWE-285"]

        # Filter by Bayesian risk category (Critical only)
        if "risk_category" in enriched_results.columns:
            priv_esc_vulns = enriched_results[
                (enriched_results["cwe_id"].isin(priv_esc_cwes))
                & (enriched_results["risk_category"] == "Critical")
            ]
        else:
            priv_esc_vulns = enriched_results[
                (enriched_results["cwe_id"].isin(priv_esc_cwes))
                & (
                    enriched_results["severity_reassessed"].isin(
                        ["Critical", "High", "Medium"]
                    )
                )
            ]

        for _, row in priv_esc_vulns.iterrows():
            try:
                cvss_score = (
                    float(row.get("cvss_score", 0))
                    if pd.notna(row.get("cvss_score"))
                    else 0
                )
                epss_score = (
                    float(row.get("epss_score", 0))
                    if pd.notna(row.get("epss_score"))
                    else 0
                )

                # Higher risk for privilege escalation in critical services
                asset_value_factor = {
                    "critical": 1.8,
                    "high": 1.5,
                    "medium": 1.2,
                    "low": 1.0,
                }.get(str(row.get("asset_value", "medium")).lower(), 1.2)

                risk_score = min(10.0, cvss_score * 1.2 * asset_value_factor)

                step = AttackStep(
                    service_name=str(row.get("service_name", "unknown")),
                    service_role=str(row.get("service_role", "service")),
                    vulnerability_id=str(
                        row.get("cve_id", row.get("vuln_id", "unknown"))
                    ),
                    cve_id=str(row.get("cve_id", row.get("vuln_id", "unknown"))),
                    attack_vector="privilege_escalation",
                    description=f"Privilege escalation via {row.get('cve_id', row.get('vuln_id', 'unknown'))}",
                    cvss_score=cvss_score,
                    epss_score=epss_score,
                )

                path = AttackPath(
                    steps=[step],
                    risk_score=risk_score,
                    description=f"Privilege escalation in {row.get('service_name', 'unknown')} via {row.get('cve_id', row.get('vuln_id', 'unknown'))}",
                    likelihood=min(1.0, epss_score * 3),
                    impact=min(1.0, cvss_score / 8.0),
                )

                paths.append(path)

            except Exception as e:
                self.logger.debug(
                    f"Error processing privilege escalation path: {str(e)}"
                )
                continue

        return paths

    def _find_lateral_movement_paths(
        self, enriched_results: pd.DataFrame
    ) -> list[AttackPath]:
        """Find lateral movement opportunities between services."""
        paths = []

        # Look for vulnerabilities in network-facing services that could enable lateral movement
        network_services = ["load_balancer", "message_broker", "cache", "registry"]

        # Filter by Bayesian risk category (Critical only)
        if "risk_category" in enriched_results.columns:
            lateral_vulns = enriched_results[
                (enriched_results["service_role"].isin(network_services))
                & (enriched_results["risk_category"] == "Critical")
            ]
        else:
            lateral_vulns = enriched_results[
                (enriched_results["service_role"].isin(network_services))
                & (
                    enriched_results["severity_reassessed"].isin(
                        ["Critical", "High", "Medium"]
                    )
                )
            ]

        for _, row in lateral_vulns.iterrows():
            try:
                cvss_score = (
                    float(row.get("cvss_score", 0))
                    if pd.notna(row.get("cvss_score"))
                    else 0
                )
                epss_score = (
                    float(row.get("epss_score", 0))
                    if pd.notna(row.get("epss_score"))
                    else 0
                )

                # High risk for network infrastructure vulnerabilities
                risk_score = min(10.0, cvss_score * 1.3)

                step = AttackStep(
                    service_name=str(row.get("service_name", "unknown")),
                    service_role=str(row.get("service_role", "service")),
                    vulnerability_id=str(
                        row.get("cve_id", row.get("vuln_id", "unknown"))
                    ),
                    cve_id=str(row.get("cve_id", row.get("vuln_id", "unknown"))),
                    attack_vector="lateral_movement",
                    description=f"Lateral movement via {row.get('service_role', 'service')} vulnerability",
                    cvss_score=cvss_score,
                    epss_score=epss_score,
                )

                path = AttackPath(
                    steps=[step],
                    risk_score=risk_score,
                    description=f"Lateral movement through {row.get('service_role', 'service')} service via {row.get('cve_id', row.get('vuln_id', 'unknown'))}",
                    likelihood=min(1.0, epss_score * 4),
                    impact=min(1.0, cvss_score / 7.0),
                )

                paths.append(path)

            except Exception as e:
                self.logger.debug(f"Error processing lateral movement path: {str(e)}")
                continue

        return paths

    def _find_data_exfiltration_paths(
        self, enriched_results: pd.DataFrame
    ) -> list[AttackPath]:
        """Find data exfiltration opportunities."""
        paths = []

        # Focus on database and critical asset services
        data_services = ["database"]
        critical_assets = ["critical", "high"]

        # Filter by Bayesian risk category (Critical only)
        if "risk_category" in enriched_results.columns:
            data_vulns = enriched_results[
                (
                    (enriched_results["service_role"].isin(data_services))
                    | (enriched_results["asset_value"].isin(critical_assets))
                )
                & (enriched_results["risk_category"] == "Critical")
            ]
        else:
            data_vulns = enriched_results[
                (
                    (enriched_results["service_role"].isin(data_services))
                    | (enriched_results["asset_value"].isin(critical_assets))
                )
                & (enriched_results["severity_reassessed"].isin(["Critical", "High"]))
            ]

        for _, row in data_vulns.iterrows():
            try:
                cvss_score = (
                    float(row.get("cvss_score", 0))
                    if pd.notna(row.get("cvss_score"))
                    else 0
                )
                epss_score = (
                    float(row.get("epss_score", 0))
                    if pd.notna(row.get("epss_score"))
                    else 0
                )

                # Very high risk for data-related vulnerabilities
                asset_value_factor = {
                    "critical": 2.0,
                    "high": 1.7,
                    "medium": 1.3,
                    "low": 1.0,
                }.get(str(row.get("asset_value", "medium")).lower(), 1.3)

                risk_score = min(10.0, cvss_score * asset_value_factor)

                step = AttackStep(
                    service_name=str(row.get("service_name", "unknown")),
                    service_role=str(row.get("service_role", "service")),
                    vulnerability_id=str(
                        row.get("cve_id", row.get("vuln_id", "unknown"))
                    ),
                    cve_id=str(row.get("cve_id", row.get("vuln_id", "unknown"))),
                    attack_vector="data_exfiltration",
                    description=f"Data exfiltration via {row.get('cve_id', row.get('vuln_id', 'unknown'))}",
                    cvss_score=cvss_score,
                    epss_score=epss_score,
                )

                path = AttackPath(
                    steps=[step],
                    risk_score=risk_score,
                    description=f"Data exfiltration from {row.get('service_name', 'unknown')} via {row.get('cve_id', row.get('vuln_id', 'unknown'))}",
                    likelihood=min(1.0, epss_score * 3),
                    impact=0.9
                    if str(row.get("asset_value", "")).lower() in ["critical", "high"]
                    else 0.6,
                )

                paths.append(path)

            except Exception as e:
                self.logger.debug(f"Error processing data exfiltration path: {str(e)}")
                continue

        return paths

    def _determine_attack_vector(self, row: pd.Series) -> str:
        """Determine the most likely attack vector based on vulnerability data."""
        # Try to determine from CVSS vector if available
        cvss_vector = str(row.get("cvss_vector", ""))
        if "AV:N" in cvss_vector:
            return "network"
        elif "AV:L" in cvss_vector:
            return "local"
        elif "AV:A" in cvss_vector:
            return "adjacent"
        elif "AV:P" in cvss_vector:
            return "physical"

        # Fallback to service role-based determination
        service_role = str(row.get("service_role", "")).lower()
        if "web" in service_role or "api" in service_role:
            return "network"
        elif "database" in service_role:
            return "lateral_movement"
        else:
            return "network"

    def _deduplicate_attack_paths(self, paths: list[AttackPath]) -> list[AttackPath]:
        """Remove duplicate attack paths."""
        seen_descriptions = set()
        unique_paths = []

        for path in paths:
            if path.description not in seen_descriptions:
                seen_descriptions.add(path.description)
                unique_paths.append(path)

        return unique_paths

    def _path_to_dict(self, path: AttackPath) -> dict[str, Any]:
        """Convert AttackPath to dictionary for serialization."""
        return {
            "description": path.description,
            "risk_score": round(path.risk_score, 2),
            "likelihood": round(path.likelihood, 2),
            "impact": round(path.impact, 2),
            "steps": [
                {
                    "service_name": step.service_name,
                    "service_role": step.service_role,
                    "vulnerability_id": step.vulnerability_id,
                    "cve_id": step.cve_id,
                    "attack_vector": step.attack_vector,
                    "description": step.description,
                    "cvss_score": step.cvss_score,
                    "epss_score": step.epss_score,
                }
                for step in path.steps
            ],
        }


def analyze_attack_scenarios(
    enriched_results: pd.DataFrame, scenario: dict[str, Any]
) -> dict[str, Any]:
    """Convenience function to analyze attack scenarios."""
    analyzer = AttackScenarioAnalyzer()
    return analyzer.analyze(enriched_results, scenario)
