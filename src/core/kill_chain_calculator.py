"""Kill-Chain Probability Calculator for multi-component applications.

Implements the sequential Bayesian kill-chain analysis described in
EXTENDED_KILL_CHAIN_METHOD.md, calculating the probability of successful
attack chain execution from initial access to objective achievement.
"""

import logging
from typing import Any

import polars as pl
from pydantic import BaseModel, Field

from src.simulation.application_templates import (
    ApplicationTemplate,
)
from src.utils.security_controls_config import get_security_controls_config

logger = logging.getLogger(__name__)


class KillChainStage(BaseModel):
    """Represents a single stage in the kill-chain."""

    name: str
    components: list[str]  # Component roles involved in this stage
    base_probability: float = Field(ge=0.0, le=1.0)
    conditional_probability: float = Field(ge=0.0, le=1.0)
    contributing_factors: dict[str, float] = Field(default_factory=dict)


class KillChainResult(BaseModel):
    """Result of kill-chain probability analysis."""

    application_name: str
    total_probability: float = Field(ge=0.0, le=1.0)
    stages: list[KillChainStage]
    critical_path: list[str]  # Most likely attack path
    bottleneck_stage: str | None = None  # Stage with lowest probability
    threat_level: str  # Critical, High, Medium, Low, Negligible


class KillChainCalculator:
    """Calculates kill-chain success probability for multi-component applications.

    References:
    - Hutchins, E. M., et al. (2011). "Intelligence-Driven Computer Network Defense"
    - Sultan, S., et al. (2019). "Container Security: Issues, Challenges, and the Road Ahead". IEEE Access.
    - NIST SP 800-190 (2017). "Application Container Security Guide"
    """

    def __init__(self) -> None:
        """Initialize the kill-chain calculator."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = get_security_controls_config()

    def _is_remote_code_execution(self, vulnerability: dict[str, Any]) -> bool:
        """Detect if vulnerability is Remote Code Execution.

        Checks CVSS vector for AV:N (Network) and high Impact (C:H, I:H, or A:H),
        or CWE categories related to code execution.

        Args:
            vulnerability: Vulnerability dictionary with cvss_vector and/or cwe_id

        Returns:
            True if vulnerability enables remote code execution
        """
        # Check CVSS vector for network-accessible high impact
        # Try multiple column name variations
        cvss_vector = (
            vulnerability.get("cvss_v3_1_vector")
            or vulnerability.get("cvss_base_vector")
            or vulnerability.get("cvss_vector")
            or ""
        )
        if (
            cvss_vector
            and "AV:N" in cvss_vector
            and ("I:H" in cvss_vector or "A:H" in cvss_vector or "C:H" in cvss_vector)
        ):
            return True

        # Check CWE for code execution categories
        cwe_id = vulnerability.get("cwe_id", "")
        rce_cwes = [
            "CWE-78",  # OS Command Injection
            "CWE-94",  # Code Injection
            "CWE-77",  # Command Injection
            "CWE-502",  # Deserialization of Untrusted Data
            "CWE-434",  # Unrestricted Upload of File with Dangerous Type
        ]
        return any(cwe in str(cwe_id) for cwe in rce_cwes)

    def _is_privilege_escalation(self, vulnerability: dict[str, Any]) -> bool:
        """Detect if vulnerability enables privilege escalation.

        Args:
            vulnerability: Vulnerability dictionary with cvss_vector and/or cwe_id

        Returns:
            True if vulnerability enables privilege escalation
        """
        # Check CVSS for privilege requirement changes
        # Try multiple column name variations
        cvss_vector = (
            vulnerability.get("cvss_v3_1_vector")
            or vulnerability.get("cvss_base_vector")
            or vulnerability.get("cvss_vector")
            or ""
        )
        if (
            cvss_vector
            and ("PR:L" in cvss_vector or "PR:N" in cvss_vector)
            and "I:H" in cvss_vector
        ):
            return True

        # Check CWE for privilege escalation
        cwe_id = vulnerability.get("cwe_id", "")
        privesc_cwes = [
            "CWE-269",  # Improper Privilege Management
            "CWE-250",  # Execution with Unnecessary Privileges
            "CWE-266",  # Incorrect Privilege Assignment
        ]
        return any(cwe in str(cwe_id) for cwe in privesc_cwes)

    def _is_container_escape(self, vulnerability: dict[str, Any]) -> bool:
        """Detect if vulnerability enables container escape.

        Args:
            vulnerability: Vulnerability dictionary with description and/or cwe_id

        Returns:
            True if vulnerability enables container escape
        """
        # Try multiple description column variations
        description = (
            vulnerability.get("vuln_desc") or vulnerability.get("description") or ""
        )
        if description:
            desc_lower = description.lower()
            return (
                "container escape" in desc_lower
                or "breakout" in desc_lower
                or "docker" in desc_lower
            )
        return False

    def calculate_kill_chain_probability(
        self,
        application: ApplicationTemplate,
        vulnerabilities: pl.DataFrame,
        security_controls: dict[str, Any],
        docker_security_good: bool = True,
    ) -> KillChainResult:
        """Calculate the probability of successful kill-chain execution.

        Implements the sequential Bayesian model:
        P(Kill-Chain) = P(Initial Access) × P(Execution | Initial Access) ×
                        P(Lateral Movement | Execution) × P(Objective | Lateral Movement)

        Args:
            application: ApplicationTemplate defining the app architecture
            vulnerabilities: DataFrame with vulnerability data including bayesian_risk_score
            security_controls: Dictionary of active security controls
            docker_security_good: Whether Docker security practices are in place

        Returns:
            KillChainResult with stage-by-stage probabilities

        """
        self.logger.info(
            f"Calculating kill-chain probability for {application.name}",
        )

        stages = []

        # Stage 1: Initial Access (internet-facing components)
        initial_access = self._calculate_initial_access(
            application,
            vulnerabilities,
            security_controls,
        )
        stages.append(initial_access)

        # Stage 2: Execution (code execution on compromised component)
        execution = self._calculate_execution(
            application,
            vulnerabilities,
            security_controls,
            docker_security_good,
            initial_access.base_probability,
        )
        stages.append(execution)

        # Stage 3: Lateral Movement (access to other components)
        lateral_movement = self._calculate_lateral_movement(
            application,
            vulnerabilities,
            security_controls,
            docker_security_good,
            execution.conditional_probability,
        )
        stages.append(lateral_movement)

        # Stage 4: Objective Achievement (data exfiltration, disruption, persistence)
        objective = self._calculate_objective(
            application,
            vulnerabilities,
            security_controls,
            lateral_movement.conditional_probability,
        )
        stages.append(objective)

        # Calculate total kill-chain probability (product of conditional probabilities)
        total_probability = (
            initial_access.base_probability
            * execution.conditional_probability
            * lateral_movement.conditional_probability
            * objective.conditional_probability
        )

        # Identify bottleneck (lowest probability stage)
        bottleneck = min(stages, key=lambda s: s.conditional_probability)

        # Determine threat level
        threat_level = self._categorize_threat_level(total_probability)

        # Build critical path (most likely attack sequence)
        critical_path = self._build_critical_path(application, vulnerabilities)

        return KillChainResult(
            application_name=application.name,
            total_probability=total_probability,
            stages=stages,
            critical_path=critical_path,
            bottleneck_stage=bottleneck.name,
            threat_level=threat_level,
        )

    def _calculate_initial_access(
        self,
        application: ApplicationTemplate,
        vulnerabilities: pl.DataFrame,
        security_controls: dict[str, Any],
    ) -> KillChainStage:
        """Calculate P(Initial Access) for internet-facing components.

        This is the base probability - highest Bayesian risk score among
        internet-facing components.
        """
        # Get internet-facing component roles
        internet_facing_roles = [
            comp.role.value
            for comp in application.components
            if comp.exposure == "internet-facing"
        ]

        # Also check for components with any exposure (fallback)
        all_component_roles = [comp.role.value for comp in application.components]

        self.logger.info(
            f"Internet-facing roles: {internet_facing_roles}, All roles: {all_component_roles}"
        )
        self.logger.info(f"Total vulnerabilities: {len(vulnerabilities)}")

        if not internet_facing_roles or vulnerabilities.is_empty():
            # Use all components if no internet-facing ones
            if (
                not internet_facing_roles
                and all_component_roles
                and not vulnerabilities.is_empty()
            ):
                internet_facing_roles = all_component_roles
                self.logger.info(
                    f"No internet-facing components, using all: {internet_facing_roles}"
                )
            else:
                return KillChainStage(
                    name="Initial Access",
                    components=internet_facing_roles or all_component_roles,
                    base_probability=0.01,  # Minimal baseline
                    conditional_probability=0.01,
                    contributing_factors={"no_vulnerabilities": 0.01},
                )

        # Filter vulnerabilities for internet-facing components
        if "service_role" in vulnerabilities.columns:
            internet_vulns = vulnerabilities.filter(
                pl.col("service_role").is_in(internet_facing_roles)
            )
            self.logger.info(
                f"Filtered by service_role, found {len(internet_vulns)} vulnerabilities"
            )
        elif "exposure" in vulnerabilities.columns:
            # Fallback: use exposure column
            internet_vulns = vulnerabilities.filter(
                pl.col("exposure") == "internet-facing"
            )
            self.logger.info(
                f"Filtered by exposure, found {len(internet_vulns)} vulnerabilities"
            )
        else:
            # No filtering possible, use all vulnerabilities
            internet_vulns = vulnerabilities
            self.logger.info(
                f"No filtering columns available, using all {len(internet_vulns)} vulnerabilities"
            )

        if internet_vulns.is_empty():
            # If filtering resulted in no vulnerabilities, use all vulnerabilities
            self.logger.warning(
                f"No internet-facing vulnerabilities found, using all {len(vulnerabilities)} vulnerabilities"
            )
            internet_vulns = vulnerabilities

            if internet_vulns.is_empty():
                return KillChainStage(
                    name="Initial Access",
                    components=internet_facing_roles,
                    base_probability=0.01,
                    conditional_probability=0.01,
                    contributing_factors={"no_exploitable_vulns": 0.01},
                )

        # Get maximum Bayesian risk score (highest exploitation probability)
        if "bayesian_risk_score" in internet_vulns.columns:
            max_risk = internet_vulns["bayesian_risk_score"].max()
            base_prob = float(max_risk) if max_risk is not None else 0.01
            self.logger.info(
                f"Initial Access: Using bayesian_risk_score, max={base_prob:.3f}"
            )
        elif "epss_score" in internet_vulns.columns:
            # Fallback to EPSS
            max_epss = internet_vulns["epss_score"].max()
            base_prob = float(max_epss) if max_epss is not None else 0.01
            self.logger.info(f"Initial Access: Using epss_score, max={base_prob:.3f}")
        elif "epss" in internet_vulns.columns:
            # Try alternative column name
            max_epss = internet_vulns["epss"].max()
            base_prob = float(max_epss) if max_epss is not None else 0.01
            self.logger.info(f"Initial Access: Using epss, max={base_prob:.3f}")
        else:
            base_prob = 0.01
            self.logger.warning(
                f"Initial Access: No risk score columns found, using default {base_prob}"
            )

        # Apply security control modifiers
        factors = {"max_vuln_probability": base_prob}

        # WAF reduces initial access probability
        if security_controls.get("waf", False):
            waf_lr = self.config.get_kill_chain_control_value("initial_access", "waf")
            base_prob *= waf_lr
            factors["waf"] = waf_lr

        # IDS/IPS reduces initial access
        if security_controls.get("ids_ips", False):
            ids_lr = self.config.get_kill_chain_control_value(
                "initial_access", "ids_ips"
            )
            base_prob *= ids_lr
            factors["ids_ips"] = ids_lr

        # MFA reduces credential-based initial access
        if security_controls.get("mfa", False):
            mfa_lr = self.config.get_kill_chain_control_value("initial_access", "mfa")
            base_prob *= mfa_lr
            factors["mfa"] = mfa_lr

        return KillChainStage(
            name="Initial Access",
            components=internet_facing_roles,
            base_probability=min(base_prob, 0.95),  # Cap at 95%
            conditional_probability=min(base_prob, 0.95),
            contributing_factors=factors,
        )

    def _calculate_execution(
        self,
        application: ApplicationTemplate,
        vulnerabilities: pl.DataFrame,
        security_controls: dict[str, Any],
        docker_security_good: bool,
        prior_probability: float,
    ) -> KillChainStage:
        """Calculate P(Execution | Initial Access).

        Docker security practices significantly affect this stage, but effectiveness
        depends on vulnerability type:
        - RCE with root user: NO reduction (immediate root access)
        - Privilege escalation with root: minimal reduction (already root)
        - Container escape: NO reduction without seccomp/AppArmor

        References:
        - Sultan, S., et al. (2019). "Container Security". IEEE Access, 7, 52976-52996.
        - Combe, T., et al. (2016). "To Docker or Not to Docker". IEEE Cloud Computing, 3(5), 54-62.
        - NIST SP 800-190 (2017). "Application Container Security Guide".
        """
        execution_roles = application.kill_chain_stages.get("execution", [])

        # Base: assume execution is likely if initial access succeeded
        base_prob = 0.8  # 80% chance of execution after initial access

        factors = {"base_execution": 0.8}

        # Analyze vulnerability types to determine Docker security effectiveness
        has_rce = False
        has_privesc = False
        has_container_escape = False

        if not vulnerabilities.is_empty():
            # Convert to list of dicts for analysis
            vuln_dicts = vulnerabilities.to_dicts()
            for vuln in vuln_dicts:
                if self._is_remote_code_execution(vuln):
                    has_rce = True
                if self._is_privilege_escalation(vuln):
                    has_privesc = True
                if self._is_container_escape(vuln):
                    has_container_escape = True

        # Apply Docker security based on vulnerability type
        # References: Sultan et al. (2019), NIST SP 800-190
        if docker_security_good:
            # Good practices: non-root user, read-only FS, seccomp, AppArmor
            if has_rce:
                rce_lr = self.config.get_docker_control_value(
                    "good_practices", "rce_protection"
                )
                base_prob *= rce_lr
                factors["docker_good_rce_protection"] = rce_lr
            elif has_privesc:
                privesc_lr = self.config.get_docker_control_value(
                    "good_practices", "privesc_protection"
                )
                base_prob *= privesc_lr
                factors["docker_good_privesc_protection"] = privesc_lr
            elif has_container_escape:
                escape_lr = self.config.get_docker_control_value(
                    "good_practices", "container_escape_protection"
                )
                base_prob *= escape_lr
                factors["docker_good_escape_protection"] = escape_lr
            else:
                general_lr = self.config.get_docker_control_value(
                    "good_practices", "general_hardening"
                )
                base_prob *= general_lr
                factors["docker_good_practices"] = general_lr
        else:
            # Bad practices: root user, writable FS, no seccomp/AppArmor
            # Critical: Running as root with RCE = immediate root access!
            if has_rce:
                rce_lr = self.config.get_docker_control_value(
                    "poor_practices", "rce_no_protection"
                )
                base_prob *= rce_lr
                factors["docker_poor_rce_no_protection"] = rce_lr
                self.logger.warning(
                    "RCE vulnerability with poor Docker practices: NO protection (root access)"
                )
            elif has_privesc:
                privesc_lr = self.config.get_docker_control_value(
                    "poor_practices", "privesc_minimal"
                )
                base_prob *= privesc_lr
                factors["docker_poor_privesc_minimal"] = privesc_lr
            elif has_container_escape:
                escape_lr = self.config.get_docker_control_value(
                    "poor_practices", "container_escape_no_protection"
                )
                base_prob *= escape_lr
                factors["docker_poor_escape_no_protection"] = escape_lr
            else:
                minimal_lr = self.config.get_docker_control_value(
                    "poor_practices", "minimal_hardening"
                )
                base_prob *= minimal_lr
                factors["docker_poor_practices"] = minimal_lr

        # EDR/XDR blocks execution
        if security_controls.get("edr_xdr", False):
            edr_lr = self.config.get_kill_chain_control_value("execution", "edr_xdr")
            base_prob *= edr_lr
            factors["edr_xdr"] = edr_lr

        # Application firewall
        if security_controls.get("waf", False):
            waf_lr = self.config.get_kill_chain_control_value("execution", "waf")
            base_prob *= waf_lr
            factors["waf"] = waf_lr

        # Conditional probability given initial access
        conditional_prob = base_prob

        return KillChainStage(
            name="Execution",
            components=execution_roles,
            base_probability=prior_probability * conditional_prob,
            conditional_probability=conditional_prob,
            contributing_factors=factors,
        )

    def _calculate_lateral_movement(
        self,
        application: ApplicationTemplate,
        vulnerabilities: pl.DataFrame,
        security_controls: dict[str, Any],
        docker_security_good: bool,
        prior_probability: float,
    ) -> KillChainStage:
        """Calculate P(Lateral Movement | Execution).

        Network segmentation and Docker security affect this stage.
        Docker isolation (network policies, user namespaces) limits lateral movement.

        References:
        - Sultan, S., et al. (2019). "Container Security". IEEE Access.
        - NIST SP 800-190 (2017). "Application Container Security Guide".
        """
        lateral_roles = application.kill_chain_stages.get("lateral_movement", [])

        # Base: lateral movement probability depends on network architecture
        base_prob = 0.7  # 70% chance if no controls

        factors = {"base_lateral": 0.7}

        # Network segmentation (strongest control for lateral movement)
        if security_controls.get("network_segmentation", False):
            seg_lr = self.config.get_kill_chain_control_value(
                "lateral_movement", "network_segmentation"
            )
            base_prob *= seg_lr
            factors["network_segmentation"] = seg_lr
        else:
            # Flat network - easier lateral movement
            flat_lr = self.config.get_kill_chain_control_value(
                "lateral_movement", "flat_network"
            )
            base_prob *= flat_lr
            factors["flat_network"] = flat_lr

        # Docker security affects lateral movement through network isolation
        # Good practices: network policies, user namespaces, limited capabilities
        # Bad practices: shared network, root user, privileged containers
        if docker_security_good:
            docker_net_lr = self.config.get_kill_chain_control_value(
                "lateral_movement", "docker_good_network"
            )
            base_prob *= docker_net_lr
            factors["docker_good_network_isolation"] = docker_net_lr
        else:
            # Bad practices provide minimal isolation
            docker_poor_lr = self.config.get_kill_chain_control_value(
                "lateral_movement", "docker_poor_network"
            )
            base_prob *= docker_poor_lr
            factors["docker_poor_network_isolation"] = docker_poor_lr

        # EDR/XDR detects lateral movement
        if security_controls.get("edr_xdr", False):
            edr_lr = self.config.get_kill_chain_control_value(
                "lateral_movement", "edr_xdr"
            )
            base_prob *= edr_lr
            factors["edr_xdr"] = edr_lr

        # SIEM/SOC monitoring
        if security_controls.get("siem", False):
            siem_lr = self.config.get_kill_chain_control_value(
                "lateral_movement", "siem"
            )
            base_prob *= siem_lr
            factors["siem"] = siem_lr

        conditional_prob = base_prob

        return KillChainStage(
            name="Lateral Movement",
            components=lateral_roles,
            base_probability=prior_probability * conditional_prob,
            conditional_probability=conditional_prob,
            contributing_factors=factors,
        )

    def _calculate_objective(
        self,
        application: ApplicationTemplate,
        vulnerabilities: pl.DataFrame,
        security_controls: dict[str, Any],
        prior_probability: float,
    ) -> KillChainStage:
        """Calculate P(Objective | Lateral Movement).

        Objective can be data exfiltration, service disruption, or persistence.
        """
        objective_roles = application.kill_chain_stages.get("exfiltration", [])

        # Base: assume objective is achievable if lateral movement succeeded
        base_prob = 0.9  # 90% chance of achieving objective

        factors = {"base_objective": 0.9}

        # Data Loss Prevention
        if security_controls.get("data_loss_prevention", False):
            dlp_lr = self.config.get_kill_chain_control_value(
                "objective_achievement", "data_loss_prevention"
            )
            base_prob *= dlp_lr
            factors["dlp"] = dlp_lr

        # Encryption at rest
        if security_controls.get("encryption_at_rest", False):
            enc_lr = self.config.get_kill_chain_control_value(
                "objective_achievement", "encryption_at_rest"
            )
            base_prob *= enc_lr
            factors["encryption"] = enc_lr

        # Backup and recovery
        if security_controls.get("backup_recovery", False):
            backup_lr = self.config.get_kill_chain_control_value(
                "objective_achievement", "backup_recovery"
            )
            base_prob *= backup_lr
            factors["backup"] = backup_lr

        # SIEM/SOC detection
        if security_controls.get("siem", False):
            siem_lr = self.config.get_kill_chain_control_value(
                "objective_achievement", "siem"
            )
            base_prob *= siem_lr
            factors["siem"] = siem_lr

        conditional_prob = base_prob

        return KillChainStage(
            name="Objective Achievement",
            components=objective_roles,
            base_probability=prior_probability * conditional_prob,
            conditional_probability=conditional_prob,
            contributing_factors=factors,
        )

    def _categorize_threat_level(self, probability: float) -> str:
        """Categorize threat level based on kill-chain success probability.

        Uses the same thresholds as Bayesian risk assessment.
        """
        if probability >= 0.40:
            return "Critical"
        elif probability >= 0.15:
            return "High"
        elif probability >= 0.05:
            return "Medium"
        elif probability >= 0.01:
            return "Low"
        else:
            return "Negligible"

    def _build_critical_path(
        self,
        application: ApplicationTemplate,
        vulnerabilities: pl.DataFrame,
    ) -> list[str]:
        """Build the most likely attack path through the application.

        Returns component names in order of likely compromise.
        """
        critical_path = []

        # Start with internet-facing components
        internet_facing = [
            comp.name
            for comp in application.components
            if comp.exposure == "internet-facing"
        ]
        critical_path.extend(internet_facing)

        # Follow data flow to critical assets
        for comp in application.components:
            if comp.asset_value == "critical" and comp.name not in critical_path:
                critical_path.append(comp.name)

        return critical_path


def calculate_application_kill_chain(
    application: ApplicationTemplate,
    vulnerabilities: pl.DataFrame,
    security_controls: dict[str, Any],
    docker_security_good: bool = True,
) -> KillChainResult:
    """Convenience function to calculate kill-chain probability.

    Args:
        application: ApplicationTemplate defining the app architecture
        vulnerabilities: DataFrame with vulnerability data
        security_controls: Dictionary of active security controls
        docker_security_good: Whether Docker security practices are in place

    Returns:
        KillChainResult with stage-by-stage probabilities

    """
    calculator = KillChainCalculator()
    return calculator.calculate_kill_chain_probability(
        application,
        vulnerabilities,
        security_controls,
        docker_security_good,
    )
