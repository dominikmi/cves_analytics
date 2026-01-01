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
    """Calculates kill-chain success probability for multi-component applications."""

    def __init__(self) -> None:
        """Initialize the kill-chain calculator."""
        self.logger = logging.getLogger(self.__class__.__name__)

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

        if not internet_facing_roles or vulnerabilities.is_empty():
            return KillChainStage(
                name="Initial Access",
                components=internet_facing_roles,
                base_probability=0.01,  # Minimal baseline
                conditional_probability=0.01,
                contributing_factors={"no_vulnerabilities": 0.01},
            )

        # Filter vulnerabilities for internet-facing components
        if "service_role" in vulnerabilities.columns:
            internet_vulns = vulnerabilities.filter(
                pl.col("service_role").is_in(internet_facing_roles)
            )
        else:
            # Fallback: use exposure column
            internet_vulns = vulnerabilities.filter(
                pl.col("exposure") == "internet-facing"
            )

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
        else:
            # Fallback to EPSS
            max_epss = internet_vulns["epss_score"].max()
            base_prob = float(max_epss) if max_epss is not None else 0.01

        # Apply security control modifiers
        factors = {"max_vuln_probability": base_prob}

        # WAF reduces initial access probability
        if security_controls.get("waf", False):
            base_prob *= 0.3  # 70% reduction
            factors["waf"] = 0.3

        # IDS/IPS reduces initial access
        if security_controls.get("ids_ips", False):
            base_prob *= 0.4  # 60% reduction
            factors["ids_ips"] = 0.4

        # MFA reduces credential-based initial access
        if security_controls.get("mfa", False):
            base_prob *= 0.5  # 50% reduction
            factors["mfa"] = 0.5

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

        Docker security practices significantly affect this stage.
        """
        execution_roles = application.kill_chain_stages.get("execution", [])

        # Base: assume execution is likely if initial access succeeded
        base_prob = 0.8  # 80% chance of execution after initial access

        factors = {"base_execution": 0.8}

        # Docker security practices (from documentation)
        if docker_security_good:
            base_prob *= 0.4  # 60% reduction with good practices
            factors["docker_good_practices"] = 0.4
        else:
            base_prob *= 0.8  # 20% reduction with poor practices
            factors["docker_poor_practices"] = 0.8

        # EDR/XDR blocks execution
        if security_controls.get("edr_xdr", False):
            base_prob *= 0.4  # 60% reduction
            factors["edr_xdr"] = 0.4

        # Application firewall
        if security_controls.get("waf", False):
            base_prob *= 0.6  # 40% reduction
            factors["waf"] = 0.6

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
        """
        lateral_roles = application.kill_chain_stages.get("lateral_movement", [])

        # Base: lateral movement probability depends on network architecture
        base_prob = 0.7  # 70% chance if no controls

        factors = {"base_lateral": 0.7}

        # Network segmentation (strongest control for lateral movement)
        if security_controls.get("network_segmentation", False):
            base_prob *= 0.3  # 70% reduction
            factors["network_segmentation"] = 0.3
        else:
            # Flat network - easier lateral movement
            base_prob *= 0.9  # 10% reduction
            factors["flat_network"] = 0.9

        # Docker security (from documentation)
        if docker_security_good:
            base_prob *= 0.5  # 50% reduction
            factors["docker_good_practices"] = 0.5
        else:
            base_prob *= 0.9  # 10% reduction
            factors["docker_poor_practices"] = 0.9

        # EDR/XDR detects lateral movement
        if security_controls.get("edr_xdr", False):
            base_prob *= 0.5  # 50% reduction
            factors["edr_xdr"] = 0.5

        # SIEM/SOC monitoring
        if security_controls.get("siem", False):
            base_prob *= 0.6  # 40% reduction
            factors["siem"] = 0.6

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
            base_prob *= 0.3  # 70% reduction
            factors["dlp"] = 0.3

        # Encryption at rest
        if security_controls.get("encryption_at_rest", False):
            base_prob *= 0.5  # 50% reduction (data less useful)
            factors["encryption"] = 0.5

        # Backup and recovery
        if security_controls.get("backup_recovery", False):
            base_prob *= 0.6  # 40% reduction (can recover)
            factors["backup"] = 0.6

        # SIEM/SOC detection
        if security_controls.get("siem", False):
            base_prob *= 0.7  # 30% reduction
            factors["siem"] = 0.7

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
