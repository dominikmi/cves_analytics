from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


@dataclass
class LikelihoodRatioConfig:
    """Configuration for Bayesian likelihood ratio parameters."""

    prior_probability: float = 0.1
    control_lrs: dict[str, float] = field(
        default_factory=lambda: {
            "firewall": 0.5,
            "ids_ips": 0.6,
            "waf": 0.5,
            "patching": 0.3,
            "mfa": 0.4,
            "encryption": 0.7,
            "access_control": 0.5,
            "monitoring": 0.6,
        }
    )
    threat_lrs: dict[str, float] = field(
        default_factory=lambda: {
            "active_exploitation": 3.0,
            "exploit_available": 2.0,
            "threat_intel_confidence": 1.5,
        }
    )
    cvss_weight: float = 1.0
    epss_weight: float = 1.0
    threat_weight: float = 1.0
    criticality_weight: float = 0.5


@dataclass
class SecurityControlsInput:
    """Input representing the security posture of a target asset."""

    firewall: bool = False
    ids_ips: bool = False
    waf: bool = False
    patching: bool = False
    mfa: bool = False
    encryption: bool = False
    access_control: bool = False
    monitoring: bool = False


@dataclass
class ThreatIndicatorsInput:
    """Input representing observed threat intelligence for a vulnerability."""

    active_exploitation: bool = False
    exploit_available: bool = False
    threat_intel_confidence: float = 0.0


@dataclass
class BayesianRiskResult:
    """Result of a Bayesian risk assessment."""

    posterior_probability: float
    prior_probability: float
    log_odds_prior: float
    log_odds_posterior: float
    control_lr: float
    threat_lr: float
    cvss_vector_lr: float
    exposure_lr: float
    criticality_lr: float
    epss_contribution: float
    risk_category: str
    credible_lower: float
    credible_upper: float
    explanation: str
    metadata: dict[str, Any] = field(default_factory=dict)


class KillChainStage(Enum):
    """Stages of the cyber kill chain model."""

    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    LATERAL_MOVEMENT = "lateral_movement"
    OBJECTIVE = "objective"


class KillChainResult(BaseModel):
    """Kill chain assessment result for a single application."""

    initial_access_probability: float = Field(
        ge=0.0, le=1.0, description="Probability of successful initial access"
    )
    execution_probability: float = Field(
        ge=0.0, le=1.0, description="Probability of successful code execution"
    )
    lateral_movement_probability: float = Field(
        ge=0.0, le=1.0, description="Probability of successful lateral movement"
    )
    objective_probability: float = Field(
        ge=0.0, le=1.0, description="Probability of achieving attacker objective"
    )
    overall_probability: float = Field(
        ge=0.0, le=1.0, description="End-to-end kill chain success probability"
    )
    threat_level: str = Field(
        description="Categorized threat level: critical/high/medium/low"
    )
    critical_path: list[KillChainStage] = Field(
        description="Ordered stages forming the most likely attack path"
    )
    rce_vulnerabilities: int = Field(
        default=0, description="Count of remote code execution vulnerabilities"
    )
    privesc_vulnerabilities: int = Field(
        default=0, description="Count of privilege escalation vulnerabilities"
    )
    container_escape_vulnerabilities: int = Field(
        default=0, description="Count of container escape vulnerabilities"
    )
