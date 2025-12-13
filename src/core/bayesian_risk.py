"""Bayesian Risk Assessment Module.

This module implements a principled Bayesian approach to vulnerability risk
assessment, replacing arbitrary multiplicative weights with likelihood ratios
that have probabilistic meaning.

The core idea:
- EPSS provides P(Exploitation | CVE characteristics) as the prior probability
- Security controls, exposure context, and threat indicators provide evidence
- Likelihood ratios update the prior to a posterior probability
- Uncertainty is quantified via credible intervals

Mathematical Foundation:
    Posterior Odds = Prior Odds × LR₁ × LR₂ × ... × LRₙ

Where:
    - Prior Odds = EPSS / (1 - EPSS)
    - LR < 1 means evidence reduces exploitation probability
    - LR > 1 means evidence increases exploitation probability
    - LR = 1 means evidence is uninformative

References:
    - FIRST EPSS: https://www.first.org/epss/
    - CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
    - Bayesian inference: https://en.wikipedia.org/wiki/Bayes%27_theorem

"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import pandas as pd
from pydantic import BaseModel, Field, field_validator

from src.utils.logging_config import get_logger

logger = get_logger(__name__)


# =============================================================================
# LIKELIHOOD RATIO TABLES
# =============================================================================
# These values are derived from security research and can be overridden via config.
# Sources: MITRE ATT&CK effectiveness data, NIST SP 800-53 control effectiveness,
# empirical studies on control efficacy.


class SecurityControlLR(float, Enum):
    """Likelihood ratios for security controls.

    LR < 1 means the control REDUCES exploitation probability.
    Values derived from:
    - MITRE ATT&CK mitigations effectiveness
    - NIST SP 800-53 control families
    - Industry benchmarks (Verizon DBIR, Mandiant M-Trends)

    Interpretation:
    - LR = 0.1: Control reduces exploitation odds by 90%
    - LR = 0.5: Control reduces exploitation odds by 50%
    - LR = 1.0: Control has no effect
    """

    # Network Controls
    NETWORK_SEGMENTATION = 0.3  # Limits lateral movement significantly
    FIREWALL = 0.5  # Blocks unauthorized network access
    WAF = 0.4  # Blocks common web attacks (OWASP Top 10)
    IDS_IPS = 0.5  # Detects/blocks known attack patterns

    # Endpoint Controls
    EDR_XDR = 0.4  # Detects/blocks endpoint exploitation
    ANTIVIRUS = 0.7  # Basic malware detection
    HOST_FIREWALL = 0.6  # Local network filtering

    # Access Controls
    MFA = 0.3  # Mitigates credential-based attacks
    PRIVILEGED_ACCESS_MGMT = 0.4  # Limits privilege escalation
    RBAC = 0.6  # Reduces attack surface via least privilege

    # Patch Management
    PATCH_DAILY = 0.2  # Minimal exposure window
    PATCH_WEEKLY = 0.4  # Short exposure window
    PATCH_MONTHLY = 0.7  # Moderate exposure window
    PATCH_QUARTERLY = 0.9  # Long exposure window

    # Security Operations
    SIEM = 0.6  # Detection capability
    SOC_24X7 = 0.5  # Continuous monitoring
    INCIDENT_RESPONSE_PLAN = 0.7  # Reduces impact, not likelihood

    # Application Security
    SECURE_SDLC = 0.6  # Reduces vulnerability introduction
    CODE_REVIEW = 0.7  # Catches vulnerabilities pre-deployment
    SAST_DAST = 0.6  # Automated security testing

    # Physical/Environmental
    AIR_GAPPED = 0.05  # Severely limits network attack surface
    PHYSICAL_SECURITY = 0.8  # Prevents physical access attacks


class ExposureLR(float, Enum):
    """Likelihood ratios for exposure context.

    LR > 1 means exposure INCREASES exploitation probability.
    """

    INTERNET_FACING = 2.5  # Directly accessible from internet
    DMZ = 1.8  # In DMZ, some protection
    INTERNAL = 0.6  # Internal network only
    RESTRICTED = 0.3  # Restricted zone, limited access
    AIR_GAPPED = 0.1  # No network connectivity


class ThreatIndicatorLR(float, Enum):
    """Likelihood ratios for threat indicators.

    LR > 1 means indicator INCREASES exploitation probability.
    """

    KEV_LISTED = 3.0  # CISA Known Exploited Vulnerabilities
    PUBLIC_EXPLOIT = 2.0  # Exploit code publicly available
    METASPLOIT_MODULE = 2.5  # Metasploit module exists
    WEAPONIZED = 4.0  # Actively weaponized in campaigns
    APT_INTEREST = 2.0  # Known APT interest in this vuln
    RANSOMWARE_ASSOCIATED = 3.0  # Associated with ransomware campaigns


class CVSSVectorLR:
    """Likelihood ratios derived from CVSS vector components.

    These adjust the prior based on attack characteristics.
    """

    # Attack Vector (AV) - how the vulnerability is exploited
    ATTACK_VECTOR = {
        "N": {"internet": 2.0, "internal": 1.0, "restricted": 0.5},  # Network
        "A": {"internet": 1.5, "internal": 1.2, "restricted": 0.8},  # Adjacent
        "L": {"internet": 0.3, "internal": 0.5, "restricted": 0.7},  # Local
        "P": {"internet": 0.1, "internal": 0.2, "restricted": 0.3},  # Physical
    }

    # Attack Complexity (AC) - conditions beyond attacker's control
    ATTACK_COMPLEXITY = {
        "L": 1.5,  # Low - no special conditions needed
        "H": 0.5,  # High - special conditions required
    }

    # Privileges Required (PR) - level of privileges needed
    PRIVILEGES_REQUIRED = {
        "N": 1.8,  # None - unauthenticated attack
        "L": 1.0,  # Low - basic user privileges
        "H": 0.5,  # High - admin privileges needed
    }

    # User Interaction (UI) - requires user action
    USER_INTERACTION = {
        "N": 1.5,  # None - no user interaction needed
        "R": 0.6,  # Required - needs user to do something
    }

    # Scope (S) - can affect other components
    SCOPE = {
        "U": 1.0,  # Unchanged - limited to vulnerable component
        "C": 1.5,  # Changed - can affect other components
    }


class ExposureConditionalControlLR:
    """Exposure-conditional likelihood ratios for security controls.

    This implements a simplified form of conditional Bayes where control
    effectiveness depends on the exposure context. For example:
    - WAF is highly effective for internet-facing services (LR=0.3)
    - WAF has minimal effect on internal services (LR=0.9)

    This avoids the independence assumption violation where we would
    otherwise multiply WAF LR regardless of whether it's relevant.

    Rationale:
    - Full conditional Bayes would require P(Exploit | Control, Exposure)
    - This approximation uses LR(Control | Exposure) as a practical middle ground
    - More accurate than flat LRs, simpler than full Bayesian networks
    """

    # Format: control -> {exposure -> LR}
    # LR < 1 means risk reduction, closer to 1 means less effective
    CONDITIONAL_LRS: dict[str, dict[str, float]] = {
        # WAF: Very effective for internet-facing, minimal for internal
        "waf": {
            "internet-facing": 0.3,  # 70% reduction - WAF blocks web attacks
            "dmz": 0.4,  # 60% reduction
            "internal": 0.9,  # 10% reduction - WAF rarely deployed internally
            "restricted": 0.8,  # 20% reduction
        },
        # IDS/IPS: More effective at perimeter
        "ids_ips": {
            "internet-facing": 0.4,  # 60% reduction - catches inbound attacks
            "dmz": 0.45,  # 55% reduction
            "internal": 0.7,  # 30% reduction - less visibility internally
            "restricted": 0.5,  # 50% reduction
        },
        # Network segmentation: More important for internal lateral movement
        "network_segmentation": {
            "internet-facing": 0.5,  # 50% reduction - limits blast radius
            "dmz": 0.4,  # 60% reduction - DMZ isolation
            "internal": 0.3,  # 70% reduction - prevents lateral movement
            "restricted": 0.2,  # 80% reduction - critical for restricted zones
        },
        # MFA: Critical for external access, less so for internal
        "mfa": {
            "internet-facing": 0.2,  # 80% reduction - blocks credential attacks
            "dmz": 0.25,  # 75% reduction
            "internal": 0.5,  # 50% reduction - internal auth often bypassed
            "restricted": 0.2,  # 80% reduction - critical for restricted
        },
        # EDR/XDR: Equally effective regardless of exposure
        "edr_xdr": {
            "internet-facing": 0.4,  # 60% reduction
            "dmz": 0.4,  # 60% reduction
            "internal": 0.4,  # 60% reduction
            "restricted": 0.35,  # 65% reduction
        },
        # SIEM: More valuable for internet-facing (more attack surface)
        "siem": {
            "internet-facing": 0.5,  # 50% reduction - detects attacks
            "dmz": 0.55,  # 45% reduction
            "internal": 0.7,  # 30% reduction - less external threat
            "restricted": 0.6,  # 40% reduction
        },
        # SOC 24x7: More valuable for internet-facing
        "soc_24x7": {
            "internet-facing": 0.4,  # 60% reduction - rapid response
            "dmz": 0.45,  # 55% reduction
            "internal": 0.6,  # 40% reduction
            "restricted": 0.5,  # 50% reduction
        },
        # PAM: More important for internal/restricted (admin access)
        "privileged_access_mgmt": {
            "internet-facing": 0.5,  # 50% reduction
            "dmz": 0.45,  # 55% reduction
            "internal": 0.35,  # 65% reduction - admin access critical
            "restricted": 0.25,  # 75% reduction - most critical here
        },
        # Firewall: Always important, slightly more for perimeter
        "firewall": {
            "internet-facing": 0.4,  # 60% reduction
            "dmz": 0.45,  # 55% reduction
            "internal": 0.6,  # 40% reduction - internal FW less strict
            "restricted": 0.4,  # 60% reduction
        },
        # Antivirus: Equally effective regardless of exposure
        "antivirus": {
            "internet-facing": 0.7,  # 30% reduction
            "dmz": 0.7,  # 30% reduction
            "internal": 0.7,  # 30% reduction
            "restricted": 0.7,  # 30% reduction
        },
    }

    # Default LRs for controls not in the conditional table
    DEFAULT_LRS: dict[str, float] = {
        "incident_response_plan": 0.7,
        "security_training": 0.8,
        "air_gapped": 0.05,
    }

    @classmethod
    def get_lr(cls, control: str, exposure: str) -> float:
        """Get the likelihood ratio for a control given exposure context.

        Args:
            control: Security control name
            exposure: Exposure type (internet-facing, dmz, internal, restricted)

        Returns:
            Likelihood ratio (< 1 means risk reduction)

        """
        exposure_lower = exposure.lower()

        # Check if control has conditional LRs
        if control in cls.CONDITIONAL_LRS:
            conditional = cls.CONDITIONAL_LRS[control]
            # Try exact match, then fallback to internal
            if exposure_lower in conditional:
                return conditional[exposure_lower]
            return conditional.get("internal", 0.5)

        # Check default LRs
        if control in cls.DEFAULT_LRS:
            return cls.DEFAULT_LRS[control]

        # Unknown control - no effect
        return 1.0


# =============================================================================
# PYDANTIC MODELS FOR CONFIGURATION
# =============================================================================


class LikelihoodRatioConfig(BaseModel):
    """Configuration for likelihood ratios - allows overriding defaults."""

    # Security controls (all should be <= 1.0 as they reduce risk)
    network_segmentation: float = Field(default=0.3, ge=0.01, le=1.0)
    firewall: float = Field(default=0.5, ge=0.01, le=1.0)
    waf: float = Field(default=0.4, ge=0.01, le=1.0)
    ids_ips: float = Field(default=0.5, ge=0.01, le=1.0)
    edr_xdr: float = Field(default=0.4, ge=0.01, le=1.0)
    antivirus: float = Field(default=0.7, ge=0.01, le=1.0)
    mfa: float = Field(default=0.3, ge=0.01, le=1.0)
    privileged_access_mgmt: float = Field(default=0.4, ge=0.01, le=1.0)
    siem: float = Field(default=0.6, ge=0.01, le=1.0)
    soc_24x7: float = Field(default=0.5, ge=0.01, le=1.0)
    air_gapped: float = Field(default=0.05, ge=0.01, le=1.0)

    # Patch management
    patch_daily: float = Field(default=0.2, ge=0.01, le=1.0)
    patch_weekly: float = Field(default=0.4, ge=0.01, le=1.0)
    patch_monthly: float = Field(default=0.7, ge=0.01, le=1.0)
    patch_quarterly: float = Field(default=0.9, ge=0.01, le=1.0)

    # Exposure (can be > 1.0 as they increase risk)
    exposure_internet: float = Field(default=2.5, ge=0.1, le=10.0)
    exposure_dmz: float = Field(default=1.8, ge=0.1, le=10.0)
    exposure_internal: float = Field(default=0.6, ge=0.1, le=10.0)
    exposure_restricted: float = Field(default=0.3, ge=0.1, le=10.0)

    # Threat indicators (> 1.0 as they increase risk)
    kev_listed: float = Field(default=3.0, ge=1.0, le=10.0)
    public_exploit: float = Field(default=2.0, ge=1.0, le=10.0)
    metasploit_module: float = Field(default=2.5, ge=1.0, le=10.0)
    weaponized: float = Field(default=4.0, ge=1.0, le=10.0)

    # Granular exploit indicators from CVSS-BT
    exploitdb: float = Field(default=2.0, ge=1.0, le=10.0)  # ExploitDB entry
    nuclei_template: float = Field(
        default=1.8,
        ge=1.0,
        le=10.0,
    )  # Nuclei scanner template
    poc_github: float = Field(default=1.5, ge=1.0, le=10.0)  # GitHub PoC


class SecurityControlsInput(BaseModel):
    """Input model for security controls - binary presence/absence."""

    # Network Controls
    network_segmentation: bool = False
    firewall: bool = False
    waf: bool = False
    ids_ips: bool = False

    # Endpoint Controls
    edr_xdr: bool = False
    antivirus: bool = False

    # Access Controls
    mfa: bool = False
    privileged_access_mgmt: bool = False

    # Patch Management (only one should be true)
    patch_daily: bool = False
    patch_weekly: bool = False
    patch_monthly: bool = False
    patch_quarterly: bool = False

    # Security Operations
    siem: bool = False
    soc_24x7: bool = False

    # Physical
    air_gapped: bool = False

    @field_validator("*", mode="before")
    @classmethod
    def coerce_bool(cls, v: Any) -> bool:
        """Coerce various truthy values to bool."""
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("true", "yes", "1", "on")
        return bool(v)


class ThreatIndicatorsInput(BaseModel):
    """Input model for threat indicators."""

    is_kev: bool = False
    has_public_exploit: bool = False
    has_metasploit_module: bool = False
    is_weaponized: bool = False
    apt_interest: bool = False
    ransomware_associated: bool = False

    # Granular exploit indicators from CVSS-BT
    has_exploitdb: bool = False  # ExploitDB entry exists
    has_nuclei: bool = False  # Nuclei scanner template exists
    has_poc_github: bool = False  # GitHub PoC exists


# =============================================================================
# BAYESIAN RISK ASSESSMENT RESULT
# =============================================================================


@dataclass
class BayesianRiskResult:
    """Result of Bayesian risk assessment with uncertainty quantification.

    Attributes:
        posterior_probability: P(Exploitation | Evidence) - main risk metric
        prior_probability: Original EPSS score
        log_likelihood_ratio: Sum of log(LR) for all evidence
        credible_interval_low: Lower bound of 95% credible interval
        credible_interval_high: Upper bound of 95% credible interval
        uncertainty: Width of credible interval (measure of confidence)
        risk_category: Categorical risk level (Critical/High/Medium/Low)
        contributing_factors: List of factors that influenced the assessment
        explanation: Human-readable explanation of the assessment

    """

    posterior_probability: float
    prior_probability: float
    log_likelihood_ratio: float
    credible_interval_low: float
    credible_interval_high: float
    uncertainty: float
    risk_category: str
    contributing_factors: list[tuple[str, float, str]] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for DataFrame integration."""
        return {
            "bayesian_risk_score": round(self.posterior_probability, 4),
            "prior_epss": round(self.prior_probability, 4),
            "log_lr": round(self.log_likelihood_ratio, 3),
            "ci_low": round(self.credible_interval_low, 4),
            "ci_high": round(self.credible_interval_high, 4),
            "uncertainty": round(self.uncertainty, 4),
            "risk_category": self.risk_category,
            "risk_explanation": self.explanation,
        }


# =============================================================================
# BAYESIAN RISK ASSESSOR
# =============================================================================


class BayesianRiskAssessor:
    """Bayesian risk assessment engine.

    Uses likelihood ratios to update EPSS prior probability based on:
    - Security controls in place
    - Exposure context
    - CVSS vector characteristics
    - Threat indicators

    Provides uncertainty quantification via credible intervals.
    """

    def __init__(self, config: LikelihoodRatioConfig | None = None):
        """Initialize the assessor with optional custom likelihood ratios.

        Args:
            config: Optional custom likelihood ratio configuration.
                   If None, uses research-derived defaults.

        """
        self.config = config or LikelihoodRatioConfig()
        self._build_lr_tables()

    def _build_lr_tables(self) -> None:
        """Build lookup tables from configuration."""
        self.control_lrs = {
            "network_segmentation": self.config.network_segmentation,
            "firewall": self.config.firewall,
            "waf": self.config.waf,
            "ids_ips": self.config.ids_ips,
            "edr_xdr": self.config.edr_xdr,
            "antivirus": self.config.antivirus,
            "mfa": self.config.mfa,
            "privileged_access_mgmt": self.config.privileged_access_mgmt,
            "siem": self.config.siem,
            "soc_24x7": self.config.soc_24x7,
            "air_gapped": self.config.air_gapped,
        }

        self.patch_lrs = {
            "daily": self.config.patch_daily,
            "weekly": self.config.patch_weekly,
            "monthly": self.config.patch_monthly,
            "quarterly": self.config.patch_quarterly,
        }

        self.exposure_lrs = {
            "internet-facing": self.config.exposure_internet,
            "internet": self.config.exposure_internet,
            "external": self.config.exposure_internet,
            "dmz": self.config.exposure_dmz,
            "internal": self.config.exposure_internal,
            "restricted": self.config.exposure_restricted,
            "air-gapped": self.config.air_gapped,
        }

        self.threat_lrs = {
            "kev": self.config.kev_listed,
            "public_exploit": self.config.public_exploit,
            "metasploit": self.config.metasploit_module,
            "weaponized": self.config.weaponized,
            # Granular exploit indicators from CVSS-BT
            "exploitdb": self.config.exploitdb,
            "nuclei": self.config.nuclei_template,
            "poc_github": self.config.poc_github,
        }

    def assess(
        self,
        epss_score: float,
        epss_percentile: float | None = None,
        security_controls: SecurityControlsInput | dict[str, bool] | None = None,
        exposure: str = "internal",
        cvss_vector: str | None = None,
        cvss_score: float | None = None,
        threat_indicators: ThreatIndicatorsInput | dict[str, bool] | None = None,
        asset_criticality: str = "medium",
        nlp_features: dict[str, Any] | None = None,
    ) -> BayesianRiskResult:
        """Perform Bayesian risk assessment.

        Args:
            epss_score: EPSS probability (0-1) - serves as prior
            epss_percentile: EPSS percentile (0-100) - used for uncertainty
            security_controls: Security controls in place
            exposure: Exposure context (internet-facing, dmz, internal, restricted)
            cvss_vector: CVSS v3 vector string
            cvss_score: CVSS base score (0-10)
            threat_indicators: Threat indicators (KEV, exploits, etc.)
            asset_criticality: Asset criticality (critical, high, medium, low)
            nlp_features: NLP-extracted features from description

        Returns:
            BayesianRiskResult with posterior probability and uncertainty

        """
        # Normalize inputs
        epss = self._normalize_epss(epss_score)
        controls = self._normalize_controls(security_controls)
        threats = self._normalize_threats(threat_indicators)

        # Check for known exploits (granular CVSS-BT indicators)
        is_kev = threats.get("is_kev", False)
        has_metasploit = threats.get("has_metasploit_module", False) or threats.get(
            "has_metasploit",
            False,
        )
        has_exploitdb = threats.get("has_exploitdb", False)
        has_nuclei = threats.get("has_nuclei", False)
        has_poc = threats.get("has_poc_github", False)
        has_public_exploit = threats.get("has_public_exploit", False)
        is_weaponized = threats.get("is_weaponized", False)

        has_known_exploit = (
            is_kev
            or has_public_exploit
            or has_metasploit
            or is_weaponized
            or has_exploitdb
            or has_nuclei
            or has_poc
        )

        # Apply minimum prior floor based on exploit/KEV status
        # KEV-listed or weaponized exploits should never have negligible prior
        if is_kev or is_weaponized:
            epss = max(epss, 0.15)  # Minimum 15% for KEV/weaponized
        elif has_metasploit:
            epss = max(epss, 0.10)  # Minimum 10% for Metasploit
        elif has_exploitdb or has_public_exploit:
            epss = max(epss, 0.05)  # Minimum 5% for public exploits
        elif has_nuclei:
            epss = max(epss, 0.03)  # Minimum 3% for Nuclei templates
        elif has_poc:
            epss = max(epss, 0.01)  # Minimum 1% for PoC

        # EPSS threshold: top 10% (~0.07) or top 5% (~0.15) indicates real threat
        exploitation_plausible = has_known_exploit or epss >= 0.05

        # Track contributing factors
        factors: list[tuple[str, float, str]] = []

        # Convert prior probability to log-odds
        # Using log-odds for numerical stability
        prior_log_odds = self._prob_to_log_odds(epss)

        # Accumulate log likelihood ratios
        total_log_lr = 0.0

        # 1. Apply security control LRs (exposure-conditional)
        # Controls have different effectiveness based on exposure context
        control_log_lr, control_factors = self._apply_control_lrs(controls, exposure)
        total_log_lr += control_log_lr
        factors.extend(control_factors)

        # 2. Apply exposure LR (gated by exploitability)
        exposure_lr = self._get_gated_exposure_lr(
            exposure,
            epss,
            exploitation_plausible,
        )
        if exposure_lr != 1.0:
            total_log_lr += math.log(exposure_lr)
            direction = "increases" if exposure_lr > 1 else "decreases"
            base_exp_lr = self.exposure_lrs.get(exposure.lower(), 1.0)
            if not exploitation_plausible and exposure_lr < base_exp_lr:
                factors.append(
                    (
                        f"Exposure: {exposure} (capped)",
                        exposure_lr,
                        f"{direction} risk (capped due to low exploitability)",
                    ),
                )
            else:
                factors.append(
                    (
                        f"Exposure: {exposure}",
                        exposure_lr,
                        f"{direction} risk by {abs(1 - exposure_lr) * 100:.0f}%",
                    ),
                )

        # 3. Apply CVSS vector LRs (gated by exploitability for amplification)
        if cvss_vector:
            cvss_log_lr, cvss_factors = self._apply_cvss_vector_lrs(
                cvss_vector,
                exposure,
                exploitation_plausible,
            )
            total_log_lr += cvss_log_lr
            factors.extend(cvss_factors)

        # 4. Apply threat indicator LRs (always apply - these CREATE exploitability)
        threat_log_lr, threat_factors = self._apply_threat_lrs(threats)
        total_log_lr += threat_log_lr
        factors.extend(threat_factors)

        # 5. Apply asset criticality modifier (gated by exploitability)
        # High-value assets are more attractive targets, but only if exploitable
        criticality_lr = self._get_gated_criticality_lr(
            asset_criticality,
            exploitation_plausible,
        )
        if criticality_lr != 1.0:
            total_log_lr += math.log(criticality_lr)
            direction = "increases" if criticality_lr > 1 else "decreases"
            factors.append(
                (
                    f"Asset criticality: {asset_criticality}",
                    criticality_lr,
                    f"{direction} risk by {abs(1 - criticality_lr) * 100:.0f}%",
                ),
            )

        # 6. Apply NLP-extracted features (weak signals, gated by confidence)
        if nlp_features:
            nlp_log_lr, nlp_factors = self._apply_nlp_features(
                nlp_features,
                exploitation_plausible,
            )
            total_log_lr += nlp_log_lr
            factors.extend(nlp_factors)

        # Calculate posterior log-odds and convert to probability
        posterior_log_odds = prior_log_odds + total_log_lr
        posterior_prob = self._log_odds_to_prob(posterior_log_odds)

        # Apply minimum posterior floor for KEV/exploit cases
        # Security controls can reduce risk but shouldn't make actively exploited
        # vulnerabilities appear negligible - that's misleading to defenders
        if is_kev or is_weaponized:
            posterior_prob = max(posterior_prob, 0.05)  # Minimum 5% for KEV
        elif has_metasploit:
            posterior_prob = max(posterior_prob, 0.03)  # Minimum 3% for Metasploit
        elif has_exploitdb or has_public_exploit:
            posterior_prob = max(posterior_prob, 0.02)  # Minimum 2% for public exploits
        elif has_nuclei:
            posterior_prob = max(posterior_prob, 0.015)  # Minimum 1.5% for Nuclei
        elif has_poc:
            posterior_prob = max(posterior_prob, 0.01)  # Minimum 1% for PoC

        # Calculate credible interval based on uncertainty
        ci_low, ci_high = self._calculate_credible_interval(
            posterior_prob,
            epss_percentile,
            len(factors),
        )

        # Determine risk category
        risk_category = self._categorize_risk(posterior_prob, cvss_score)

        # Generate explanation
        explanation = self._generate_explanation(
            epss,
            posterior_prob,
            factors,
            risk_category,
        )

        return BayesianRiskResult(
            posterior_probability=posterior_prob,
            prior_probability=epss,
            log_likelihood_ratio=total_log_lr,
            credible_interval_low=ci_low,
            credible_interval_high=ci_high,
            uncertainty=ci_high - ci_low,
            risk_category=risk_category,
            contributing_factors=factors,
            explanation=explanation,
        )

    def _normalize_epss(self, epss: float | None) -> float:
        """Normalize EPSS to valid probability range."""
        if epss is None or pd.isna(epss):
            return 0.01  # Default to low probability, not zero

        epss = float(epss)

        # Handle percentage format
        if epss > 1.0:
            epss = epss / 100.0

        # Clamp to valid range, avoiding 0 and 1 for log-odds
        return max(0.001, min(0.999, epss))

    def _normalize_controls(
        self,
        controls: SecurityControlsInput | dict[str, bool] | None,
    ) -> dict[str, bool]:
        """Normalize security controls input."""
        if controls is None:
            return {}
        if isinstance(controls, SecurityControlsInput):
            return controls.model_dump()
        return {k: bool(v) for k, v in controls.items()}

    def _normalize_threats(
        self,
        threats: ThreatIndicatorsInput | dict[str, bool] | None,
    ) -> dict[str, bool]:
        """Normalize threat indicators input."""
        if threats is None:
            return {}
        if isinstance(threats, ThreatIndicatorsInput):
            return threats.model_dump()
        return {k: bool(v) for k, v in threats.items()}

    def _prob_to_log_odds(self, p: float) -> float:
        """Convert probability to log-odds."""
        return math.log(p / (1 - p))

    def _log_odds_to_prob(self, log_odds: float) -> float:
        """Convert log-odds to probability."""
        # Clamp to prevent overflow
        log_odds = max(-20, min(20, log_odds))
        return 1 / (1 + math.exp(-log_odds))

    def _apply_control_lrs(
        self,
        controls: dict[str, bool],
        exposure: str = "internal",
    ) -> tuple[float, list[tuple[str, float, str]]]:
        """Apply likelihood ratios for security controls with exposure conditioning.

        This implements a simplified form of conditional Bayes where control
        effectiveness depends on the exposure context. For example:
        - WAF is highly effective for internet-facing (LR=0.3, 70% reduction)
        - WAF has minimal effect on internal services (LR=0.9, 10% reduction)

        Args:
            controls: Dictionary of control name -> present (bool)
            exposure: Exposure context (internet-facing, dmz, internal, restricted)

        Returns:
            Tuple of (total log LR, list of contributing factors)

        """
        total_log_lr = 0.0
        factors = []

        for control, present in controls.items():
            if not present:
                continue

            # Check if it's a patch management control
            if control.startswith("patch_"):
                patch_level = control.replace("patch_", "")
                lr = self.patch_lrs.get(patch_level, 1.0)
                if lr != 1.0:
                    total_log_lr += math.log(lr)
                    factors.append(
                        (
                            f"Patch management: {patch_level}",
                            lr,
                            f"reduces risk by {(1 - lr) * 100:.0f}%",
                        ),
                    )
                continue

            # Use exposure-conditional LR for security controls
            lr = ExposureConditionalControlLR.get_lr(control, exposure)
            if lr != 1.0:
                total_log_lr += math.log(lr)
                control_name = control.replace("_", " ").title()
                reduction = (1 - lr) * 100
                factors.append(
                    (
                        f"Control: {control_name}",
                        lr,
                        f"reduces risk by {reduction:.0f}% (for {exposure})",
                    ),
                )

        return total_log_lr, factors

    def _get_gated_exposure_lr(
        self,
        exposure: str,
        epss: float,
        exploitation_plausible: bool,
    ) -> float:
        """Get exposure likelihood ratio, gated by exploitability.

        Exposure only amplifies risk if exploitation is actually plausible.
        Without a known exploit or high EPSS, being internet-facing doesn't
        magically make an unexploitable vulnerability exploitable.

        Args:
            exposure: Exposure context (internet-facing, internal, etc.)
            epss: Normalized EPSS score
            exploitation_plausible: Whether exploitation is plausible

        Returns:
            Gated likelihood ratio for exposure

        """
        base_lr = self.exposure_lrs.get(exposure.lower(), 1.0)

        # If exploitation is plausible, apply full exposure LR
        if exploitation_plausible:
            return base_lr

        # If exploitation is NOT plausible:
        # - Reductions (LR < 1) still apply (restricted access helps)
        # - Amplifications (LR > 1) are capped to prevent false inflation
        if base_lr <= 1.0:
            return base_lr

        # Cap amplification for low-exploitability vulns
        # Allow slight increase (1.2) for attack surface consideration
        # but not full amplification
        max_amplification = 1.2
        return min(base_lr, max_amplification)

    def _get_gated_criticality_lr(
        self,
        criticality: str,
        exploitation_plausible: bool,
    ) -> float:
        """Get asset criticality likelihood ratio, gated by exploitability.

        High-value assets are more attractive targets, but only if the
        vulnerability is actually exploitable.

        Args:
            criticality: Asset criticality level
            exploitation_plausible: Whether exploitation is plausible

        Returns:
            Gated likelihood ratio for asset criticality

        """
        base_lr = self._get_criticality_lr(criticality)

        # If exploitation is plausible, apply full criticality LR
        if exploitation_plausible:
            return base_lr

        # If exploitation is NOT plausible:
        # - Reductions still apply (low-value assets less interesting)
        # - Amplifications are neutralized (can't target what you can't exploit)
        if base_lr <= 1.0:
            return base_lr

        # Neutralize amplification for unexploitable vulns
        return 1.0

    def _apply_cvss_vector_lrs(
        self,
        cvss_vector: str,
        exposure: str,
        exploitation_plausible: bool = True,
    ) -> tuple[float, list[tuple[str, float, str]]]:
        """Apply likelihood ratios based on CVSS vector components.

        Amplification factors (LR > 1) are gated by exploitability.
        Reduction factors (LR < 1) always apply.

        Args:
            cvss_vector: CVSS v3 vector string
            exposure: Exposure context
            exploitation_plausible: Whether exploitation is plausible

        Returns:
            Tuple of (total log LR, list of contributing factors)

        """
        total_log_lr = 0.0
        factors = []

        # Parse CVSS vector
        components = self._parse_cvss_vector(cvss_vector)
        if not components:
            return 0.0, []

        # Normalize exposure for lookup
        exp_lower = exposure.lower()
        internet_exposures = ("internet-facing", "external", "dmz")
        exposure_key = "internet" if exp_lower in internet_exposures else "internal"
        if exp_lower in ("restricted", "air-gapped"):
            exposure_key = "restricted"

        # Attack Vector (AV)
        av = components.get("AV")
        if av and av in CVSSVectorLR.ATTACK_VECTOR:
            raw_lr = CVSSVectorLR.ATTACK_VECTOR[av].get(exposure_key, 1.0)
            lr = self._gate_amplification(raw_lr, exploitation_plausible)
            if lr != 1.0:
                total_log_lr += math.log(lr)
                av_names = {
                    "N": "Network",
                    "A": "Adjacent",
                    "L": "Local",
                    "P": "Physical",
                }
                direction = "increases" if lr > 1 else "decreases"
                capped = " (capped)" if lr < raw_lr else ""
                factors.append(
                    (
                        f"Attack Vector: {av_names.get(av, av)}{capped}",
                        lr,
                        f"{direction} risk given {exposure} exposure",
                    ),
                )

        # Attack Complexity (AC)
        ac = components.get("AC")
        if ac and ac in CVSSVectorLR.ATTACK_COMPLEXITY:
            raw_lr = CVSSVectorLR.ATTACK_COMPLEXITY[ac]
            lr = self._gate_amplification(raw_lr, exploitation_plausible)
            if lr != 1.0:
                total_log_lr += math.log(lr)
                ac_names = {"L": "Low", "H": "High"}
                direction = "increases" if lr > 1 else "decreases"
                capped = " (capped)" if lr < raw_lr else ""
                factors.append(
                    (
                        f"Attack Complexity: {ac_names.get(ac, ac)}{capped}",
                        lr,
                        f"{direction} risk - {'easy' if ac == 'L' else 'hard'}",
                    ),
                )

        # Privileges Required (PR)
        pr = components.get("PR")
        if pr and pr in CVSSVectorLR.PRIVILEGES_REQUIRED:
            raw_lr = CVSSVectorLR.PRIVILEGES_REQUIRED[pr]
            lr = self._gate_amplification(raw_lr, exploitation_plausible)
            if lr != 1.0:
                total_log_lr += math.log(lr)
                pr_names = {"N": "None", "L": "Low", "H": "High"}
                direction = "increases" if lr > 1 else "decreases"
                capped = " (capped)" if lr < raw_lr else ""
                factors.append(
                    (
                        f"Privileges Required: {pr_names.get(pr, pr)}{capped}",
                        lr,
                        f"{direction} risk - {'no auth' if pr == 'N' else 'auth needed'}",
                    ),
                )

        # User Interaction (UI)
        ui = components.get("UI")
        if ui and ui in CVSSVectorLR.USER_INTERACTION:
            raw_lr = CVSSVectorLR.USER_INTERACTION[ui]
            lr = self._gate_amplification(raw_lr, exploitation_plausible)
            if lr != 1.0:
                total_log_lr += math.log(lr)
                ui_names = {"N": "None", "R": "Required"}
                direction = "increases" if lr > 1 else "decreases"
                capped = " (capped)" if lr < raw_lr else ""
                factors.append(
                    (
                        f"User Interaction: {ui_names.get(ui, ui)}{capped}",
                        lr,
                        f"{direction} risk - {'automated' if ui == 'N' else 'user action'}",
                    ),
                )

        # Scope (S)
        scope = components.get("S")
        if scope and scope in CVSSVectorLR.SCOPE:
            raw_lr = CVSSVectorLR.SCOPE[scope]
            lr = self._gate_amplification(raw_lr, exploitation_plausible)
            if lr != 1.0:
                total_log_lr += math.log(lr)
                scope_names = {"U": "Unchanged", "C": "Changed"}
                capped = " (capped)" if lr < raw_lr else ""
                factors.append(
                    (
                        f"Scope: {scope_names.get(scope, scope)}{capped}",
                        lr,
                        "can affect other components"
                        if scope == "C"
                        else "limited scope",
                    ),
                )

        return total_log_lr, factors

    def _gate_amplification(
        self,
        lr: float,
        exploitation_plausible: bool,
        max_cap: float = 1.1,
    ) -> float:
        """Gate amplification factors by exploitability.

        Args:
            lr: Raw likelihood ratio
            exploitation_plausible: Whether exploitation is plausible
            max_cap: Maximum LR when exploitation is not plausible

        Returns:
            Gated likelihood ratio

        """
        if exploitation_plausible:
            return lr
        if lr <= 1.0:
            return lr  # Reductions always apply
        return min(lr, max_cap)  # Cap amplifications

    def _parse_cvss_vector(self, vector: str) -> dict[str, str]:
        """Parse CVSS vector string into components."""
        if not vector or not isinstance(vector, str):
            return {}

        components = {}
        parts = vector.split("/")

        for part in parts:
            if ":" not in part or part.startswith("CVSS:"):
                continue
            try:
                metric, value = part.split(":", 1)
                components[metric.strip().upper()] = value.strip().upper()
            except ValueError:
                continue

        return components

    def _apply_threat_lrs(
        self,
        threats: dict[str, bool],
    ) -> tuple[float, list[tuple[str, float, str]]]:
        """Apply likelihood ratios for threat indicators."""
        total_log_lr = 0.0
        factors = []

        threat_mapping = {
            "is_kev": ("kev", "KEV Listed", "actively exploited"),
            "has_public_exploit": (
                "public_exploit",
                "Public Exploit",
                "exploit available",
            ),
            "has_metasploit_module": (
                "metasploit",
                "Metasploit Module",
                "weaponized exploit",
            ),
            "is_weaponized": ("weaponized", "Weaponized", "used in attacks"),
            "apt_interest": ("weaponized", "APT Interest", "APT targeted"),
            "ransomware_associated": ("weaponized", "Ransomware", "ransomware"),
            # Granular exploit indicators from CVSS-BT
            "has_exploitdb": ("exploitdb", "ExploitDB", "public exploit code"),
            "has_metasploit": ("metasploit", "Metasploit", "weaponized exploit"),
            "has_nuclei": ("nuclei", "Nuclei Template", "automated scanning"),
            "has_poc_github": ("poc_github", "GitHub PoC", "proof of concept"),
        }

        for threat_key, present in threats.items():
            if not present:
                continue

            mapping = threat_mapping.get(threat_key)
            if not mapping:
                continue

            lr_key, name, description = mapping
            lr = self.threat_lrs.get(lr_key, 1.0)

            if lr != 1.0:
                total_log_lr += math.log(lr)
                factors.append(
                    (f"Threat: {name}", lr, f"increases risk - {description}"),
                )

        return total_log_lr, factors

    def _apply_nlp_features(
        self,
        nlp_features: dict[str, Any],
        exploitation_plausible: bool,
    ) -> tuple[float, list[tuple[str, float, str]]]:
        """Apply NLP-extracted features as weak signals.

        NLP features are intentionally conservative (LRs close to 1.0) since
        regex-based extraction is less reliable than structured data.
        """
        total_log_lr = 0.0
        factors: list[tuple[str, float, str]] = []

        # Only apply if confidence is reasonable
        confidence = nlp_features.get("nlp_confidence", 0)
        if confidence < 0.3:
            return total_log_lr, factors

        # Attack type LRs (conservative)
        attack_type_lrs = {
            "remote_code_execution": 1.15,
            "command_injection": 1.12,
            "sql_injection": 1.1,
            "buffer_overflow": 1.1,
            "use_after_free": 1.1,
            "authentication_bypass": 1.12,
            "privilege_escalation": 1.1,
            "insecure_deserialization": 1.1,
            "cross_site_scripting": 1.02,
            "information_disclosure": 1.0,
            "denial_of_service": 0.98,
            "open_redirect": 0.95,
        }

        primary_attack = nlp_features.get("nlp_primary_attack")
        if primary_attack and primary_attack in attack_type_lrs:
            lr = attack_type_lrs[primary_attack]
            # Gate amplification by exploitability
            if not exploitation_plausible and lr > 1.0:
                lr = min(lr, 1.05)  # Cap amplification
            if lr != 1.0:
                total_log_lr += math.log(lr)
                direction = "increases" if lr > 1 else "decreases"
                attack_name = primary_attack.replace("_", " ").title()
                factors.append(
                    (
                        f"NLP: {attack_name}",
                        lr,
                        f"{direction} risk (from description)",
                    ),
                )

        # Authentication context
        requires_auth = nlp_features.get("nlp_requires_auth")
        if requires_auth is True:
            lr = 0.9  # Auth required reduces risk
            total_log_lr += math.log(lr)
            factors.append(
                ("NLP: Auth required", lr, "reduces risk - authentication needed"),
            )
        elif requires_auth is False:
            lr = 1.08 if exploitation_plausible else 1.02
            total_log_lr += math.log(lr)
            factors.append(
                ("NLP: No auth required", lr, "increases risk - unauthenticated"),
            )

        # User interaction context
        requires_ui = nlp_features.get("nlp_requires_user_interaction")
        if requires_ui is True:
            lr = 0.92  # User interaction reduces exploitability
            total_log_lr += math.log(lr)
            factors.append(
                ("NLP: User interaction", lr, "reduces risk - needs victim action"),
            )

        # Default configuration
        if nlp_features.get("nlp_default_config"):
            lr = 1.08 if exploitation_plausible else 1.02
            total_log_lr += math.log(lr)
            factors.append(
                ("NLP: Default config", lr, "increases risk - affects defaults"),
            )

        return total_log_lr, factors

    def _get_criticality_lr(self, criticality: str) -> float:
        """Get likelihood ratio modifier for asset criticality."""
        criticality_lrs = {
            "critical": 1.5,  # Critical assets are higher value targets
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8,
        }
        return criticality_lrs.get(criticality.lower(), 1.0)

    def _calculate_credible_interval(
        self,
        posterior: float,
        epss_percentile: float | None,
        num_factors: int,
    ) -> tuple[float, float]:
        """Calculate 95% credible interval for the posterior probability.

        Uncertainty is higher when:
        - EPSS percentile is low (less confidence in prior)
        - Fewer factors contribute (less evidence)
        - Posterior is near 0.5 (maximum uncertainty)

        Uses a beta distribution approximation.
        """
        # Base uncertainty from EPSS percentile
        if epss_percentile is None or pd.isna(epss_percentile):
            percentile_factor = 0.5  # High uncertainty
        else:
            # Higher percentile = more confidence in EPSS
            percentile_factor = 1 - (epss_percentile / 100)

        # Evidence factor - more factors = less uncertainty
        evidence_factor = max(0.1, 1 - (num_factors * 0.05))

        # Entropy factor - uncertainty highest at p=0.5
        entropy_factor = 4 * posterior * (1 - posterior)

        # Combined uncertainty (0.05 to 0.3 range)
        uncertainty_product = percentile_factor * evidence_factor * entropy_factor
        base_uncertainty = 0.05 + 0.25 * uncertainty_product

        # Calculate interval
        ci_low = max(0.0, posterior - base_uncertainty)
        ci_high = min(1.0, posterior + base_uncertainty)

        return ci_low, ci_high

    def _categorize_risk(self, posterior: float, cvss_score: float | None) -> str:
        """Categorize risk level based on posterior probability.

        Thresholds are based on EPSS research showing:
        - Top 1% EPSS (~0.37) captures most exploited vulns
        - Top 10% EPSS (~0.07) captures nearly all exploited vulns
        """
        # Primary categorization by posterior probability
        if posterior >= 0.4:
            return "Critical"
        if posterior >= 0.15:
            return "High"
        if posterior >= 0.05:
            return "Medium"
        if posterior >= 0.01:
            return "Low"
        return "Negligible"

    def _generate_explanation(
        self,
        prior: float,
        posterior: float,
        factors: list[tuple[str, float, str]],
        risk_category: str,
    ) -> str:
        """Generate human-readable explanation of the assessment."""
        change = posterior / prior if prior > 0 else 1

        if change > 1.5:
            change_desc = f"increased {change:.1f}x"
        elif change < 0.67:
            change_desc = f"decreased to {change:.1%} of prior"
        else:
            change_desc = "remained similar"

        # Top 3 most impactful factors
        sorted_factors = sorted(
            factors,
            key=lambda x: abs(math.log(x[1])),
            reverse=True,
        )
        top_factors = sorted_factors[:3]

        factor_strs = [f"{f[0]} ({f[2]})" for f in top_factors]
        if factor_strs:
            factors_desc = "; ".join(factor_strs)
        else:
            factors_desc = "no significant factors"

        return (
            f"{risk_category} risk (P={posterior:.2%}). "
            f"Prior EPSS {prior:.2%} {change_desc}. "
            f"Key factors: {factors_desc}."
        )


# =============================================================================
# DATAFRAME INTEGRATION
# =============================================================================


def assess_vulnerabilities_bayesian(
    df: pd.DataFrame,
    epss_score_col: str = "epss_score",
    epss_percentile_col: str | None = "epss_percentile",
    cvss_vector_col: str = "cvss_vector",
    cvss_score_col: str = "cvss_score",
    exposure_col: str = "exposure",
    asset_value_col: str = "asset_value",
    security_posture_col: str | None = "security_posture",
    kev_col: str | None = "is_kev",
    config: LikelihoodRatioConfig | None = None,
) -> pd.DataFrame:
    """Assess all vulnerabilities in a DataFrame using Bayesian risk assessment.

    Args:
        df: DataFrame with vulnerability data
        epss_score_col: Column name for EPSS score
        epss_percentile_col: Column name for EPSS percentile
        cvss_vector_col: Column name for CVSS vector
        cvss_score_col: Column name for CVSS score
        exposure_col: Column name for exposure context
        asset_value_col: Column name for asset criticality
        security_posture_col: Column name for security posture dict
        kev_col: Column name for KEV indicator
        config: Optional custom likelihood ratio configuration

    Returns:
        DataFrame with added Bayesian risk columns

    """
    assessor = BayesianRiskAssessor(config)

    def assess_row(row: pd.Series) -> dict[str, Any]:
        """Assess a single vulnerability."""
        # Extract values
        epss = row.get(epss_score_col)
        epss_percentile = row.get(epss_percentile_col) if epss_percentile_col else None
        cvss_vector = row.get(cvss_vector_col)
        cvss_score = row.get(cvss_score_col)
        exposure = str(row.get(exposure_col, "internal"))
        asset_value = str(row.get(asset_value_col, "medium"))

        # Extract security controls from security_posture dict
        security_controls = {}
        if security_posture_col and security_posture_col in row.index:
            posture = row.get(security_posture_col)
            if isinstance(posture, dict):
                security_controls = _extract_controls_from_posture(posture)

        # Extract threat indicators
        threat_indicators = {}
        if kev_col and kev_col in row.index:
            threat_indicators["is_kev"] = bool(row.get(kev_col, False))

        # Check for other threat columns
        for col in ["has_public_exploit", "has_metasploit_module", "is_weaponized"]:
            if col in row.index:
                threat_indicators[col] = bool(row.get(col, False))

        # Perform assessment
        result = assessor.assess(
            epss_score=epss,
            epss_percentile=epss_percentile,
            security_controls=security_controls,
            exposure=exposure,
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            threat_indicators=threat_indicators,
            asset_criticality=asset_value,
        )

        return result.to_dict()

    logger.info("Performing Bayesian risk assessment...")
    logger.info(f"  EPSS column: {epss_score_col}")
    logger.info(f"  CVSS vector column: {cvss_vector_col}")
    logger.info(f"  Exposure column: {exposure_col}")

    # Apply assessment to each row
    results = df.apply(assess_row, axis=1, result_type="expand")

    # Add result columns to DataFrame
    for col in results.columns:
        df[col] = results[col]

    # Log summary
    critical_count = (df["risk_category"] == "Critical").sum()
    high_count = (df["risk_category"] == "High").sum()
    medium_count = (df["risk_category"] == "Medium").sum()
    low_count = (df["risk_category"] == "Low").sum()

    logger.info(
        f"Bayesian assessment complete. "
        f"Critical: {critical_count}, High: {high_count}, "
        f"Medium: {medium_count}, Low: {low_count}",
    )

    avg_risk = df["bayesian_risk_score"].mean()
    avg_uncertainty = df["uncertainty"].mean()
    logger.info(f"  Average risk score: {avg_risk:.4f}")
    logger.info(f"  Average uncertainty: {avg_uncertainty:.4f}")

    return df


def _extract_controls_from_posture(posture: dict[str, Any]) -> dict[str, bool]:
    """Extract security controls from security_posture dictionary."""
    controls = {}

    # Direct boolean controls
    control_mapping = {
        "network_segmentation": "network_segmentation",
        "mfa_enforced": "mfa",
        "encryption_at_rest": None,  # Not directly a control for exploitation
        "incident_response_plan": None,  # Reduces impact, not likelihood
        "security_training": None,  # Indirect effect
    }

    for posture_key, control_key in control_mapping.items():
        if control_key and posture_key in posture:
            controls[control_key] = bool(posture[posture_key])

    # Patch management
    patch_mgmt = posture.get("patch_management", "monthly")
    if patch_mgmt:
        controls[f"patch_{patch_mgmt}"] = True

    # Check for additional controls that might be in posture
    additional_controls = [
        "firewall",
        "waf",
        "ids_ips",
        "edr_xdr",
        "antivirus",
        "privileged_access_mgmt",
        "siem",
        "soc_24x7",
        "air_gapped",
    ]
    for ctrl in additional_controls:
        if ctrl in posture:
            controls[ctrl] = bool(posture[ctrl])

    return controls
