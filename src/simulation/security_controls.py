"""Security Controls Model for Scenario Simulation.

This module defines the security controls that can be present in a simulated
environment. These controls are used by the Bayesian risk assessment to
adjust exploitation probability based on defensive measures in place.

The controls are organized by category:
- Network Controls: Segmentation, firewalls, WAF, IDS/IPS
- Endpoint Controls: EDR/XDR, antivirus
- Access Controls: MFA, PAM, RBAC
- Patch Management: Daily, weekly, monthly, quarterly cycles
- Security Operations: SIEM, SOC, incident response
- Physical Controls: Air-gapped networks

Each control has:
- A binary presence indicator (True/False)
- Probability of being present based on security maturity
- Industry-specific adjustments
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SecurityMaturityLevel(str, Enum):
    """Security maturity levels based on industry frameworks (CMMI, NIST CSF)."""

    INITIAL = "initial"  # Ad-hoc, reactive security
    DEVELOPING = "developing"  # Basic controls, inconsistent
    DEFINED = "defined"  # Documented policies, some automation
    MANAGED = "managed"  # Measured and controlled
    OPTIMIZING = "optimizing"  # Continuous improvement, advanced


class PatchManagementCadence(str, Enum):
    """Patch management frequency."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    AD_HOC = "ad_hoc"


@dataclass
class ControlProbabilities:
    """Probability of each control being present at different maturity levels.

    These probabilities are derived from:
    - Verizon DBIR control adoption statistics
    - SANS security spending surveys
    - Industry benchmarks
    """

    # Network Controls
    network_segmentation: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.1,
            "developing": 0.3,
            "defined": 0.6,
            "managed": 0.85,
            "optimizing": 0.95,
        },
    )

    firewall: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.5,
            "developing": 0.8,
            "defined": 0.95,
            "managed": 0.99,
            "optimizing": 0.99,
        },
    )

    waf: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.05,
            "developing": 0.2,
            "defined": 0.5,
            "managed": 0.75,
            "optimizing": 0.9,
        },
    )

    ids_ips: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.1,
            "developing": 0.3,
            "defined": 0.6,
            "managed": 0.8,
            "optimizing": 0.95,
        },
    )

    # Endpoint Controls
    edr_xdr: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.05,
            "developing": 0.15,
            "defined": 0.4,
            "managed": 0.7,
            "optimizing": 0.9,
        },
    )

    antivirus: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.6,
            "developing": 0.8,
            "defined": 0.9,
            "managed": 0.95,
            "optimizing": 0.95,
        },
    )

    # Access Controls
    mfa: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.1,
            "developing": 0.3,
            "defined": 0.6,
            "managed": 0.85,
            "optimizing": 0.95,
        },
    )

    privileged_access_mgmt: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.02,
            "developing": 0.1,
            "defined": 0.3,
            "managed": 0.6,
            "optimizing": 0.85,
        },
    )

    # Security Operations
    siem: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.05,
            "developing": 0.15,
            "defined": 0.4,
            "managed": 0.7,
            "optimizing": 0.9,
        },
    )

    soc_24x7: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.01,
            "developing": 0.05,
            "defined": 0.2,
            "managed": 0.5,
            "optimizing": 0.8,
        },
    )

    # Patch Management (probability of each cadence)
    patch_daily: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.01,
            "developing": 0.05,
            "defined": 0.1,
            "managed": 0.3,
            "optimizing": 0.6,
        },
    )

    patch_weekly: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.05,
            "developing": 0.15,
            "defined": 0.3,
            "managed": 0.4,
            "optimizing": 0.3,
        },
    )

    patch_monthly: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.3,
            "developing": 0.5,
            "defined": 0.4,
            "managed": 0.25,
            "optimizing": 0.08,
        },
    )

    patch_quarterly: dict[str, float] = field(
        default_factory=lambda: {
            "initial": 0.4,
            "developing": 0.25,
            "defined": 0.15,
            "managed": 0.04,
            "optimizing": 0.01,
        },
    )


class SecurityControlsConfig(BaseModel):
    """Configuration for security controls in a simulated environment.

    All controls are binary (present/absent) as requested.
    """

    # Network Controls
    network_segmentation: bool = Field(
        default=False,
        description="Network is segmented into zones (DMZ, app tier, data tier)",
    )
    firewall: bool = Field(default=True, description="Perimeter firewall in place")
    waf: bool = Field(
        default=False,
        description="Web Application Firewall protecting web services",
    )
    ids_ips: bool = Field(
        default=False,
        description="Intrusion Detection/Prevention System active",
    )

    # Endpoint Controls
    edr_xdr: bool = Field(
        default=False,
        description="Endpoint Detection and Response / Extended Detection and Response",
    )
    antivirus: bool = Field(
        default=True,
        description="Traditional antivirus/antimalware",
    )

    # Access Controls
    mfa: bool = Field(default=False, description="Multi-Factor Authentication enforced")
    privileged_access_mgmt: bool = Field(
        default=False,
        description="Privileged Access Management solution",
    )

    # Patch Management (only one should be true)
    patch_daily: bool = Field(
        default=False,
        description="Critical patches applied within 24 hours",
    )
    patch_weekly: bool = Field(default=False, description="Patches applied weekly")
    patch_monthly: bool = Field(
        default=True,
        description="Patches applied monthly (Patch Tuesday cycle)",
    )
    patch_quarterly: bool = Field(
        default=False,
        description="Patches applied quarterly",
    )

    # Security Operations
    siem: bool = Field(
        default=False,
        description="Security Information and Event Management",
    )
    soc_24x7: bool = Field(default=False, description="24/7 Security Operations Center")
    incident_response_plan: bool = Field(
        default=False,
        description="Documented incident response plan",
    )
    security_training: bool = Field(
        default=False,
        description="Regular security awareness training",
    )

    # Physical/Environmental
    air_gapped: bool = Field(
        default=False,
        description="Air-gapped network (no internet connectivity)",
    )

    def get_patch_cadence(self) -> str:
        """Get the active patch management cadence."""
        if self.patch_daily:
            return "daily"
        if self.patch_weekly:
            return "weekly"
        if self.patch_monthly:
            return "monthly"
        if self.patch_quarterly:
            return "quarterly"
        return "ad_hoc"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for scenario storage."""
        return self.model_dump()

    def get_active_controls(self) -> list[str]:
        """Get list of active control names."""
        controls = []
        for field_name, value in self.model_dump().items():
            if value is True and not field_name.startswith("patch_"):
                controls.append(field_name)

        # Add patch management
        cadence = self.get_patch_cadence()
        if cadence != "ad_hoc":
            controls.append(f"patch_{cadence}")

        return controls

    def count_controls(self) -> int:
        """Count number of active controls."""
        return len(self.get_active_controls())


class SecurityControlsGenerator:
    """Generates realistic security control configurations based on:
    - Organization size
    - Industry
    - Security maturity level
    - Environment type (dev/test/prod)
    """

    def __init__(self, probabilities: ControlProbabilities | None = None):
        """Initialize the generator.

        Args:
            probabilities: Optional custom control probabilities.
                          If None, uses research-derived defaults.

        """
        self.probabilities = probabilities or ControlProbabilities()

    def generate(
        self,
        maturity: SecurityMaturityLevel | str = SecurityMaturityLevel.DEFINED,
        industry: str = "general",
        environment: str = "prod",
        size: str = "mid",
    ) -> SecurityControlsConfig:
        """Generate security controls configuration.

        Args:
            maturity: Security maturity level
            industry: Industry type (financial-services, healthcare, retail, etc.)
            environment: Environment type (dev, test, stage, prod)
            size: Organization size (small, mid, large)

        Returns:
            SecurityControlsConfig with generated controls

        """
        if isinstance(maturity, str):
            maturity = SecurityMaturityLevel(maturity.lower())

        maturity_key = maturity.value

        # Industry modifiers (some industries have regulatory requirements)
        industry_modifiers = self._get_industry_modifiers(industry)

        # Environment modifiers (prod has more controls than dev)
        env_modifiers = self._get_environment_modifiers(environment)

        # Size modifiers (larger orgs have more resources)
        size_modifiers = self._get_size_modifiers(size)

        # Generate each control based on probability
        controls = {}

        # Network Controls
        controls["network_segmentation"] = self._should_have_control(
            self.probabilities.network_segmentation[maturity_key],
            industry_modifiers.get("network_segmentation", 1.0),
            env_modifiers.get("network_segmentation", 1.0),
            size_modifiers.get("network_segmentation", 1.0),
        )

        controls["firewall"] = self._should_have_control(
            self.probabilities.firewall[maturity_key],
            industry_modifiers.get("firewall", 1.0),
            env_modifiers.get("firewall", 1.0),
            size_modifiers.get("firewall", 1.0),
        )

        controls["waf"] = self._should_have_control(
            self.probabilities.waf[maturity_key],
            industry_modifiers.get("waf", 1.0),
            env_modifiers.get("waf", 1.0),
            size_modifiers.get("waf", 1.0),
        )

        controls["ids_ips"] = self._should_have_control(
            self.probabilities.ids_ips[maturity_key],
            industry_modifiers.get("ids_ips", 1.0),
            env_modifiers.get("ids_ips", 1.0),
            size_modifiers.get("ids_ips", 1.0),
        )

        # Endpoint Controls
        controls["edr_xdr"] = self._should_have_control(
            self.probabilities.edr_xdr[maturity_key],
            industry_modifiers.get("edr_xdr", 1.0),
            env_modifiers.get("edr_xdr", 1.0),
            size_modifiers.get("edr_xdr", 1.0),
        )

        controls["antivirus"] = self._should_have_control(
            self.probabilities.antivirus[maturity_key],
            industry_modifiers.get("antivirus", 1.0),
            env_modifiers.get("antivirus", 1.0),
            size_modifiers.get("antivirus", 1.0),
        )

        # Access Controls
        controls["mfa"] = self._should_have_control(
            self.probabilities.mfa[maturity_key],
            industry_modifiers.get("mfa", 1.0),
            env_modifiers.get("mfa", 1.0),
            size_modifiers.get("mfa", 1.0),
        )

        controls["privileged_access_mgmt"] = self._should_have_control(
            self.probabilities.privileged_access_mgmt[maturity_key],
            industry_modifiers.get("privileged_access_mgmt", 1.0),
            env_modifiers.get("privileged_access_mgmt", 1.0),
            size_modifiers.get("privileged_access_mgmt", 1.0),
        )

        # Security Operations
        controls["siem"] = self._should_have_control(
            self.probabilities.siem[maturity_key],
            industry_modifiers.get("siem", 1.0),
            env_modifiers.get("siem", 1.0),
            size_modifiers.get("siem", 1.0),
        )

        controls["soc_24x7"] = self._should_have_control(
            self.probabilities.soc_24x7[maturity_key],
            industry_modifiers.get("soc_24x7", 1.0),
            env_modifiers.get("soc_24x7", 1.0),
            size_modifiers.get("soc_24x7", 1.0),
        )

        controls["incident_response_plan"] = self._should_have_control(
            0.3 if maturity_key == "initial" else 0.9,  # Most orgs have some plan
            industry_modifiers.get("incident_response_plan", 1.0),
            env_modifiers.get("incident_response_plan", 1.0),
            1.0,
        )

        controls["security_training"] = self._should_have_control(
            0.2 if maturity_key == "initial" else 0.7,
            industry_modifiers.get("security_training", 1.0),
            1.0,
            1.0,
        )

        # Patch Management (select one based on probabilities)
        patch_cadence = self._select_patch_cadence(maturity_key)
        controls["patch_daily"] = patch_cadence == "daily"
        controls["patch_weekly"] = patch_cadence == "weekly"
        controls["patch_monthly"] = patch_cadence == "monthly"
        controls["patch_quarterly"] = patch_cadence == "quarterly"

        # Air-gapped (rare, usually only for critical infrastructure)
        controls["air_gapped"] = self._should_have_control(
            0.01 if industry not in ("critical-infrastructure", "defense") else 0.2,
            1.0,
            1.0,
            1.0,
        )

        return SecurityControlsConfig(**controls)

    def _should_have_control(
        self,
        base_prob: float,
        industry_mod: float,
        env_mod: float,
        size_mod: float,
    ) -> bool:
        """Determine if a control should be present based on probability."""
        adjusted_prob = min(0.99, base_prob * industry_mod * env_mod * size_mod)
        return random.random() < adjusted_prob

    def _select_patch_cadence(self, maturity_key: str) -> str:
        """Select patch management cadence based on maturity."""
        probs = {
            "daily": self.probabilities.patch_daily[maturity_key],
            "weekly": self.probabilities.patch_weekly[maturity_key],
            "monthly": self.probabilities.patch_monthly[maturity_key],
            "quarterly": self.probabilities.patch_quarterly[maturity_key],
        }

        # Normalize probabilities
        total = sum(probs.values())
        normalized = {k: v / total for k, v in probs.items()}

        # Random selection
        r = random.random()
        cumulative = 0.0
        for cadence, prob in normalized.items():
            cumulative += prob
            if r < cumulative:
                return cadence

        return "monthly"  # Default fallback

    def _get_industry_modifiers(self, industry: str) -> dict[str, float]:
        """Get industry-specific probability modifiers."""
        modifiers = {
            "financial-services": {
                "network_segmentation": 1.3,
                "mfa": 1.5,
                "siem": 1.3,
                "privileged_access_mgmt": 1.4,
                "edr_xdr": 1.3,
                "waf": 1.2,
                "incident_response_plan": 1.2,
            },
            "healthcare": {
                "network_segmentation": 1.2,
                "mfa": 1.3,
                "siem": 1.2,
                "incident_response_plan": 1.3,
            },
            "retail": {
                "waf": 1.3,
                "ids_ips": 1.2,
            },
            "on-line-store": {
                "waf": 1.4,
                "ids_ips": 1.2,
                "mfa": 1.1,
            },
            "consulting": {
                "mfa": 1.2,
                "security_training": 1.2,
            },
            "critical-infrastructure": {
                "network_segmentation": 1.5,
                "ids_ips": 1.4,
                "siem": 1.4,
                "soc_24x7": 1.5,
            },
        }
        return modifiers.get(industry, {})

    def _get_environment_modifiers(self, environment: str) -> dict[str, float]:
        """Get environment-specific probability modifiers."""
        modifiers = {
            "prod": {
                "network_segmentation": 1.3,
                "waf": 1.2,
                "ids_ips": 1.2,
                "edr_xdr": 1.2,
                "siem": 1.2,
            },
            "stage": {
                "network_segmentation": 1.1,
                "waf": 0.8,
            },
            "qa": {
                "network_segmentation": 0.7,
                "waf": 0.5,
                "siem": 0.5,
            },
            "dev": {
                "network_segmentation": 0.5,
                "waf": 0.3,
                "ids_ips": 0.5,
                "siem": 0.3,
                "soc_24x7": 0.2,
            },
            "test": {
                "network_segmentation": 0.5,
                "waf": 0.3,
                "siem": 0.3,
            },
        }
        return modifiers.get(environment, {})

    def _get_size_modifiers(self, size: str) -> dict[str, float]:
        """Get organization size probability modifiers."""
        modifiers = {
            "small": {
                "siem": 0.5,
                "soc_24x7": 0.2,
                "privileged_access_mgmt": 0.5,
                "edr_xdr": 0.6,
            },
            "mid": {
                "siem": 0.8,
                "soc_24x7": 0.5,
            },
            "large": {
                "siem": 1.2,
                "soc_24x7": 1.3,
                "privileged_access_mgmt": 1.2,
                "edr_xdr": 1.2,
            },
        }
        return modifiers.get(size, {})


class ExposureBasedControlProbabilities:
    """Control probabilities adjusted by exposure type.

    Rationale:
    - Internet-facing: Maximum protection required (WAF mandatory, strong perimeter)
    - DMZ: High protection (buffer zone, most controls active)
    - Internal: Variable protection (often under-protected, basic controls)
    - Restricted: High protection (sensitive data, strict access)
    """

    # Probability multipliers by exposure type
    # Values > 1.0 increase probability, < 1.0 decrease
    EXPOSURE_MODIFIERS: dict[str, dict[str, float]] = {
        "internet-facing": {
            "firewall": 1.0,  # Always (base prob already high)
            "waf": 2.5,  # WAF is critical for internet-facing
            "ids_ips": 1.5,  # Strong perimeter monitoring
            "network_segmentation": 1.3,  # Isolate from internal
            "mfa": 1.5,  # Mandatory for external access
            "edr_xdr": 1.3,  # Enhanced endpoint protection
            "antivirus": 1.0,  # Always
            "privileged_access_mgmt": 1.2,  # Control admin access
            "siem": 1.3,  # Monitor external threats
            "soc_24x7": 1.2,  # 24/7 monitoring for external
        },
        "dmz": {
            "firewall": 1.0,  # Always
            "waf": 2.0,  # Likely for web services in DMZ
            "ids_ips": 1.4,  # Strong monitoring
            "network_segmentation": 1.5,  # DMZ is segmentation by definition
            "mfa": 1.3,  # Required for DMZ access
            "edr_xdr": 1.2,  # Enhanced protection
            "antivirus": 1.0,  # Always
            "privileged_access_mgmt": 1.1,  # Control access
            "siem": 1.2,  # Monitor DMZ activity
            "soc_24x7": 1.0,  # Normal monitoring
        },
        "internal": {
            "firewall": 0.9,  # Usually present but may be relaxed
            "waf": 0.3,  # Rarely needed for internal services
            "ids_ips": 0.7,  # Often missing internally
            "network_segmentation": 0.8,  # Often flat internal networks
            "mfa": 0.7,  # Sometimes skipped internally
            "edr_xdr": 0.8,  # May be present
            "antivirus": 1.0,  # Always
            "privileged_access_mgmt": 0.6,  # Often missing
            "siem": 0.6,  # May not cover internal
            "soc_24x7": 0.5,  # Less focus on internal
        },
        "restricted": {
            "firewall": 1.0,  # Always
            "waf": 0.5,  # Only if web-based
            "ids_ips": 1.3,  # Enhanced monitoring
            "network_segmentation": 1.5,  # Strict isolation
            "mfa": 1.5,  # Mandatory
            "edr_xdr": 1.4,  # Enhanced protection
            "antivirus": 1.0,  # Always
            "privileged_access_mgmt": 1.5,  # Strict access control
            "siem": 1.3,  # Full monitoring
            "soc_24x7": 1.2,  # Enhanced monitoring
        },
    }

    # Minimum controls that MUST be present for each exposure type
    # These override probability-based selection
    MANDATORY_CONTROLS: dict[str, list[str]] = {
        "internet-facing": ["firewall", "waf", "antivirus"],
        "dmz": ["firewall", "antivirus", "network_segmentation"],
        "internal": ["firewall", "antivirus"],
        "restricted": ["firewall", "antivirus", "network_segmentation", "mfa"],
    }

    @classmethod
    def get_modifier(cls, exposure: str, control: str) -> float:
        """Get probability modifier for a control based on exposure."""
        exposure_lower = exposure.lower()
        if exposure_lower not in cls.EXPOSURE_MODIFIERS:
            return 1.0
        return cls.EXPOSURE_MODIFIERS[exposure_lower].get(control, 1.0)

    @classmethod
    def get_mandatory_controls(cls, exposure: str) -> list[str]:
        """Get list of mandatory controls for an exposure type."""
        exposure_lower = exposure.lower()
        return cls.MANDATORY_CONTROLS.get(exposure_lower, ["firewall", "antivirus"])


class ServiceSecurityControlsGenerator:
    """Generates security controls for individual services based on their exposure.

    This provides more realistic control distributions where:
    - Internet-facing services have WAF, strong MFA, enhanced monitoring
    - Internal services have basic controls only
    - Restricted services have strict access controls
    """

    def __init__(
        self,
        base_generator: SecurityControlsGenerator | None = None,
        base_maturity: SecurityMaturityLevel | str = SecurityMaturityLevel.DEFINED,
    ):
        """Initialize the service-level generator.

        Args:
            base_generator: Base generator for organization-wide controls
            base_maturity: Base security maturity level

        """
        self.base_generator = base_generator or SecurityControlsGenerator()
        if isinstance(base_maturity, str):
            base_maturity = SecurityMaturityLevel(base_maturity.lower())
        self.base_maturity = base_maturity

    def generate_for_service(
        self,
        exposure: str,
        service_role: str = "service",
        asset_value: str = "medium",
        industry: str = "general",
        environment: str = "prod",
        size: str = "mid",
    ) -> dict[str, bool]:
        """Generate security controls for a specific service.

        Args:
            exposure: Service exposure (internet-facing, dmz, internal, restricted)
            service_role: Role of the service (web_server, database, cache, etc.)
            asset_value: Value of the asset (critical, high, medium, low)
            industry: Industry type
            environment: Environment type (dev, test, prod)
            size: Organization size

        Returns:
            Dictionary of control name -> bool

        """
        maturity_key = self.base_maturity.value
        probabilities = self.base_generator.probabilities

        # Get base modifiers
        industry_mods = self.base_generator._get_industry_modifiers(industry)
        env_mods = self.base_generator._get_environment_modifiers(environment)
        size_mods = self.base_generator._get_size_modifiers(size)

        # Get exposure-based modifiers
        exposure_mods = {
            ctrl: ExposureBasedControlProbabilities.get_modifier(exposure, ctrl)
            for ctrl in [
                "firewall",
                "waf",
                "ids_ips",
                "network_segmentation",
                "mfa",
                "edr_xdr",
                "antivirus",
                "privileged_access_mgmt",
                "siem",
                "soc_24x7",
            ]
        }

        # Asset value modifiers (critical assets get more protection)
        asset_mods = self._get_asset_value_modifiers(asset_value)

        # Service role modifiers (databases get more access control, etc.)
        role_mods = self._get_service_role_modifiers(service_role)

        controls = {}

        # Generate each control
        control_configs = [
            ("network_segmentation", probabilities.network_segmentation),
            ("firewall", probabilities.firewall),
            ("waf", probabilities.waf),
            ("ids_ips", probabilities.ids_ips),
            ("edr_xdr", probabilities.edr_xdr),
            ("antivirus", probabilities.antivirus),
            ("mfa", probabilities.mfa),
            ("privileged_access_mgmt", probabilities.privileged_access_mgmt),
            ("siem", probabilities.siem),
            ("soc_24x7", probabilities.soc_24x7),
        ]

        for control_name, base_probs in control_configs:
            base_prob = base_probs[maturity_key]

            # Apply all modifiers
            adjusted_prob = base_prob
            adjusted_prob *= industry_mods.get(control_name, 1.0)
            adjusted_prob *= env_mods.get(control_name, 1.0)
            adjusted_prob *= size_mods.get(control_name, 1.0)
            adjusted_prob *= exposure_mods.get(control_name, 1.0)
            adjusted_prob *= asset_mods.get(control_name, 1.0)
            adjusted_prob *= role_mods.get(control_name, 1.0)

            # Cap at 99%
            adjusted_prob = min(0.99, adjusted_prob)

            controls[control_name] = random.random() < adjusted_prob

        # Apply mandatory controls for exposure type
        mandatory = ExposureBasedControlProbabilities.get_mandatory_controls(exposure)
        for ctrl in mandatory:
            if ctrl in controls:
                controls[ctrl] = True

        # Add other controls with fixed probabilities
        controls["incident_response_plan"] = random.random() < (
            0.3 if maturity_key == "initial" else 0.8
        )
        controls["security_training"] = random.random() < (
            0.2 if maturity_key == "initial" else 0.6
        )

        # Patch management
        patch_cadence = self.base_generator._select_patch_cadence(maturity_key)
        controls["patch_daily"] = patch_cadence == "daily"
        controls["patch_weekly"] = patch_cadence == "weekly"
        controls["patch_monthly"] = patch_cadence == "monthly"
        controls["patch_quarterly"] = patch_cadence == "quarterly"

        # Air-gapped (only for restricted + critical infrastructure)
        controls["air_gapped"] = (
            exposure == "restricted"
            and industry in ("critical-infrastructure", "defense")
            and random.random() < 0.3
        )

        return controls

    def _get_asset_value_modifiers(self, asset_value: str) -> dict[str, float]:
        """Get modifiers based on asset criticality."""
        modifiers = {
            "critical": {
                "network_segmentation": 1.5,
                "mfa": 1.5,
                "privileged_access_mgmt": 1.5,
                "edr_xdr": 1.4,
                "siem": 1.4,
                "soc_24x7": 1.3,
            },
            "high": {
                "network_segmentation": 1.3,
                "mfa": 1.3,
                "privileged_access_mgmt": 1.3,
                "edr_xdr": 1.2,
                "siem": 1.2,
            },
            "medium": {},  # No modification
            "low": {
                "siem": 0.7,
                "soc_24x7": 0.5,
                "privileged_access_mgmt": 0.7,
            },
        }
        return modifiers.get(asset_value, {})

    def _get_service_role_modifiers(self, service_role: str) -> dict[str, float]:
        """Get modifiers based on service role."""
        modifiers = {
            "database": {
                "network_segmentation": 1.3,
                "privileged_access_mgmt": 1.4,
                "mfa": 1.2,
            },
            "web_server": {
                "waf": 1.5,
                "ids_ips": 1.2,
            },
            "app_server": {
                "edr_xdr": 1.2,
            },
            "cache": {
                "network_segmentation": 1.1,
            },
            "secrets_management": {
                "network_segmentation": 1.5,
                "privileged_access_mgmt": 1.5,
                "mfa": 1.5,
                "siem": 1.3,
            },
            "load_balancer": {
                "waf": 1.3,
                "ids_ips": 1.2,
            },
        }
        return modifiers.get(service_role, {})


def estimate_maturity_from_posture(posture: dict[str, Any]) -> SecurityMaturityLevel:
    """Estimate security maturity level from existing security posture dict.

    This is used to convert legacy security_posture dicts to maturity levels.

    Args:
        posture: Legacy security_posture dictionary

    Returns:
        Estimated SecurityMaturityLevel

    """
    score = 0

    # Check various indicators
    if posture.get("network_segmentation"):
        score += 2
    if posture.get("mfa_enforced"):
        score += 2
    if posture.get("encryption_at_rest"):
        score += 1
    if posture.get("incident_response_plan"):
        score += 1
    if posture.get("security_training"):
        score += 1

    # Check patch management
    patch_mgmt = posture.get("patch_management", "monthly")
    if patch_mgmt == "daily":
        score += 3
    elif patch_mgmt == "weekly":
        score += 2
    elif patch_mgmt == "monthly":
        score += 1

    # Check compliance standards
    standards = posture.get("compliance_standards", [])
    score += len(standards)

    # Map score to maturity
    if score >= 10:
        return SecurityMaturityLevel.OPTIMIZING
    if score >= 7:
        return SecurityMaturityLevel.MANAGED
    if score >= 4:
        return SecurityMaturityLevel.DEFINED
    if score >= 2:
        return SecurityMaturityLevel.DEVELOPING
    return SecurityMaturityLevel.INITIAL
