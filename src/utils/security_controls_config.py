"""Security Controls Configuration Loader.

Loads and validates security control parameters from YAML configuration.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class SecurityControlsConfig(BaseModel):
    """Security controls configuration with validation."""

    # Network controls
    network_controls: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Endpoint controls
    endpoint_controls: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Access controls
    access_controls: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Security operations
    security_operations: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Data protection
    data_protection: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Application security
    application_security: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Docker security
    docker_security: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Patch management
    patch_management: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Exposure context
    exposure_context: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # Threat indicators
    threat_indicators: dict[str, dict[str, Any]] = Field(default_factory=dict)

    # CVSS modifiers
    cvss_modifiers: dict[str, Any] = Field(default_factory=dict)

    # Conditional controls
    conditional_controls: dict[str, dict[str, float]] = Field(default_factory=dict)

    # Kill-chain controls
    kill_chain_controls: dict[str, dict[str, float]] = Field(default_factory=dict)

    # Temporal factors
    temporal_factors: dict[str, float] = Field(default_factory=dict)

    # Probability bounds
    probability_bounds: dict[str, float] = Field(default_factory=dict)

    # Control correlations
    control_correlations: dict[str, Any] = Field(default_factory=dict)

    # Control maturity levels
    control_maturity_levels: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "network_controls",
        "endpoint_controls",
        "access_controls",
        "security_operations",
        "data_protection",
        "application_security",
        "patch_management",
        "exposure_context",
        "threat_indicators",
        mode="before",
    )
    @classmethod
    def validate_control_structure(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate control structure has 'default' and 'description' keys."""
        for control_name, control_data in v.items():
            if not isinstance(control_data, dict):
                continue
            if "default" not in control_data:
                raise ValueError(f"Control '{control_name}' missing 'default' value")
        return v

    @field_validator("docker_security", mode="before")
    @classmethod
    def validate_docker_structure(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate Docker security structure (nested)."""
        # Docker security has nested structure, no validation needed
        return v

    def get_control_value(
        self, category: str, control_name: str, context: str | None = None
    ) -> float:
        """Get control value from configuration.

        Args:
            category: Control category (e.g., 'network_controls', 'endpoint_controls')
            control_name: Name of the control
            context: Optional context for conditional controls (e.g., 'internet_facing')

        Returns:
            Likelihood ratio value for the control

        Raises:
            ValueError: If control not found
        """
        # Check conditional controls first if context provided
        if context and control_name in self.conditional_controls:
            conditional_values = self.conditional_controls[control_name]
            if context in conditional_values:
                return conditional_values[context]

        # Get from category
        category_data = getattr(self, category, {})
        if control_name not in category_data:
            raise ValueError(
                f"Control '{control_name}' not found in category '{category}'"
            )

        control_data = category_data[control_name]

        # Handle nested structure (e.g., docker_security)
        if isinstance(control_data, dict) and "default" in control_data:
            return control_data["default"]

        raise ValueError(
            f"Invalid control structure for '{control_name}' in '{category}'"
        )

    def get_docker_control_value(
        self, practice_type: str, vulnerability_type: str
    ) -> float:
        """Get Docker security control value.

        Args:
            practice_type: 'good_practices' or 'poor_practices'
            vulnerability_type: Type of vulnerability (e.g., 'rce_protection', 'general_hardening')

        Returns:
            Likelihood ratio value
        """
        if practice_type not in self.docker_security:
            raise ValueError(f"Docker practice type '{practice_type}' not found")

        practices = self.docker_security[practice_type]
        if vulnerability_type not in practices:
            raise ValueError(
                f"Vulnerability type '{vulnerability_type}' not found in '{practice_type}'"
            )

        return practices[vulnerability_type]

    def get_exposure_value(self, exposure_type: str) -> float:
        """Get exposure context value.

        Args:
            exposure_type: Type of exposure (e.g., 'internet_facing', 'internal')

        Returns:
            Likelihood ratio value (>1.0 increases risk, <1.0 decreases risk)
        """
        if exposure_type not in self.exposure_context:
            raise ValueError(f"Exposure type '{exposure_type}' not found")

        return self.exposure_context[exposure_type]["default"]

    def get_threat_indicator_value(self, indicator: str) -> float:
        """Get threat indicator value.

        Args:
            indicator: Threat indicator (e.g., 'kev_listed', 'public_exploit')

        Returns:
            Likelihood ratio value (>1.0 increases risk)
        """
        if indicator not in self.threat_indicators:
            raise ValueError(f"Threat indicator '{indicator}' not found")

        return self.threat_indicators[indicator]["default"]

    def get_temporal_factor(self, factor_name: str) -> float:
        """Get temporal factor value.

        Args:
            factor_name: Temporal factor name (e.g., 'patch_0_7_days')

        Returns:
            Temporal adjustment factor
        """
        if factor_name not in self.temporal_factors:
            raise ValueError(f"Temporal factor '{factor_name}' not found")

        return self.temporal_factors[factor_name]

    def get_probability_bound(self, bound_name: str) -> float:
        """Get probability bound value.

        Args:
            bound_name: Bound name (e.g., 'max_probability', 'kev_floor')

        Returns:
            Probability bound value
        """
        if bound_name not in self.probability_bounds:
            raise ValueError(f"Probability bound '{bound_name}' not found")

        return self.probability_bounds[bound_name]

    def get_kill_chain_control_value(self, stage: str, control: str) -> float:
        """Get kill-chain stage specific control value.

        Args:
            stage: Kill-chain stage (e.g., 'initial_access', 'execution')
            control: Control name

        Returns:
            Likelihood ratio value for the stage
        """
        if stage not in self.kill_chain_controls:
            raise ValueError(f"Kill-chain stage '{stage}' not found")

        stage_controls = self.kill_chain_controls[stage]
        if control not in stage_controls:
            raise ValueError(f"Control '{control}' not found in stage '{stage}'")

        return stage_controls[control]


def load_security_controls_config(
    config_path: str | Path | None = None,
) -> SecurityControlsConfig:
    """Load security controls configuration from YAML file.

    Args:
        config_path: Path to security_controls.yaml file.
                    If None, uses default location: config/security_controls.yaml

    Returns:
        SecurityControlsConfig instance

    Raises:
        FileNotFoundError: If config file not found
        ValueError: If config file is invalid
    """
    logger = logging.getLogger(__name__)

    if config_path is None:
        # Default to config/security_controls.yaml relative to project root
        project_root = Path(__file__).parent.parent.parent
        config_path = project_root / "config" / "security_controls.yaml"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Security controls config not found: {config_path}")

    logger.info(f"Loading security controls config from: {config_path}")

    with open(config_path) as f:
        config_data = yaml.safe_load(f)

    if not config_data:
        raise ValueError(f"Empty or invalid YAML file: {config_path}")

    # Create and validate config
    config = SecurityControlsConfig(**config_data)

    logger.info(
        f"Loaded security controls config version {config.metadata.get('version', 'unknown')}"
    )

    return config


# Global config instance (lazy loaded)
_config: SecurityControlsConfig | None = None


def get_security_controls_config() -> SecurityControlsConfig:
    """Get global security controls configuration instance.

    Returns:
        SecurityControlsConfig instance (singleton)
    """
    global _config
    if _config is None:
        _config = load_security_controls_config()
    return _config
