"""Configuration constants for scenario generation."""

from typing import Any

from pydantic import BaseModel, Field, model_validator


class ScenarioConfig(BaseModel):
    """Configuration for scenario generation."""

    # Network topology probabilities
    PROD_FLAT_NETWORK_PROB: float = Field(
        default=0.1, ge=0.0, le=1.0, description="10% chance prod is flat"
    )
    DEV_SEGMENTED_NETWORK_PROB: float = Field(
        default=0.2, ge=0.0, le=1.0, description="20% chance dev is segmented"
    )

    # Network policy misconfiguration probabilities
    APP_TIER_UNRESTRICTED_PROB: float = Field(default=0.15, ge=0.0, le=1.0)
    DB_EXPOSED_PROB: float = Field(default=0.1, ge=0.0, le=1.0)

    # Security posture scoring (legacy - kept for backward compatibility)
    BASE_SCORE_MID_SIZE: int = 1
    BASE_SCORE_GLOBAL_REACH: int = 3
    BASE_SCORE_FINANCIAL: int = 4
    BASE_SCORE_ONLINE_STORE: int = 2
    BASE_SCORE_DEV_TEST: int = -3
    BASE_SCORE_STAGE: int = -1

    # Patch management thresholds (legacy)
    PATCH_MONTHLY_THRESHOLD: int = 4
    PATCH_WEEKLY_THRESHOLD: int = 7

    # Incident response thresholds (legacy)
    INCIDENT_RESPONSE_THRESHOLD: int = 3
    ENCRYPTION_THRESHOLD: int = 4
    NETWORK_SEG_THRESHOLD: int = 2
    MFA_THRESHOLD: int = 5
    SECURITY_TRAINING_THRESHOLD: int = 3

    # CI/CD probability
    CICD_PROBABILITY: float = Field(default=0.5, ge=0.0, le=1.0)

    # Service generation parameters
    SERVICES_SMALL_SIZE: int = Field(default=3, ge=1)
    SERVICES_MID_SIZE: int = Field(default=6, ge=1)
    SERVICES_GLOBAL_MULTIPLIER: float = Field(default=1.5, ge=1.0)

    # Sidecar exporter probability
    SIDECAR_PROBABILITY: float = Field(default=0.8, ge=0.0, le=1.0)

    # Hardcoded secrets parameters
    SECRETS_PROBABILITY: float = Field(default=0.3, ge=0.0, le=1.0)
    SECRET_TYPES: list[str] = Field(default_factory=list)

    # Misconfigurations parameters
    MISCONFIG_PROBABILITY: float = Field(default=0.4, ge=0.0, le=1.0)
    MISCONFIG_TYPES: list[str] = Field(default_factory=list)

    # ==========================================================================
    # SECURITY MATURITY CONFIGURATION (NEW - for Bayesian risk assessment)
    # ==========================================================================

    # Security maturity level mapping based on organization characteristics
    # Maps (size, reach, industry, environment) to maturity level
    MATURITY_LEVEL_MAPPING: dict[str, dict[str, Any]] = Field(
        default_factory=lambda: {
            # Industry-based base maturity
            "industry": {
                "financial-services": "managed",
                "healthcare": "defined",
                "critical-infrastructure": "managed",
                "on-line-store": "developing",
                "consulting": "defined",
                "retail": "developing",
                "default": "developing",
            },
            # Size adjustments (can upgrade maturity)
            "size_upgrade": {
                "large": 1,  # +1 maturity level
                "mid": 0,  # no change
                "small": -1,  # -1 maturity level
            },
            # Reach adjustments
            "reach_upgrade": {
                "global": 1,  # Global reach usually means more mature
                "local": 0,
            },
            # Environment adjustments (dev/test have lower effective maturity)
            "environment_downgrade": {
                "prod": 0,
                "stage": -1,
                "qa": -1,
                "test": -2,
                "dev": -2,
            },
        },
    )

    @model_validator(mode="after")
    def set_default_lists(self) -> "ScenarioConfig":
        """Initialize default lists if empty."""
        if not self.SECRET_TYPES:
            self.SECRET_TYPES = [
                "api_key",
                "password",
                "database_url",
                "private_key",
                "token",
            ]

        if not self.MISCONFIG_TYPES:
            self.MISCONFIG_TYPES = [
                "exposed_port",
                "weak_permissions",
                "debug_mode_enabled",
                "default_credentials",
                "unencrypted_communication",
            ]
        return self

    def get_maturity_level(
        self,
        size: str,
        reach: str,
        industry: str,
        environment: str,
    ) -> str:
        """Calculate security maturity level based on organization characteristics.

        Args:
            size: Organization size (small, mid, large)
            reach: Geographic reach (local, global)
            industry: Industry type
            environment: Environment type (dev, test, qa, stage, prod)

        Returns:
            Maturity level string (initial, developing, defined, managed, optimizing)

        """
        maturity_levels = ["initial", "developing", "defined", "managed", "optimizing"]

        # Get base maturity from industry
        industry_mapping = self.MATURITY_LEVEL_MAPPING.get("industry", {})
        default_maturity = industry_mapping.get("default", "developing")
        base_maturity = industry_mapping.get(industry, default_maturity)

        # Get base index
        try:
            base_idx = maturity_levels.index(base_maturity)
        except ValueError:
            base_idx = 1  # Default to "developing"

        # Apply adjustments
        size_mapping = self.MATURITY_LEVEL_MAPPING.get("size_upgrade", {})
        reach_mapping = self.MATURITY_LEVEL_MAPPING.get("reach_upgrade", {})
        env_mapping = self.MATURITY_LEVEL_MAPPING.get("environment_downgrade", {})

        size_adj = size_mapping.get(size, 0)
        reach_adj = reach_mapping.get(reach, 0)
        env_adj = env_mapping.get(environment, 0)

        # Calculate final index
        final_idx = base_idx + size_adj + reach_adj + env_adj
        final_idx = max(0, min(len(maturity_levels) - 1, final_idx))

        return maturity_levels[final_idx]


# Global default configuration
DEFAULT_CONFIG = ScenarioConfig()
