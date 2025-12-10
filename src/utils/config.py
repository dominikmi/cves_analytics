"""Configuration management for CVEs Analytics."""

from pathlib import Path

# Try to import from pydantic-settings first (Pydantic v2)
try:
    from pydantic import Field
    from pydantic_settings import BaseSettings
except ImportError:
    # Fallback to pydantic v1
    from pydantic import BaseSettings, Field


class AppConfig(BaseSettings):
    """Application configuration settings."""

    # Paths
    grype_binary_path: str = Field(
        default="/opt/homebrew/bin/grype", description="Path to Grype binary"
    )
    data_path: str = Field(default="./data", description="Path to data directory")
    output_path: str = Field(default="./output", description="Path to output directory")

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")

    # Processing limits
    max_cve_files: int = Field(
        default=5000, description="Maximum number of CVE files to process"
    )

    # Docker scanning
    max_concurrent_scans: int = Field(
        default=5, description="Maximum concurrent Docker image scans"
    )

    # Pydantic v2 compatible config
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "allow"  # Allow extra fields


# Global configuration instance
config: AppConfig | None = None


def get_config() -> AppConfig:
    """
    Get the global configuration instance.

    Returns:
        AppConfig: Configuration instance
    """
    global config
    if config is None:
        config = AppConfig()
    return config


def initialize_config(config_path: Path | None = None) -> AppConfig:
    """
    Initialize configuration from file or environment.

    Args:
        config_path: Path to configuration file

    Returns:
        AppConfig: Initialized configuration
    """
    global config

    if config_path and config_path.exists():
        # Load from file if provided
        import yaml

        with open(config_path) as f:
            config_data = yaml.safe_load(f)
        config = AppConfig(**config_data)
    else:
        # Load from environment
        config = AppConfig()

    return config
