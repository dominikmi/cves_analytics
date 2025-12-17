"""Configuration management for CVEs Analytics."""

from pathlib import Path

# Import from pydantic-settings (Pydantic v2)
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """Application configuration settings."""

    # Pydantic v2 model_config (replaces deprecated class Config)
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="allow",
    )

    # Paths
    grype_binary_path: str = Field(
        default="/opt/homebrew/bin/grype",
        description="Path to Grype binary",
    )
    data_path: str = Field(default="./data", description="Path to data directory")
    output_path: str = Field(default="./output", description="Path to output directory")

    # Logging
    log_level: str = Field(default="INFO", description="Logging level")

    # Processing limits
    max_cve_files: int = Field(
        default=5000,
        description="Maximum number of CVE files to process",
    )

    # Docker scanning
    max_concurrent_scans: int = Field(
        default=5,
        description="Maximum concurrent Docker image scans",
    )


class ConfigManager:
    """Thread-safe configuration manager using singleton pattern.

    Avoids global state by encapsulating config in a class.
    """

    _instance: "ConfigManager | None" = None
    _config: AppConfig | None = None

    def __new__(cls) -> "ConfigManager":
        """Create singleton instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @property
    def config(self) -> AppConfig:
        """Get configuration, initializing if needed."""
        if self._config is None:
            self._config = AppConfig()
        return self._config

    def initialize(self, config_path: Path | None = None) -> AppConfig:
        """Initialize configuration from file or environment.

        Args:
            config_path: Path to configuration file

        Returns:
            AppConfig: Initialized configuration

        """
        if config_path and config_path.exists():
            from ruamel.yaml import YAML

            yaml = YAML(typ="safe")
            with open(config_path) as f:
                config_data = yaml.load(f)
            self._config = AppConfig(**config_data)
        else:
            self._config = AppConfig()

        return self._config

    def reset(self) -> None:
        """Reset configuration (useful for testing)."""
        self._config = None


# Module-level accessor functions for backward compatibility
def get_config() -> AppConfig:
    """Get the configuration instance.

    Returns:
        AppConfig: Configuration instance

    """
    return ConfigManager().config


def initialize_config(config_path: Path | None = None) -> AppConfig:
    """Initialize configuration from file or environment.

    Args:
        config_path: Path to configuration file

    Returns:
        AppConfig: Initialized configuration

    """
    return ConfigManager().initialize(config_path)
