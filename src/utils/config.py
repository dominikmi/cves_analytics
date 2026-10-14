"""Application configuration using pydantic-settings."""

from pathlib import Path

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

# Rendered from .env by `make config` (scripts/render_config.py).
CONFIG_YAML = Path("config.yaml")


class Settings(BaseSettings):
    """Application settings.

    Sources in precedence order: init kwargs, ``CVE_*`` environment
    variables, ``.env``, ``config.yaml``, field defaults.
    """

    app_name: str = "cves-analytics"
    debug: bool = False
    data_dir: str = "data"
    upload_dir: str = "uploads"
    db_path: str = "analytics.db"
    duckdb_path: str = "db/findings.duckdb"
    log_level: str = "INFO"
    github_cve_url: str = (
        "https://api.github.com/repos/CVEProject/cvelistV5/contents/cves/"
    )
    github_max_cve_files: int = 10
    registry_host: str = "localhost:5000"
    # Reserved for upstream API auth (NVD, GitHub); unset by default.
    gh_token: str | None = None
    nvd_api_key: str | None = None

    model_config = SettingsConfigDict(
        env_prefix="CVE_", env_file=".env", extra="ignore"
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls, yaml_file=CONFIG_YAML),
            file_secret_settings,
        )


settings = Settings()


def get_config() -> Settings:
    """Return the application settings singleton."""
    return settings
