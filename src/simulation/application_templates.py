"""Application templates for real-world multi-component applications."""

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field
from ruamel.yaml import YAML

from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class ApplicationType(StrEnum):
    """Types of real-world applications."""

    ECOMMERCE = "ecommerce"
    FINANCIAL_SERVICES = "financial_services"
    CONSULTING = "consulting"
    SAAS_PLATFORM = "saas_platform"
    CONTENT_MANAGEMENT = "content_management"
    DATA_ANALYTICS = "data_analytics"


class ComponentRole(StrEnum):
    """Roles of components within an application."""

    INGRESS = "ingress"
    FRONTEND = "frontend"
    BACKEND = "backend"
    DATABASE = "database"
    CACHE = "cache"
    MESSAGING = "messaging"
    PAYMENT = "payment"
    AUTH = "auth"
    MONITORING = "monitoring"
    CICD = "cicd"


class ApplicationComponent(BaseModel):
    """A single component within an application."""

    name: str
    role: ComponentRole
    service_category: str
    exposure: str = "internal"
    asset_value: str = "medium"
    required: bool = True
    depends_on: list[str] = Field(default_factory=list)


class ApplicationTemplate(BaseModel):
    """Template for a complete multi-component application."""

    name: str
    type: ApplicationType
    description: str
    components: list[ApplicationComponent]
    kill_chain_stages: dict[str, list[str]] = Field(default_factory=dict)
    data_flow: list[tuple[str, str]] = Field(default_factory=list)


def _load_application_templates(
    config_path: str = "config/services.yaml",
) -> dict[str, ApplicationTemplate]:
    """Load application templates from YAML configuration."""
    config_file = Path(config_path)

    if not config_file.exists():
        current_dir = Path(__file__).parent.parent.parent
        config_file = current_dir / config_path
        if not config_file.exists():
            logger.warning("Config file not found at %s", config_path)
            return {}

    try:
        yaml = YAML(typ="safe")
        with open(config_file) as f:
            config = yaml.load(f) or {}

        applications_config = config.get("applications", {})
        if not applications_config:
            logger.warning("No applications section found in config")
            return {}

        templates = {}
        for app_key, app_data in applications_config.items():
            try:
                components = []
                for comp_data in app_data.get("components", []):
                    component = ApplicationComponent(
                        name=comp_data["name"],
                        role=ComponentRole(comp_data["role"]),
                        service_category=comp_data["service_category"],
                        exposure=comp_data.get("exposure", "internal"),
                        asset_value=comp_data.get("asset_value", "medium"),
                        required=comp_data.get("required", True),
                        depends_on=comp_data.get("depends_on", []),
                    )
                    components.append(component)

                kill_chain_stages = app_data.get("kill_chain_stages", {})
                data_flow = [tuple(flow) for flow in app_data.get("data_flow", [])]

                template = ApplicationTemplate(
                    name=app_data["name"],
                    type=ApplicationType(app_data["type"]),
                    description=app_data["description"],
                    components=components,
                    kill_chain_stages=kill_chain_stages,
                    data_flow=data_flow,
                )
                templates[app_key] = template

            except Exception:
                logger.exception("Failed to parse application template '%s'", app_key)
                continue

        logger.info(
            "Loaded %d application templates from %s", len(templates), config_file
        )
        return templates

    except Exception:
        logger.exception("Error loading application templates")
        return {}


_APPLICATION_TEMPLATES_CACHE: dict[str, ApplicationTemplate] | None = None


def _get_templates() -> dict[str, ApplicationTemplate]:
    """Get application templates, loading from YAML if not cached."""
    global _APPLICATION_TEMPLATES_CACHE
    if _APPLICATION_TEMPLATES_CACHE is None:
        _APPLICATION_TEMPLATES_CACHE = _load_application_templates()
    return _APPLICATION_TEMPLATES_CACHE


def _get_ecommerce_template() -> ApplicationTemplate:
    templates = _get_templates()
    return templates.get(
        "ecommerce",
        ApplicationTemplate(
            name="E-Commerce Platform",
            type=ApplicationType.ECOMMERCE,
            description="Online store with product catalog, shopping cart, and payment processing",
            components=[],
        ),
    )


ECOMMERCE_APP = _get_ecommerce_template()


def _get_financial_services_template() -> ApplicationTemplate:
    templates = _get_templates()
    return templates.get(
        "financial_services",
        ApplicationTemplate(
            name="Financial Services Platform",
            type=ApplicationType.FINANCIAL_SERVICES,
            description="Banking/trading platform with high security requirements",
            components=[],
        ),
    )


FINANCIAL_SERVICES_APP = _get_financial_services_template()


def _get_consulting_template() -> ApplicationTemplate:
    templates = _get_templates()
    return templates.get(
        "consulting",
        ApplicationTemplate(
            name="Consulting Services Platform",
            type=ApplicationType.CONSULTING,
            description="Project management and collaboration platform",
            components=[],
        ),
    )


CONSULTING_APP = _get_consulting_template()


def _get_saas_platform_template() -> ApplicationTemplate:
    templates = _get_templates()
    return templates.get(
        "saas_platform",
        ApplicationTemplate(
            name="SaaS Platform",
            type=ApplicationType.SAAS_PLATFORM,
            description="Multi-tenant SaaS application with microservices",
            components=[],
        ),
    )


SAAS_PLATFORM_APP = _get_saas_platform_template()


def _get_data_analytics_template() -> ApplicationTemplate:
    templates = _get_templates()
    return templates.get(
        "data_analytics",
        ApplicationTemplate(
            name="Data Analytics Platform",
            type=ApplicationType.DATA_ANALYTICS,
            description="Big data processing and analytics platform",
            components=[],
        ),
    )


DATA_ANALYTICS_APP = _get_data_analytics_template()


def get_application_templates() -> dict[ApplicationType, ApplicationTemplate]:
    """Get all application templates."""
    templates = _get_templates()
    return {
        ApplicationType.ECOMMERCE: templates.get("ecommerce", ECOMMERCE_APP),
        ApplicationType.FINANCIAL_SERVICES: templates.get(
            "financial_services", FINANCIAL_SERVICES_APP
        ),
        ApplicationType.CONSULTING: templates.get("consulting", CONSULTING_APP),
        ApplicationType.SAAS_PLATFORM: templates.get(
            "saas_platform", SAAS_PLATFORM_APP
        ),
        ApplicationType.DATA_ANALYTICS: templates.get(
            "data_analytics", DATA_ANALYTICS_APP
        ),
    }


APPLICATION_TEMPLATES = get_application_templates()


def get_template_for_industry(industry: str) -> ApplicationTemplate:
    """Get appropriate application template based on industry."""
    try:
        yaml = YAML(typ="safe")
        config_file = Path("config/services.yaml")
        if not config_file.exists():
            config_file = Path(__file__).parent.parent.parent / "config/services.yaml"

        with open(config_file) as f:
            config = yaml.load(f) or {}

        industry_mapping_yaml = config.get("industry_mapping", {})
        if industry_mapping_yaml and industry in industry_mapping_yaml:
            app_key = industry_mapping_yaml[industry]
            templates = _get_templates()
            if app_key in templates:
                return templates[app_key]
    except Exception as e:
        logger.debug("Could not load industry mapping from YAML: %s", e)

    industry_mapping = {
        "on-line-store": ApplicationType.ECOMMERCE,
        "financial-services": ApplicationType.FINANCIAL_SERVICES,
        "consulting": ApplicationType.CONSULTING,
        "saas": ApplicationType.SAAS_PLATFORM,
        "data-analytics": ApplicationType.DATA_ANALYTICS,
    }

    app_type = industry_mapping.get(industry, ApplicationType.CONSULTING)
    return get_application_templates()[app_type]


def get_all_templates() -> list[ApplicationTemplate]:
    """Get all available application templates."""
    return list(get_application_templates().values())
