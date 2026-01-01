"""Application templates for real-world multi-component applications.

This module defines realistic application architectures that group services
into cohesive applications, enabling kill-chain analysis across components.
"""

from enum import Enum

from pydantic import BaseModel, Field


class ApplicationType(str, Enum):
    """Types of real-world applications."""

    ECOMMERCE = "ecommerce"
    FINANCIAL_SERVICES = "financial_services"
    CONSULTING = "consulting"
    SAAS_PLATFORM = "saas_platform"
    CONTENT_MANAGEMENT = "content_management"
    DATA_ANALYTICS = "data_analytics"


class ComponentRole(str, Enum):
    """Roles of components within an application."""

    INGRESS = "ingress"  # Entry point (nginx, load balancer)
    FRONTEND = "frontend"  # Web server, UI
    BACKEND = "backend"  # API server, business logic
    DATABASE = "database"  # Data persistence
    CACHE = "cache"  # Redis, Memcached
    MESSAGING = "messaging"  # RabbitMQ, Kafka
    PAYMENT = "payment"  # Payment processing
    AUTH = "auth"  # Authentication/authorization
    MONITORING = "monitoring"  # Observability
    CICD = "cicd"  # CI/CD pipeline


class ApplicationComponent(BaseModel):
    """A single component within an application."""

    name: str
    role: ComponentRole
    service_category: str  # Maps to services.yaml categories
    exposure: str = "internal"  # internet-facing, dmz, internal, restricted
    asset_value: str = "medium"  # critical, high, medium, low
    required: bool = True  # Whether component is required for app to function
    depends_on: list[str] = Field(default_factory=list)  # Component dependencies


class ApplicationTemplate(BaseModel):
    """Template for a complete multi-component application."""

    name: str
    type: ApplicationType
    description: str
    components: list[ApplicationComponent]
    kill_chain_stages: dict[str, list[str]] = Field(
        default_factory=dict
    )  # Stage -> component roles
    data_flow: list[tuple[str, str]] = Field(
        default_factory=list
    )  # (source, destination) pairs


# =============================================================================
# REAL-WORLD APPLICATION TEMPLATES
# =============================================================================

ECOMMERCE_APP = ApplicationTemplate(
    name="E-Commerce Platform",
    type=ApplicationType.ECOMMERCE,
    description="Online store with product catalog, shopping cart, and payment processing",
    components=[
        ApplicationComponent(
            name="nginx-ingress",
            role=ComponentRole.INGRESS,
            service_category="proxy",
            exposure="internet-facing",
            asset_value="high",
            required=True,
        ),
        ApplicationComponent(
            name="web-frontend",
            role=ComponentRole.FRONTEND,
            service_category="web_server",
            exposure="internet-facing",
            asset_value="high",
            required=True,
            depends_on=["nginx-ingress"],
        ),
        ApplicationComponent(
            name="api-backend",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["web-frontend"],
        ),
        ApplicationComponent(
            name="product-database",
            role=ComponentRole.DATABASE,
            service_category="database",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["api-backend"],
        ),
        ApplicationComponent(
            name="session-cache",
            role=ComponentRole.CACHE,
            service_category="database",  # Redis in database category
            exposure="internal",
            asset_value="medium",
            required=False,
            depends_on=["api-backend"],
        ),
        ApplicationComponent(
            name="payment-service",
            role=ComponentRole.PAYMENT,
            service_category="payment_gateway",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["api-backend"],
        ),
    ],
    kill_chain_stages={
        "initial_access": ["ingress", "frontend"],
        "execution": ["frontend", "backend"],
        "lateral_movement": ["backend", "database", "cache", "payment"],
        "exfiltration": ["database", "payment"],
    },
    data_flow=[
        ("nginx-ingress", "web-frontend"),
        ("web-frontend", "api-backend"),
        ("api-backend", "product-database"),
        ("api-backend", "session-cache"),
        ("api-backend", "payment-service"),
    ],
)

FINANCIAL_SERVICES_APP = ApplicationTemplate(
    name="Financial Services Platform",
    type=ApplicationType.FINANCIAL_SERVICES,
    description="Banking/trading platform with high security requirements",
    components=[
        ApplicationComponent(
            name="load-balancer",
            role=ComponentRole.INGRESS,
            service_category="proxy",
            exposure="internet-facing",
            asset_value="high",
            required=True,
        ),
        ApplicationComponent(
            name="api-gateway",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="dmz",
            asset_value="high",
            required=True,
            depends_on=["load-balancer"],
        ),
        ApplicationComponent(
            name="auth-service",
            role=ComponentRole.AUTH,
            service_category="auth_service",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["api-gateway"],
        ),
        ApplicationComponent(
            name="transaction-processor",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["api-gateway", "auth-service"],
        ),
        ApplicationComponent(
            name="financial-database",
            role=ComponentRole.DATABASE,
            service_category="database",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["transaction-processor"],
        ),
        ApplicationComponent(
            name="reporting-service",
            role=ComponentRole.BACKEND,
            service_category="financial_reporting",
            exposure="internal",
            asset_value="high",
            required=False,
            depends_on=["financial-database"],
        ),
        ApplicationComponent(
            name="audit-log",
            role=ComponentRole.MESSAGING,
            service_category="messaging",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["transaction-processor"],
        ),
    ],
    kill_chain_stages={
        "initial_access": ["ingress"],
        "execution": ["backend"],
        "lateral_movement": ["auth", "backend", "database", "messaging"],
        "exfiltration": ["database", "messaging"],
    },
    data_flow=[
        ("load-balancer", "api-gateway"),
        ("api-gateway", "auth-service"),
        ("api-gateway", "transaction-processor"),
        ("transaction-processor", "financial-database"),
        ("transaction-processor", "audit-log"),
        ("financial-database", "reporting-service"),
    ],
)

CONSULTING_APP = ApplicationTemplate(
    name="Consulting Services Platform",
    type=ApplicationType.CONSULTING,
    description="Project management and collaboration platform",
    components=[
        ApplicationComponent(
            name="reverse-proxy",
            role=ComponentRole.INGRESS,
            service_category="proxy",
            exposure="internet-facing",
            asset_value="medium",
            required=True,
        ),
        ApplicationComponent(
            name="web-app",
            role=ComponentRole.FRONTEND,
            service_category="web_server",
            exposure="internet-facing",
            asset_value="medium",
            required=True,
            depends_on=["reverse-proxy"],
        ),
        ApplicationComponent(
            name="api-server",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["web-app"],
        ),
        ApplicationComponent(
            name="project-database",
            role=ComponentRole.DATABASE,
            service_category="database",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["api-server"],
        ),
        ApplicationComponent(
            name="message-queue",
            role=ComponentRole.MESSAGING,
            service_category="messaging",
            exposure="internal",
            asset_value="medium",
            required=False,
            depends_on=["api-server"],
        ),
        ApplicationComponent(
            name="ci-cd-pipeline",
            role=ComponentRole.CICD,
            service_category="cicd",
            exposure="internal",
            asset_value="high",
            required=False,
        ),
        ApplicationComponent(
            name="monitoring-stack",
            role=ComponentRole.MONITORING,
            service_category="monitoring",
            exposure="internal",
            asset_value="low",
            required=False,
        ),
    ],
    kill_chain_stages={
        "initial_access": ["ingress", "frontend"],
        "execution": ["frontend", "backend", "cicd"],
        "lateral_movement": ["backend", "database", "messaging", "cicd"],
        "exfiltration": ["database", "cicd"],
    },
    data_flow=[
        ("reverse-proxy", "web-app"),
        ("web-app", "api-server"),
        ("api-server", "project-database"),
        ("api-server", "message-queue"),
        ("ci-cd-pipeline", "api-server"),
    ],
)

SAAS_PLATFORM_APP = ApplicationTemplate(
    name="SaaS Platform",
    type=ApplicationType.SAAS_PLATFORM,
    description="Multi-tenant SaaS application with microservices",
    components=[
        ApplicationComponent(
            name="api-gateway",
            role=ComponentRole.INGRESS,
            service_category="proxy",
            exposure="internet-facing",
            asset_value="high",
            required=True,
        ),
        ApplicationComponent(
            name="auth-service",
            role=ComponentRole.AUTH,
            service_category="auth_service",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["api-gateway"],
        ),
        ApplicationComponent(
            name="user-service",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["auth-service"],
        ),
        ApplicationComponent(
            name="business-logic",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["user-service"],
        ),
        ApplicationComponent(
            name="primary-database",
            role=ComponentRole.DATABASE,
            service_category="database",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["user-service", "business-logic"],
        ),
        ApplicationComponent(
            name="cache-layer",
            role=ComponentRole.CACHE,
            service_category="database",
            exposure="internal",
            asset_value="medium",
            required=False,
            depends_on=["business-logic"],
        ),
        ApplicationComponent(
            name="event-bus",
            role=ComponentRole.MESSAGING,
            service_category="messaging",
            exposure="internal",
            asset_value="medium",
            required=True,
            depends_on=["business-logic"],
        ),
    ],
    kill_chain_stages={
        "initial_access": ["ingress"],
        "execution": ["auth", "backend"],
        "lateral_movement": ["backend", "database", "cache", "messaging"],
        "exfiltration": ["database"],
    },
    data_flow=[
        ("api-gateway", "auth-service"),
        ("auth-service", "user-service"),
        ("user-service", "business-logic"),
        ("business-logic", "primary-database"),
        ("business-logic", "cache-layer"),
        ("business-logic", "event-bus"),
    ],
)

DATA_ANALYTICS_APP = ApplicationTemplate(
    name="Data Analytics Platform",
    type=ApplicationType.DATA_ANALYTICS,
    description="Big data processing and analytics platform",
    components=[
        ApplicationComponent(
            name="web-interface",
            role=ComponentRole.FRONTEND,
            service_category="web_server",
            exposure="internet-facing",
            asset_value="medium",
            required=True,
        ),
        ApplicationComponent(
            name="api-backend",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["web-interface"],
        ),
        ApplicationComponent(
            name="data-warehouse",
            role=ComponentRole.DATABASE,
            service_category="data_processing",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["api-backend"],
        ),
        ApplicationComponent(
            name="processing-engine",
            role=ComponentRole.BACKEND,
            service_category="data_processing",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["data-warehouse"],
        ),
        ApplicationComponent(
            name="metadata-db",
            role=ComponentRole.DATABASE,
            service_category="database",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["api-backend"],
        ),
        ApplicationComponent(
            name="visualization",
            role=ComponentRole.FRONTEND,
            service_category="financial_reporting",
            exposure="internal",
            asset_value="medium",
            required=False,
            depends_on=["api-backend"],
        ),
    ],
    kill_chain_stages={
        "initial_access": ["frontend"],
        "execution": ["backend"],
        "lateral_movement": ["backend", "database"],
        "exfiltration": ["database"],
    },
    data_flow=[
        ("web-interface", "api-backend"),
        ("api-backend", "data-warehouse"),
        ("api-backend", "metadata-db"),
        ("data-warehouse", "processing-engine"),
        ("api-backend", "visualization"),
    ],
)

# Template registry
APPLICATION_TEMPLATES: dict[ApplicationType, ApplicationTemplate] = {
    ApplicationType.ECOMMERCE: ECOMMERCE_APP,
    ApplicationType.FINANCIAL_SERVICES: FINANCIAL_SERVICES_APP,
    ApplicationType.CONSULTING: CONSULTING_APP,
    ApplicationType.SAAS_PLATFORM: SAAS_PLATFORM_APP,
    ApplicationType.DATA_ANALYTICS: DATA_ANALYTICS_APP,
}


def get_template_for_industry(industry: str) -> ApplicationTemplate:
    """Get appropriate application template based on industry.

    Args:
        industry: Industry type (on-line-store, financial-services, consulting, etc.)

    Returns:
        ApplicationTemplate for the industry

    """
    industry_mapping = {
        "on-line-store": ApplicationType.ECOMMERCE,
        "financial-services": ApplicationType.FINANCIAL_SERVICES,
        "consulting": ApplicationType.CONSULTING,
        "saas": ApplicationType.SAAS_PLATFORM,
        "data-analytics": ApplicationType.DATA_ANALYTICS,
    }

    app_type = industry_mapping.get(industry, ApplicationType.CONSULTING)
    return APPLICATION_TEMPLATES[app_type]


def get_all_templates() -> list[ApplicationTemplate]:
    """Get all available application templates.

    Returns:
        List of all ApplicationTemplate instances

    """
    return list(APPLICATION_TEMPLATES.values())
