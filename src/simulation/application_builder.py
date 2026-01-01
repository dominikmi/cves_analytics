"""Application builder for creating multi-component applications from templates.

This module instantiates application templates with actual Docker images from
the service catalog, creating realistic multi-component applications for
kill-chain analysis.
"""

import random
from typing import Any

from src.simulation.application_templates import (
    ApplicationComponent,
    ApplicationTemplate,
    ComponentRole,
    get_template_for_industry,
)
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class ApplicationBuilder:
    """Builds concrete application instances from templates."""

    def __init__(self, service_catalog: dict[str, Any]) -> None:
        """Initialize the application builder.

        Args:
            service_catalog: Service catalog from services.yaml

        """
        self.service_catalog = service_catalog

    def build_application(
        self,
        template: ApplicationTemplate,
        company_name: str,
        is_segmented: bool,
    ) -> dict[str, Any]:
        """Build a concrete application instance from a template.

        Args:
            template: ApplicationTemplate to instantiate
            company_name: Company name for the application
            is_segmented: Whether network is segmented

        Returns:
            Dictionary with application metadata and services

        """
        logger.info(f"Building application: {template.name}")

        services = []
        component_map = {}  # Map component names to service instances

        # Instantiate each component with actual Docker images
        for component in template.components:
            service = self._instantiate_component(
                component,
                is_segmented,
            )
            if service:
                services.append(service)
                component_map[component.name] = service

        # Add component dependencies to services
        for component in template.components:
            if component.name in component_map:
                service = component_map[component.name]
                service["depends_on"] = component.depends_on
                service["component_role"] = component.role.value

        application = {
            "name": template.name,
            "type": template.type.value,
            "description": template.description,
            "company_name": company_name,
            "services": services,
            "kill_chain_stages": template.kill_chain_stages,
            "data_flow": template.data_flow,
            "component_count": len(services),
        }

        logger.info(
            f"Built application with {len(services)} components: {[s['name'] for s in services]}",
        )

        return application

    def _instantiate_component(
        self,
        component: ApplicationComponent,
        is_segmented: bool,
    ) -> dict[str, Any] | None:
        """Instantiate a component with a concrete Docker image.

        Args:
            component: ApplicationComponent to instantiate
            is_segmented: Whether network is segmented

        Returns:
            Service dictionary or None if no matching service found

        """
        # Get services from catalog for this component's category
        category_services = self.service_catalog.get(component.service_category, [])

        if not category_services:
            logger.warning(
                f"No services found for category: {component.service_category}",
            )
            return None

        # Select a random service from the category
        if isinstance(category_services, list):
            service_def = random.choice(category_services)
        else:
            logger.warning(
                f"Invalid service category format: {component.service_category}",
            )
            return None

        # Create service instance
        service = {
            "name": component.name,
            "role": service_def.get("role", component.role.value),
            "image": random.choice(
                service_def.get(
                    "versions",
                    [service_def.get("image", "unknown")],
                ),
            ),
            "zone": self._get_zone(component.exposure, is_segmented),
            "exposure": component.exposure,
            "asset_value": component.asset_value,
            "required": component.required,
            "ownership": self._determine_ownership(component.role),
            "ip_address": self._generate_ip(),
            "port": random.randint(1024, 65535),
            "data_classification": self._get_data_classification(component.role),
            "misconfigurations": [],
            "hardcoded_secrets": [],
        }

        return service

    def _get_zone(self, exposure: str, is_segmented: bool) -> str:
        """Get network zone based on exposure and segmentation."""
        if not is_segmented:
            return "flat_network"

        if exposure == "internet-facing":
            return "dmz"
        elif exposure == "dmz":
            return "dmz"
        elif exposure == "internal":
            return random.choice(["app_tier", "data_tier", "internal"])
        elif exposure == "restricted":
            return "internal"
        else:
            return "internal"

    def _determine_ownership(self, role: ComponentRole) -> str:
        """Determine service ownership based on component role."""
        ownership_map = {
            ComponentRole.INGRESS: "CLOUDNET",
            ComponentRole.FRONTEND: "DEV",
            ComponentRole.BACKEND: "DEV",
            ComponentRole.DATABASE: "DBTEAM",
            ComponentRole.CACHE: "DBTEAM",
            ComponentRole.MESSAGING: "DEVOPS",
            ComponentRole.PAYMENT: "DEV",
            ComponentRole.AUTH: "SECURITY",
            ComponentRole.MONITORING: "DEVOPS",
            ComponentRole.CICD: "DEVOPS",
        }
        return ownership_map.get(role, "DEV")

    def _get_data_classification(self, role: ComponentRole) -> list[str]:
        """Get data classification based on component role."""
        classification_map = {
            ComponentRole.DATABASE: ["pii", "financial"],
            ComponentRole.PAYMENT: ["pci-dss", "financial"],
            ComponentRole.AUTH: ["credentials", "confidential"],
            ComponentRole.CACHE: ["session-data"],
            ComponentRole.MESSAGING: ["logs", "audit"],
        }
        return classification_map.get(role, [])

    def _generate_ip(self) -> str:
        """Generate a private IP address."""
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def build_application_for_scenario(
    industry: str,
    company_name: str,
    is_segmented: bool,
    service_catalog: dict[str, Any],
) -> dict[str, Any]:
    """Build an application for a scenario based on industry.

    Args:
        industry: Industry type (on-line-store, financial-services, etc.)
        company_name: Company name
        is_segmented: Whether network is segmented
        service_catalog: Service catalog from services.yaml

    Returns:
        Application dictionary with services and metadata

    """
    template = get_template_for_industry(industry)
    builder = ApplicationBuilder(service_catalog)
    return builder.build_application(template, company_name, is_segmented)
