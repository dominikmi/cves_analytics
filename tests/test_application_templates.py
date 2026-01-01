"""Unit tests for application templates module."""

import pytest

from src.simulation.application_templates import (
    ApplicationComponent,
    ApplicationTemplate,
    ApplicationType,
    ComponentRole,
    _load_application_templates,
    get_all_templates,
    get_application_templates,
    get_template_for_industry,
)


class TestApplicationComponent:
    """Test ApplicationComponent model."""

    def test_create_component(self):
        """Test creating a valid component."""
        component = ApplicationComponent(
            name="test-component",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["other-component"],
        )

        assert component.name == "test-component"
        assert component.role == ComponentRole.BACKEND
        assert component.service_category == "app_server"
        assert component.exposure == "internal"
        assert component.asset_value == "high"
        assert component.required is True
        assert component.depends_on == ["other-component"]

    def test_component_defaults(self):
        """Test component with default values."""
        component = ApplicationComponent(
            name="minimal-component",
            role=ComponentRole.DATABASE,
            service_category="database",
        )

        assert component.exposure == "internal"
        assert component.asset_value == "medium"
        assert component.required is True
        assert component.depends_on == []


class TestApplicationTemplate:
    """Test ApplicationTemplate model."""

    def test_create_template(self):
        """Test creating a valid template."""
        components = [
            ApplicationComponent(
                name="frontend",
                role=ComponentRole.FRONTEND,
                service_category="web_server",
                exposure="internet-facing",
            ),
            ApplicationComponent(
                name="backend",
                role=ComponentRole.BACKEND,
                service_category="app_server",
                depends_on=["frontend"],
            ),
        ]

        template = ApplicationTemplate(
            name="Test App",
            type=ApplicationType.CONSULTING,
            description="Test application",
            components=components,
            kill_chain_stages={
                "initial_access": ["frontend"],
                "execution": ["backend"],
            },
            data_flow=[("frontend", "backend")],
        )

        assert template.name == "Test App"
        assert template.type == ApplicationType.CONSULTING
        assert len(template.components) == 2
        assert "initial_access" in template.kill_chain_stages
        assert len(template.data_flow) == 1


class TestLoadApplicationTemplates:
    """Test loading templates from YAML."""

    def test_load_templates_from_yaml(self):
        """Test loading templates from config file."""
        templates = _load_application_templates("config/services.yaml")

        assert isinstance(templates, dict)
        assert len(templates) > 0

        # Check expected templates exist
        assert "ecommerce" in templates
        assert "financial_services" in templates
        assert "consulting" in templates
        assert "saas_platform" in templates
        assert "data_analytics" in templates

    def test_ecommerce_template_structure(self):
        """Test ecommerce template has correct structure."""
        templates = _load_application_templates("config/services.yaml")
        ecommerce = templates.get("ecommerce")

        assert ecommerce is not None
        assert ecommerce.name == "E-Commerce Platform"
        assert ecommerce.type == ApplicationType.ECOMMERCE
        assert len(ecommerce.components) == 6

        # Check for expected components
        component_names = [c.name for c in ecommerce.components]
        assert "nginx-ingress" in component_names
        assert "web-frontend" in component_names
        assert "api-backend" in component_names
        assert "product-database" in component_names
        assert "session-cache" in component_names
        assert "payment-service" in component_names

        # Check kill-chain stages
        assert "initial_access" in ecommerce.kill_chain_stages
        assert "execution" in ecommerce.kill_chain_stages
        assert "lateral_movement" in ecommerce.kill_chain_stages
        assert "exfiltration" in ecommerce.kill_chain_stages

    def test_financial_services_template_structure(self):
        """Test financial services template has correct structure."""
        templates = _load_application_templates("config/services.yaml")
        financial = templates.get("financial_services")

        assert financial is not None
        assert financial.name == "Financial Services Platform"
        assert financial.type == ApplicationType.FINANCIAL_SERVICES
        assert len(financial.components) == 7

        # Check for critical components
        component_names = [c.name for c in financial.components]
        assert "load-balancer" in component_names
        assert "auth-service" in component_names
        assert "financial-database" in component_names

    def test_component_dependencies(self):
        """Test component dependencies are loaded correctly."""
        templates = _load_application_templates("config/services.yaml")
        ecommerce = templates.get("ecommerce")

        # Find api-backend component
        api_backend = next(
            (c for c in ecommerce.components if c.name == "api-backend"),
            None,
        )

        assert api_backend is not None
        assert "web-frontend" in api_backend.depends_on

    def test_component_roles(self):
        """Test component roles are parsed correctly."""
        templates = _load_application_templates("config/services.yaml")
        ecommerce = templates.get("ecommerce")

        roles = {c.role for c in ecommerce.components}
        assert ComponentRole.INGRESS in roles
        assert ComponentRole.FRONTEND in roles
        assert ComponentRole.BACKEND in roles
        assert ComponentRole.DATABASE in roles
        assert ComponentRole.CACHE in roles
        assert ComponentRole.PAYMENT in roles

    def test_exposure_levels(self):
        """Test exposure levels are set correctly."""
        templates = _load_application_templates("config/services.yaml")
        ecommerce = templates.get("ecommerce")

        # Check internet-facing components
        internet_facing = [
            c for c in ecommerce.components if c.exposure == "internet-facing"
        ]
        assert len(internet_facing) >= 2

        # Check internal components
        internal = [c for c in ecommerce.components if c.exposure == "internal"]
        assert len(internal) >= 3

    def test_asset_values(self):
        """Test asset values are set correctly."""
        templates = _load_application_templates("config/services.yaml")
        ecommerce = templates.get("ecommerce")

        # Check for critical assets
        critical = [c for c in ecommerce.components if c.asset_value == "critical"]
        assert len(critical) >= 2

        # Database and payment should be critical
        critical_names = [c.name for c in critical]
        assert "product-database" in critical_names
        assert "payment-service" in critical_names


class TestGetApplicationTemplates:
    """Test template retrieval functions."""

    def test_get_application_templates(self):
        """Test getting all templates as dictionary."""
        templates = get_application_templates()

        assert isinstance(templates, dict)
        assert ApplicationType.ECOMMERCE in templates
        assert ApplicationType.FINANCIAL_SERVICES in templates
        assert ApplicationType.CONSULTING in templates
        assert ApplicationType.SAAS_PLATFORM in templates
        assert ApplicationType.DATA_ANALYTICS in templates

    def test_get_all_templates(self):
        """Test getting all templates as list."""
        templates = get_all_templates()

        assert isinstance(templates, list)
        assert len(templates) == 5

        # Check all are ApplicationTemplate instances
        for template in templates:
            assert isinstance(template, ApplicationTemplate)

    def test_get_template_for_industry(self):
        """Test getting template by industry."""
        # Test valid industries
        ecommerce = get_template_for_industry("on-line-store")
        assert ecommerce.type == ApplicationType.ECOMMERCE

        financial = get_template_for_industry("financial-services")
        assert financial.type == ApplicationType.FINANCIAL_SERVICES

        consulting = get_template_for_industry("consulting")
        assert consulting.type == ApplicationType.CONSULTING

        saas = get_template_for_industry("saas")
        assert saas.type == ApplicationType.SAAS_PLATFORM

        analytics = get_template_for_industry("data-analytics")
        assert analytics.type == ApplicationType.DATA_ANALYTICS

    def test_get_template_for_unknown_industry(self):
        """Test fallback for unknown industry."""
        template = get_template_for_industry("unknown-industry")

        # Should fallback to consulting
        assert template.type == ApplicationType.CONSULTING


class TestDataFlows:
    """Test data flow definitions."""

    def test_data_flows_exist(self):
        """Test all templates have data flows defined."""
        templates = get_all_templates()

        for template in templates:
            assert len(template.data_flow) > 0

    def test_data_flow_components_exist(self):
        """Test data flow references valid components."""
        templates = _load_application_templates("config/services.yaml")

        for template in templates.values():
            component_names = {c.name for c in template.components}

            for source, dest in template.data_flow:
                assert source in component_names, f"Source {source} not in components"
                assert dest in component_names, f"Dest {dest} not in components"


class TestKillChainStages:
    """Test kill-chain stage definitions."""

    def test_all_stages_defined(self):
        """Test all templates have required kill-chain stages."""
        templates = get_all_templates()
        required_stages = [
            "initial_access",
            "execution",
            "lateral_movement",
            "exfiltration",
        ]

        for template in templates:
            for stage in required_stages:
                assert stage in template.kill_chain_stages, (
                    f"Template {template.name} missing stage {stage}"
                )

    def test_stage_roles_exist(self):
        """Test kill-chain stages reference valid component roles."""
        templates = _load_application_templates("config/services.yaml")

        for template in templates.values():
            component_roles = {c.role.value for c in template.components}

            for stage, roles in template.kill_chain_stages.items():
                for role in roles:
                    assert role in component_roles or role in [
                        "ingress",
                        "frontend",
                        "backend",
                        "database",
                        "cache",
                        "payment",
                        "auth",
                        "messaging",
                        "cicd",
                    ], f"Role {role} in stage {stage} not valid"


class TestTemplateValidation:
    """Test template validation and error handling."""

    def test_load_nonexistent_file(self):
        """Test loading from nonexistent file returns empty dict."""
        templates = _load_application_templates("nonexistent.yaml")
        assert templates == {}

    def test_required_components(self):
        """Test templates have required components marked correctly."""
        templates = _load_application_templates("config/services.yaml")

        for template in templates.values():
            required = [c for c in template.components if c.required]
            assert len(required) > 0, (
                f"Template {template.name} has no required components"
            )

    def test_component_uniqueness(self):
        """Test component names are unique within template."""
        templates = _load_application_templates("config/services.yaml")

        for template in templates.values():
            names = [c.name for c in template.components]
            assert len(names) == len(set(names)), (
                f"Template {template.name} has duplicate component names"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
