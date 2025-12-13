"""Scenario generation module for simulating IT environments."""

import csv
import io
import random
import uuid
from pathlib import Path
from typing import Any

import yaml
from faker import Faker

from src.simulation.scenario_config import DEFAULT_CONFIG, ScenarioConfig
from src.simulation.security_controls import (
    SecurityControlsConfig,
    SecurityControlsGenerator,
    SecurityMaturityLevel,
)
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class ScenarioGenerator:
    """Generates realistic IT environment scenarios for simulation and testing."""

    def __init__(
        self,
        config_path: str = "config/services.yaml",
        scenario_config: ScenarioConfig | None = None,
    ):
        """Initialize the scenario generator.

        Args:
            config_path: Path to YAML configuration file
            scenario_config: Optional ScenarioConfig instance

        """
        self.fake = Faker()
        self.service_catalog = self._load_config(config_path)
        self.scenario_config = scenario_config or DEFAULT_CONFIG
        self.security_controls_generator = SecurityControlsGenerator()

    def _load_config(self, path: str) -> dict[str, Any]:
        """Load configuration from YAML file.

        Args:
            path: Path to YAML configuration file

        Returns:
            Dictionary with configuration data

        """
        config_path = Path(path)

        # Try relative to current directory first
        if not config_path.exists():
            # Try relative to this file location
            current_dir = Path(__file__).parent.parent.parent
            config_path = current_dir / path
            if not config_path.exists():
                logger.debug(f"Config file not found at {path}")
                return {}

        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            logger.info(f"Loaded service catalog from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {e}")
            return {}

    def generate_scenario(
        self,
        size: str,
        reach: str,
        industry: str,
        environment_type: str = "prod",
        output_format: str = "json",
    ) -> dict[str, Any] | str:
        """Generate a simulation scenario based on input criteria.

        Args:
            size: Organization size ('small' or 'mid')
            reach: Geographic reach ('local' or 'global')
            industry: Industry type ('on-line-store', 'consulting',
                'financial-services')
            environment_type: Environment type ('dev', 'test', 'qa',
                'stage', 'prod')
            output_format: Output format ('json' or 'csv')

        Returns:
            Dictionary or CSV string describing the generated environment

        """
        scenario_id = str(uuid.uuid4())
        company_name = self.fake.company().split()[0].replace(",", "").strip()

        # Determine network topology
        is_segmented = environment_type in ["stage", "prod"]

        # Simulate misconfigurations
        if (
            is_segmented
            and random.random() < self.scenario_config.PROD_FLAT_NETWORK_PROB
        ):
            is_segmented = False
        elif (
            not is_segmented
            and random.random() < self.scenario_config.DEV_SEGMENTED_NETWORK_PROB
        ):
            is_segmented = True

        network_zones = (
            ["dmz", "app_tier", "data_tier", "internal"]
            if is_segmented
            else ["flat_network"]
        )

        environment = {
            "scenario_id": scenario_id,
            "company_name": company_name,
            "metadata": {
                "size": size,
                "reach": reach,
                "industry": industry,
                "environment": environment_type,
                "topology": "segmented" if is_segmented else "flat",
            },
            "network_zones": network_zones,
            "services": [],
        }

        # Determine complexity
        complexity = 1
        if size == "mid":
            complexity += 1
        if reach == "global":
            complexity += 1

        if environment_type in ["dev", "test"]:
            complexity = max(1, complexity - 1)

        # Generate services
        services = self._design_architecture(
            industry,
            complexity,
            reach,
            environment_type,
            is_segmented,
        )

        # Add sidecars if monitoring present
        services = [s for s in services if s and s.get("role")]
        has_monitoring = any(s.get("role") == "monitoring" for s in services)
        if has_monitoring and environment_type in ["stage", "prod"]:
            services = self._add_sidecar_exporters(services)

        # Add CI/CD services
        is_dev_env = environment_type in ["dev", "qa", "test"]
        add_cicd = is_dev_env or random.random() < self.scenario_config.CICD_PROBABILITY
        if add_cicd:
            services = self._add_cicd_services(services, environment_type, is_segmented)

        environment["services"] = services
        environment["network_policies"] = self._generate_network_policies(
            services,
            is_segmented,
            environment_type,
        )

        # Generate security posture (legacy format for backward compatibility)
        environment["security_posture"] = self._generate_posture(
            size,
            reach,
            industry,
            environment_type,
        )

        # Generate security controls (new Bayesian risk assessment format)
        maturity_level = self.scenario_config.get_maturity_level(
            size,
            reach,
            industry,
            environment_type,
        )
        security_controls = self._generate_security_controls(
            maturity_level,
            industry,
            environment_type,
            size,
        )
        environment["security_controls"] = security_controls.to_dict()
        environment["security_maturity"] = maturity_level

        # Sync some controls with legacy security_posture for consistency
        posture = environment["security_posture"]
        posture["network_segmentation"] = security_controls.network_segmentation
        posture["mfa_enforced"] = security_controls.mfa
        posture["patch_management"] = security_controls.get_patch_cadence()

        if output_format == "csv":
            return self.export_to_csv(environment)

        return environment

    def export_to_csv(self, scenario: dict[str, Any]) -> str:
        """Flatten scenario JSON into CSV format.

        Args:
            scenario: Scenario dictionary

        Returns:
            CSV string representation

        """
        output = io.StringIO()
        writer = csv.writer(output)

        headers = [
            "scenario_id",
            "company_name",
            "size",
            "reach",
            "industry",
            "environment",
            "topology",
            "security_score_patching",
            "security_standards",
            "service_name",
            "service_role",
            "image",
            "version",
            "zone",
            "ip_address",
            "exposure",
            "asset_value",
            "data_classification",
            "misconfigurations",
            "hardcoded_secrets",
        ]
        writer.writerow(headers)

        meta = scenario.get("metadata", {})
        posture = scenario.get("security_posture", {})

        base_row = [
            scenario.get("scenario_id"),
            scenario.get("company_name"),
            meta.get("size"),
            meta.get("reach"),
            meta.get("industry"),
            meta.get("environment"),
            meta.get("topology"),
            posture.get("patch_management"),
            ";".join(posture.get("compliance_standards", [])),
        ]

        for service in scenario.get("services", []):
            misconfigs = "; ".join(
                [
                    f"{m['key']}={m['value']}"
                    for m in service.get("misconfigurations", [])
                ],
            )
            secrets = "; ".join(
                [s["type"] for s in service.get("hardcoded_secrets", [])],
            )
            data_class = "; ".join(service.get("data_classification", []))

            row = base_row + [
                service.get("name"),
                service.get("role"),
                service.get("image"),
                service.get("image"),
                service.get("zone"),
                service.get("ip_address"),
                service.get("exposure"),
                service.get("asset_value"),
                data_class,
                misconfigs,
                secrets,
            ]
            writer.writerow(row)

        return output.getvalue()

    def _generate_network_policies(
        self,
        services: list[dict[str, Any]],
        is_segmented: bool,
        environment_type: str,
    ) -> list[dict[str, Any]]:
        """Generate network communication policies.

        Args:
            services: List of services
            is_segmented: Whether network is segmented
            environment_type: Environment type

        Returns:
            List of network policies

        """
        policies = []

        if not is_segmented:
            policies.append(
                {
                    "source": "*",
                    "destination": "*",
                    "port": "*",
                    "action": "allow",
                    "description": "Flat network allows all traffic by default",
                },
            )
            return policies

        # Segmented network policies
        policies.append(
            {
                "source": "internet",
                "destination": "dmz",
                "port": "443, 80",
                "action": "allow",
                "description": "Public ingress",
            },
        )

        policies.append(
            {
                "source": "dmz",
                "destination": "app_tier",
                "port": "8080, 8443",
                "action": "allow",
                "description": "Frontend to Backend communication",
            },
        )

        policies.append(
            {
                "source": "app_tier",
                "destination": "data_tier",
                "port": "5432, 3306, 6379",
                "action": "allow",
                "description": "Backend to Database/Cache communication",
            },
        )

        # Bastion access
        if any(s.get("role") == "bastion" for s in services):
            policies.append(
                {
                    "source": "bastion-host",
                    "destination": "*",
                    "port": "22, 3389",
                    "action": "allow",
                    "description": "Bastion administrative access",
                },
            )

        # Monitoring
        if any(s.get("role") == "monitoring" for s in services):
            policies.append(
                {
                    "source": "internal",
                    "destination": "*",
                    "port": "9090, 9100, 9323",
                    "action": "allow",
                    "description": "Prometheus scraping",
                },
            )

        # Misconfigurations
        if random.random() < self.scenario_config.APP_TIER_UNRESTRICTED_PROB:
            policies.append(
                {
                    "source": "app_tier",
                    "destination": "*",
                    "port": "*",
                    "action": "allow",
                    "description": "MISCONFIGURATION: App tier unrestricted",
                },
            )

        if random.random() < self.scenario_config.DB_EXPOSED_PROB:
            policies.append(
                {
                    "source": "*",
                    "destination": "data_tier",
                    "port": "5432",
                    "action": "allow",
                    "description": "MISCONFIGURATION: Database exposed",
                },
            )

        return policies

    def _generate_security_controls(
        self,
        maturity_level: str,
        industry: str,
        environment_type: str,
        size: str,
    ) -> SecurityControlsConfig:
        """Generate security controls configuration based on maturity level.

        Args:
            maturity_level: Security maturity level (initial, developing, etc.)
            industry: Industry type
            environment_type: Environment type (dev, test, prod, etc.)
            size: Organization size

        Returns:
            SecurityControlsConfig with generated controls

        """
        try:
            maturity = SecurityMaturityLevel(maturity_level)
        except ValueError:
            maturity = SecurityMaturityLevel.DEVELOPING

        return self.security_controls_generator.generate(
            maturity=maturity,
            industry=industry,
            environment=environment_type,
            size=size,
        )

    def _generate_posture(
        self,
        size: str,
        reach: str,
        industry: str,
        environment_type: str,
    ) -> dict[str, Any]:
        """Generate security posture profile.

        Args:
            size: Organization size
            reach: Geographic reach
            industry: Industry type
            environment_type: Environment type

        Returns:
            Security posture dictionary

        """
        base_score = 0
        if size == "mid":
            base_score += self.scenario_config.BASE_SCORE_MID_SIZE
        if reach == "global":
            base_score += self.scenario_config.BASE_SCORE_GLOBAL_REACH

        if industry == "financial-services":
            base_score += self.scenario_config.BASE_SCORE_FINANCIAL
        elif industry == "on-line-store":
            base_score += self.scenario_config.BASE_SCORE_ONLINE_STORE

        if environment_type in ["dev", "test"]:
            base_score += self.scenario_config.BASE_SCORE_DEV_TEST
        elif environment_type == "stage":
            base_score += self.scenario_config.BASE_SCORE_STAGE

        score = max(0, base_score + random.randint(-1, 2))

        posture = {
            "patch_management": (
                "monthly"
                if score < self.scenario_config.PATCH_MONTHLY_THRESHOLD
                else (
                    "weekly"
                    if score < self.scenario_config.PATCH_WEEKLY_THRESHOLD
                    else "daily"
                )
            ),
            "incident_response_plan": (
                score > self.scenario_config.INCIDENT_RESPONSE_THRESHOLD
            ),
            "encryption_at_rest": score > self.scenario_config.ENCRYPTION_THRESHOLD,
            "network_segmentation": (
                score > self.scenario_config.NETWORK_SEG_THRESHOLD
            ),
            "mfa_enforced": score > self.scenario_config.MFA_THRESHOLD,
            "security_training": (
                score > self.scenario_config.SECURITY_TRAINING_THRESHOLD
            ),
            "compliance_standards": [],
        }

        if environment_type == "prod":
            if industry == "financial-services":
                posture["compliance_standards"].extend(["PCI-DSS", "SOC2"])
                posture["encryption_at_rest"] = True
                posture["mfa_enforced"] = True

            if reach == "global":
                posture["compliance_standards"].append("GDPR")
        else:
            posture["encryption_at_rest"] = False
            posture["mfa_enforced"] = False

        return posture

    def _design_architecture(
        self,
        industry: str,
        complexity: int,
        reach: str,
        environment_type: str,
        is_segmented: bool,
    ) -> list[dict[str, Any]]:
        """Design architecture based on industry and complexity using service catalog.

        Args:
            industry: Industry type
            complexity: Complexity level
            reach: Geographic reach
            environment_type: Environment type
            is_segmented: Whether network is segmented

        Returns:
            List of services

        """
        services = []

        # Map industry to service categories
        industry_services = {
            "on-line-store": [
                "proxy",
                "web_server",
                "app_server",
                "database",
                "payment_gateway",
                "messaging",
            ],
            "financial-services": [
                "proxy",
                "web_server",
                "app_server",
                "database",
                "security",
                "monitoring",
                "financial_reporting",
            ],
            "consulting": [
                "proxy",
                "web_server",
                "app_server",
                "database",
                "messaging",
                "cicd",
                "monitoring",
            ],
        }

        # Get services for this industry
        service_categories = industry_services.get(
            industry,
            ["proxy", "web_server", "app_server", "database"],
        )

        # Add complexity-based services
        if complexity >= 2:
            service_categories.extend(["monitoring", "network_infra"])
        if complexity >= 3:
            service_categories.extend(["data_processing", "cicd"])

        # Select services from catalog
        for category in service_categories:
            if category not in self.service_catalog:
                continue

            category_services = self.service_catalog[category]
            if not isinstance(category_services, list):
                continue

            # Select random services from category based on complexity
            num_services = min(complexity, len(category_services))
            selected = random.sample(category_services, num_services)

            for service_def in selected:
                # Create service instance
                service = {
                    "name": service_def.get("name", "unknown"),
                    "role": service_def.get("role", "service"),
                    "image": random.choice(
                        service_def.get(
                            "versions",
                            [service_def.get("image", "unknown")],
                        ),
                    ),
                    "zone": self._get_zone(
                        service_def.get("exposure", "internal"),
                        is_segmented,
                    ),
                    "exposure": service_def.get("exposure", "internal"),
                    "asset_value": self._calculate_asset_value(
                        service_def.get("role", "service"),
                        industry,
                    ),
                    "ownership": self._determine_ownership(
                        service_def.get("role", "service"),
                        industry,
                    ),
                    "ip_address": self.fake.ipv4_private(),
                    "port": random.randint(1024, 65535),
                    "data_classification": self._get_data_classification(
                        service_def.get("role", "service"),
                    ),
                }

                # Add misconfigurations
                if random.random() < self.scenario_config.MISCONFIG_PROBABILITY:
                    service["misconfigurations"] = [
                        {
                            "key": random.choice(self.scenario_config.MISCONFIG_TYPES),
                            "value": self.fake.word(),
                        },
                    ]
                else:
                    service["misconfigurations"] = []

                # Add hardcoded secrets
                if random.random() < self.scenario_config.SECRETS_PROBABILITY:
                    service["hardcoded_secrets"] = [
                        {
                            "type": random.choice(self.scenario_config.SECRET_TYPES),
                            "location": f"/app/{self.fake.word()}.py",
                        },
                    ]
                else:
                    service["hardcoded_secrets"] = []

                services.append(service)

        return services

    def _get_zone(self, exposure: str, is_segmented: bool) -> str:
        """Get network zone based on exposure and segmentation."""
        if not is_segmented:
            return "flat_network"

        if exposure == "internet-facing":
            return "dmz"
        if exposure == "internal":
            return random.choice(["app_tier", "data_tier", "internal"])
        return "internal"

    def _calculate_asset_value(self, role: str, industry: str) -> str:
        """Calculate asset value based on role and industry."""
        critical_roles = ["database", "payment", "billing", "iam", "secrets_management"]
        high_value_roles = [
            "api_server",
            "web_server",
            "app_server",
            "cicd_server",
            "message_broker",
        ]

        if role in critical_roles:
            return "critical"
        if role in high_value_roles:
            return "high"
        return "medium"

    def _determine_ownership(self, role: str, industry: str) -> str:
        """Determine service ownership based on role and industry."""
        # Define ownership mappings
        dev_roles = ["app_server", "api_server", "web_server"]
        devops_roles = [
            "cicd_server",
            "monitoring",
            "load_balancer",
            "ingress_controller",
        ]
        cloudnet_roles = ["load_balancer", "ingress_controller", "network_infra"]
        dbteam_roles = ["database", "cache"]
        security_roles = ["iam", "secrets_management", "waf"]

        # Industry-specific ownership
        if industry == "financial-services":
            if role in dbteam_roles:
                return "DBTEAM"
            if role in security_roles:
                return "SECURITY"
        elif industry == "consulting":
            if role in dbteam_roles:
                return "DBTEAM"
            if role in devops_roles:
                return "DEVOPS"

        # Default ownership based on role
        if role in dev_roles:
            return "DEV"
        if role in devops_roles:
            return "DEVOPS"
        if role in cloudnet_roles:
            return "CLOUDNET"
        if role in dbteam_roles:
            return "DBTEAM"
        if role in security_roles:
            return "SECURITY"

        # Default ownership
        return "DEV"

    def _get_data_classification(self, role: str) -> list[str]:
        """Get data classification based on service role."""
        classifications = {
            "database": ["pii", "financial"],
            "payment": ["pci-dss", "financial"],
            "iam": ["credentials", "confidential"],
            "secrets_management": ["secrets", "confidential"],
            "siem_storage": ["logs", "audit"],
            "bi_tool": ["analytics", "business-intelligence"],
        }
        return classifications.get(role, [])

    def _add_sidecar_exporters(
        self,
        services: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Add monitoring exporters as sidecars to services.

        Args:
            services: List of services

        Returns:
            Services with sidecars added

        """
        for service in services:
            if random.random() < self.scenario_config.SIDECAR_PROBABILITY:
                service["sidecar_exporter"] = {
                    "name": f"{service['name']}-exporter",
                    "image": "prom/node-exporter:latest",
                    "port": 9100,
                }

        return services

    def _add_cicd_services(
        self,
        services: list[dict[str, Any]],
        environment_type: str,
        is_segmented: bool,
    ) -> list[dict[str, Any]]:
        """Add CI/CD services to the scenario.

        Args:
            services: List of services
            environment_type: Environment type
            is_segmented: Whether network is segmented

        Returns:
            Services with CI/CD added

        """
        cicd_services = [
            {
                "name": "git-repository",
                "role": "vcs",
                "image": "gitea:latest",
                "zone": "internal" if is_segmented else "flat_network",
                "port": 3000,
                "exposure": "internal",
                "asset_value": "high",
                "data_classification": ["source-code"],
                "ip_address": self.fake.ipv4_private(),
                "misconfigurations": [],
                "hardcoded_secrets": [],
            },
            {
                "name": "ci-runner",
                "role": "ci",
                "image": "gitlab-runner:latest",
                "zone": "app_tier" if is_segmented else "flat_network",
                "port": 8080,
                "exposure": "internal",
                "asset_value": "high",
                "ip_address": self.fake.ipv4_private(),
                "misconfigurations": [],
                "hardcoded_secrets": [],
            },
            {
                "name": "artifact-registry",
                "role": "registry",
                "image": "registry:latest",
                "zone": "app_tier" if is_segmented else "flat_network",
                "port": 5000,
                "exposure": "internal",
                "asset_value": "high",
                "ip_address": self.fake.ipv4_private(),
                "misconfigurations": [],
                "hardcoded_secrets": [],
            },
        ]

        # Add security issues to CI/CD services
        for service in cicd_services:
            if random.random() < self.scenario_config.MISCONFIG_PROBABILITY:
                service["misconfigurations"] = [
                    {
                        "key": random.choice(self.scenario_config.MISCONFIG_TYPES),
                        "value": self.fake.word(),
                    },
                ]
            if random.random() < self.scenario_config.SECRETS_PROBABILITY:
                service["hardcoded_secrets"] = [
                    {
                        "type": random.choice(self.scenario_config.SECRET_TYPES),
                        "location": f"/app/{self.fake.word()}.py",
                    },
                ]

        return services + cicd_services
