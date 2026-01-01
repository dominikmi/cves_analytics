"""Kill-chain analysis pipeline step.

Analyzes vulnerabilities in the context of multi-component applications
to calculate kill-chain success probabilities.
"""

import logging
import time
from typing import Any

import polars as pl

from src.core.kill_chain_calculator import calculate_application_kill_chain
from src.simulation.application_builder import build_application_for_scenario


class KillChainAnalyzer:
    """Analyzes kill-chain probabilities for applications."""

    def __init__(self, logger: logging.Logger) -> None:
        """Initialize the kill-chain analyzer."""
        self.logger = logger

    def analyze(
        self,
        scenario: dict[str, Any],
        enriched_results: pl.DataFrame,
        service_catalog: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze kill-chain probabilities for the scenario.

        Args:
            scenario: Scenario dictionary with metadata and services
            enriched_results: DataFrame with enriched vulnerability data
            service_catalog: Service catalog from services.yaml

        Returns:
            Dictionary with kill-chain analysis results

        """
        start_time = time.time()

        try:
            self.logger.info("Starting kill-chain analysis")

            # Build application from scenario
            metadata = scenario.get("metadata", {})
            industry = metadata.get("industry", "consulting")
            company_name = scenario.get("company_name", "Unknown")
            is_segmented = metadata.get("topology") == "segmented"

            application = build_application_for_scenario(
                industry=industry,
                company_name=company_name,
                is_segmented=is_segmented,
                service_catalog=service_catalog,
            )

            # Get security controls
            security_controls = scenario.get("security_controls", {})

            # Determine Docker security posture
            # Good practices if: patch management is daily/weekly, has EDR, has network segmentation
            docker_security_good = self._assess_docker_security(
                scenario.get("security_posture", {}),
                security_controls,
            )

            # Calculate kill-chain probability
            kill_chain_result = calculate_application_kill_chain(
                application=self._convert_to_template(application),
                vulnerabilities=enriched_results,
                security_controls=security_controls,
                docker_security_good=docker_security_good,
            )

            # Build result
            result = {
                "application": {
                    "name": application["name"],
                    "type": application["type"],
                    "description": application["description"],
                    "component_count": application["component_count"],
                    "components": [
                        {
                            "name": svc["name"],
                            "role": svc.get("component_role", svc["role"]),
                            "image": svc["image"],
                            "exposure": svc["exposure"],
                            "asset_value": svc["asset_value"],
                        }
                        for svc in application["services"]
                    ],
                },
                "kill_chain": {
                    "total_probability": kill_chain_result.total_probability,
                    "threat_level": kill_chain_result.threat_level,
                    "bottleneck_stage": kill_chain_result.bottleneck_stage,
                    "critical_path": kill_chain_result.critical_path,
                    "stages": [
                        {
                            "name": stage.name,
                            "base_probability": stage.base_probability,
                            "conditional_probability": stage.conditional_probability,
                            "components": stage.components,
                            "contributing_factors": stage.contributing_factors,
                        }
                        for stage in kill_chain_result.stages
                    ],
                },
                "docker_security": {
                    "good_practices": docker_security_good,
                    "impact": "60% reduction in execution/lateral movement"
                    if docker_security_good
                    else "20% reduction in execution/lateral movement",
                },
            }

            duration = time.time() - start_time
            self.logger.info(
                f"Kill-chain analysis completed in {duration:.2f}s - "
                f"Total probability: {kill_chain_result.total_probability:.1%}, "
                f"Threat level: {kill_chain_result.threat_level}",
            )

            return result

        except Exception as e:
            self.logger.error(
                f"Failed to analyze kill-chain: {e!s}",
                exc_info=True,
            )
            return {
                "error": str(e),
                "application": None,
                "kill_chain": None,
            }

    def _assess_docker_security(
        self,
        security_posture: dict[str, Any],
        security_controls: dict[str, Any],
    ) -> bool:
        """Assess whether Docker security practices are good.

        Good practices include:
        - Frequent patching (daily/weekly)
        - EDR/XDR deployed
        - Network segmentation
        - Non-root containers
        - Read-only filesystems

        Args:
            security_posture: Legacy security posture dictionary
            security_controls: Security controls dictionary

        Returns:
            True if Docker security practices are good

        """
        # Check patch management
        patch_mgmt = security_posture.get("patch_management", "monthly")
        good_patching = patch_mgmt in ["daily", "weekly"]

        # Check for EDR/XDR
        has_edr = security_controls.get("edr_xdr", False)

        # Check for network segmentation
        has_segmentation = security_controls.get("network_segmentation", False)

        # Good if at least 2 of 3 criteria met
        score = sum([good_patching, has_edr, has_segmentation])
        return score >= 2

    def _convert_to_template(self, application: dict[str, Any]) -> Any:
        """Convert application dict to ApplicationTemplate for calculator.

        This is a temporary adapter until we refactor to use templates directly.

        Args:
            application: Application dictionary

        Returns:
            ApplicationTemplate-like object

        """
        from src.simulation.application_templates import (
            ApplicationTemplate,
            ApplicationType,
        )

        # Create a minimal template from the application
        # This is a simplified conversion - in production, we'd use the actual template
        return ApplicationTemplate(
            name=application["name"],
            type=ApplicationType(application["type"]),
            description=application["description"],
            components=[],  # Components already instantiated
            kill_chain_stages=application.get("kill_chain_stages", {}),
            data_flow=application.get("data_flow", []),
        )


def analyze_kill_chain(
    scenario: dict[str, Any],
    enriched_results: pl.DataFrame,
    service_catalog: dict[str, Any],
    logger: logging.Logger,
) -> dict[str, Any]:
    """Convenience function to analyze kill-chain.

    Args:
        scenario: Scenario dictionary
        enriched_results: Enriched vulnerability data
        service_catalog: Service catalog
        logger: Logger instance

    Returns:
        Kill-chain analysis results

    """
    analyzer = KillChainAnalyzer(logger)
    return analyzer.analyze(scenario, enriched_results, service_catalog)
