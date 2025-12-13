import logging
import time
from typing import Any

from src.simulation.scenario_generator import ScenarioGenerator


class EnvironmentGenerator:
    """Generates simulated environments for vulnerability assessment."""

    def __init__(self, logger: logging.Logger):
        """Initialize the environment generator."""
        self.logger = logger

    def generate(
        self,
        size: str,
        reach: str,
        industry: str,
        environment_type: str,
    ) -> dict[str, Any]:
        """Generate a simulated environment scenario."""
        start_time = time.time()

        try:
            self.logger.info(
                f"Generating environment: size={size}, reach={reach}, industry={industry}, env={environment_type}",
            )

            generator = ScenarioGenerator()
            scenario = generator.generate_scenario(
                size=size,
                reach=reach,
                industry=industry,
                environment_type=environment_type,
                output_format="json",
            )

            duration = time.time() - start_time
            services_count = len(scenario.get("services", []))
            self.logger.info(
                f"Environment generated in {duration:.2f}s with {services_count} services",
            )

            return scenario

        except Exception as e:
            self.logger.error(
                f"Failed to generate environment: {e!s}",
                exc_info=True,
            )
            raise
