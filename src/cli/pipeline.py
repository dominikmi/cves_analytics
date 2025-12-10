import logging
import time
from typing import Any

from src.cli.pipeline_steps.attack_analyzer import AttackAnalyzer
from src.cli.pipeline_steps.data_enricher import DataEnricher
from src.cli.pipeline_steps.docker_scanner import DockerScanner
from src.cli.pipeline_steps.environment_generator import EnvironmentGenerator
from src.cli.pipeline_steps.report_generator import ReportGenerator
from src.utils.config import AppConfig
from src.utils.logging_config import setup_logger


class VulnerabilityAssessmentPipeline:
    """Orchestrates the full vulnerability assessment pipeline."""

    def __init__(self, config: AppConfig):
        """Initialize the pipeline."""
        self.config = config
        # Setup logger with configured log level
        log_level = getattr(logging, config.log_level.upper(), logging.INFO)
        self.logger = setup_logger("pipeline", level=log_level)

        # Initialize pipeline steps
        self.environment_generator = EnvironmentGenerator(self.logger)
        self.docker_scanner = DockerScanner(self.logger)
        self.data_enricher = DataEnricher(self.logger)
        self.attack_analyzer = AttackAnalyzer(self.logger)
        self.report_generator = ReportGenerator(self.logger)

        # Pipeline state
        self.state: dict[str, Any] = {}

    def run(self) -> str:
        """Execute the complete pipeline and return the report path."""
        self.logger.info("Starting vulnerability assessment pipeline")
        start_time = time.time()

        try:
            # Step 1: Generate environment
            self._execute_step("Environment Generation", self._generate_environment)

            # Step 2: Scan Docker images
            self._execute_step("Docker Image Scanning", self._scan_docker_images)

            # Step 3: Enrich data
            self._execute_step("Data Enrichment", self._enrich_data)

            # Step 4: Analyze attack scenarios
            self._execute_step(
                "Attack Scenario Analysis", self._analyze_attack_scenarios
            )

            # Step 5: Generate report
            report_path = self._execute_step("Report Generation", self._generate_report)

            total_time = time.time() - start_time
            self.logger.info(f"Pipeline completed successfully in {total_time:.2f}s")

            return report_path

        except Exception as e:
            self.logger.error(f"Pipeline failed: {str(e)}", exc_info=True)
            raise

    def _execute_step(self, step_name: str, step_function):
        """Execute a pipeline step with timing and error handling."""
        self.logger.info("=" * 80)
        self.logger.info(f"STEP: {step_name}")
        self.logger.info("=" * 80)
        start_time = time.time()

        try:
            result = step_function()
            duration = time.time() - start_time
            self.logger.info(f"STEP COMPLETE: {step_name} (Duration: {duration:.2f}s)")
            self.logger.info("=" * 80)
            return result
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"ERROR in {step_name}: {str(e)}", exc_info=True)
            self.logger.error(f"Step {step_name} failed after {duration:.2f}s")
            raise

    def _generate_environment(self):
        """Generate the simulated environment."""
        self.state["scenario"] = self.environment_generator.generate(
            self.config.org_size,
            self.config.org_reach,
            self.config.industry,
            self.config.environment,
        )

    def _scan_docker_images(self):
        """Scan Docker images for vulnerabilities."""
        if "scenario" not in self.state:
            raise RuntimeError("Environment must be generated before scanning")

        self.state["scan_results"] = self.docker_scanner.scan(
            self.state["scenario"], self.config.grype_binary_path
        )

    def _enrich_data(self):
        """Enrich scan results with CVE and environment context."""
        if "scan_results" not in self.state:
            raise RuntimeError("Scan results must be available before enrichment")

        if "scenario" not in self.state:
            raise RuntimeError("Scenario must be available for enrichment")

        self.state["enriched_results"] = self.data_enricher.enrich(
            self.state["scan_results"], self.state["scenario"], self.config.data_path
        )

    def _analyze_attack_scenarios(self):
        """Analyze attack scenarios and vulnerability chains."""
        if "enriched_results" not in self.state:
            raise RuntimeError("Enriched results must be available for analysis")

        if "scenario" not in self.state:
            raise RuntimeError("Scenario must be available for analysis")

        self.state["analysis_results"] = self.attack_analyzer.analyze(
            self.state["enriched_results"], self.state["scenario"]
        )

    def _generate_report(self):
        """Generate the final vulnerability assessment report."""
        required_keys = [
            "scenario",
            "scan_results",
            "enriched_results",
            "analysis_results",
        ]
        for key in required_keys:
            if key not in self.state:
                raise RuntimeError(f"{key} must be available for report generation")

        return self.report_generator.generate(
            self.state["scenario"],
            self.state["scan_results"],
            self.state["enriched_results"],
            self.state["analysis_results"],
            self.config.output_path,
        )
