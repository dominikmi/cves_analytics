import sys
import unittest
from pathlib import Path

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestPipelineStructure(unittest.TestCase):
    """Test cases for pipeline structure and modularity."""

    def test_pipeline_imports(self):
        """Test that pipeline modules can be imported."""
        # Test main pipeline components
        from src.cli.pipeline import VulnerabilityAssessmentPipeline
        from src.cli.pipeline_steps.attack_analyzer import AttackAnalyzer
        from src.cli.pipeline_steps.data_enricher import DataEnricher
        from src.cli.pipeline_steps.docker_scanner import DockerScanner

        # Test pipeline steps
        from src.cli.pipeline_steps.environment_generator import EnvironmentGenerator
        from src.cli.pipeline_steps.report_generator import ReportGenerator
        from src.utils.config import AppConfig

        # Verify classes exist
        self.assertTrue(hasattr(VulnerabilityAssessmentPipeline, "__init__"))
        # Check AppConfig has the field defined (Pydantic v2 uses model_fields)
        config = AppConfig()
        self.assertTrue(hasattr(config, "grype_binary_path"))
        self.assertTrue(hasattr(EnvironmentGenerator, "generate"))
        self.assertTrue(hasattr(DockerScanner, "scan"))
        self.assertTrue(hasattr(DataEnricher, "enrich"))
        self.assertTrue(hasattr(AttackAnalyzer, "analyze"))
        self.assertTrue(hasattr(ReportGenerator, "generate"))

    def test_pipeline_config_validation(self):
        """Test that pipeline configuration validation works."""
        from src.utils.config import AppConfig

        # Test valid configuration
        config = AppConfig(
            grype_binary_path="/opt/homebrew/bin/grype",
            data_path="./data",
            output_path="./output",
            log_level="INFO",
        )

        self.assertEqual(config.grype_binary_path, "/opt/homebrew/bin/grype")
        self.assertEqual(config.data_path, "./data")
        self.assertEqual(config.output_path, "./output")
        self.assertEqual(config.log_level, "INFO")

    def test_pipeline_step_modules_exist(self):
        """Test that all pipeline step modules exist."""
        pipeline_steps_dir = (
            Path(__file__).parent.parent / "src" / "cli" / "pipeline_steps"
        )

        expected_files = [
            "__init__.py",
            "environment_generator.py",
            "docker_scanner.py",
            "data_enricher.py",
            "attack_analyzer.py",
            "report_generator.py",
        ]

        for filename in expected_files:
            file_path = pipeline_steps_dir / filename
            self.assertTrue(file_path.exists(), f"Missing file: {file_path}")

    def test_utils_modules_exist(self):
        """Test that all utility modules exist."""
        utils_dir = Path(__file__).parent.parent / "src" / "utils"

        expected_files = [
            "__init__.py",
            "config.py",
            "logging_config.py",
            "error_handling.py",
        ]

        for filename in expected_files:
            file_path = utils_dir / filename
            self.assertTrue(file_path.exists(), f"Missing file: {file_path}")


if __name__ == "__main__":
    unittest.main()
