"""Basic smoke test for project structure."""

from typing import Any

from src.api.main import create_app
from src.utils.config import Settings, settings


class TestSettings:
    """Test configuration loading."""

    def test_default_settings(self) -> None:
        assert settings.app_name == "cves-analytics"
        assert not settings.debug

    def test_settings_type(self) -> None:
        assert isinstance(settings, Settings)


class TestApp:
    """Test FastAPI app creation."""

    def test_create_app(self) -> None:
        app = create_app()
        assert app is not None
        assert app.title == "CVE Analytics"

    def test_health_endpoint(self) -> None:
        from fastapi.testclient import TestClient

        app = create_app()
        client = TestClient(app)
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}


class TestCLI:
    """Test CLI pipeline."""

    def test_main_initializes(self, mocker: Any) -> None:
        from src.cli import pipeline

        mocker.patch(
            "argparse.ArgumentParser.parse_args",
            return_value=type(
                "Args",
                (),
                {
                    "data_dir": "data",
                    "upload_dir": "uploads",
                    "profile": 1,
                    "images": None,
                    "generate_scenario": False,
                    "size": "small",
                    "reach": "local",
                    "industry": "technology",
                    "env_type": "prod",
                },
            )(),
        )
        mocker.patch("src.cli.pipeline.get_engine")
        mocker.patch("src.cli.pipeline.DuckDBStore")
        mocker.patch("src.cli.pipeline.sys.exit")
        mock_pipeline = mocker.patch("src.cli.pipeline.VulnerabilityAssessmentPipeline")
        mock_pipeline.return_value.run.return_value = mocker.MagicMock(
            findings_df=mocker.MagicMock(__len__=mocker.MagicMock(return_value=0)),
            severity_counts={},
            avg_bayesian_risk=0.5,
        )
        pipeline.main()
