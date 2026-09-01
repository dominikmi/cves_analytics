"""Tests for FastAPI application."""

from fastapi.testclient import TestClient

from src.api.main import create_app


class TestApp:
    """Test FastAPI app factory and health endpoint."""

    def test_health(self) -> None:
        app = create_app()
        client = TestClient(app)
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "healthy"}

    def test_app_has_routers(self) -> None:
        app = create_app()
        all_paths = []
        for route in app.routes:
            if hasattr(route, "path"):
                all_paths.append(route.path)
            elif hasattr(route, "original_router"):
                for sub in route.original_router.routes:
                    if hasattr(sub, "path"):
                        all_paths.append(sub.path)
        assert "/api/profiles" in all_paths or "" in all_paths
        assert "/{job_id}" in all_paths
