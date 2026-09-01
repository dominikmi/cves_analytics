"""Integration tests for the full API workflow.

Verifies: create profile -> trigger scan -> scan completes -> results stored.
"""

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import polars as pl
import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine

from src.api.main import create_app


@pytest.fixture(autouse=True)
def _reset_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Isolate SQLite (throwaway file DB) and the DuckDB singleton per test."""
    import src.db.sqlite_models as models

    old_engine = models._engine
    engine = create_engine(
        f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False}
    )
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(models, "_engine", engine)
    monkeypatch.setattr(models, "_session_factory", None)

    # Reset DuckDB singleton
    import src.api.main as main_mod

    monkeypatch.setattr(main_mod, "_duckdb_store", None)
    yield
    # Close pooled connections before the engines are garbage-collected;
    # otherwise sqlite3 emits ResourceWarning at GC time.
    if old_engine is not None:
        old_engine.dispose()
    engine.dispose()


@pytest.fixture
def client() -> TestClient:
    """Create test client with in-memory DB."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def mock_scanner() -> None:
    """Patch DockerScanner to return synthetic findings."""
    mock = patch("src.services.pipeline.DockerScanner")
    scanner = mock.start()
    scanner.return_value.scan_batch.return_value = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "package": ["openssl", "curl"],
            "version": ["3.0.0", "7.88.0"],
            "image": ["nginx:latest", "nginx:latest"],
            "severity": ["HIGH", "CRITICAL"],
        }
    )
    yield
    mock.stop()


@pytest.fixture
def mock_loaders() -> None:
    """Patch data loaders to return reference data."""
    patches = [
        patch("src.services.pipeline.CVSSBTLoader"),
        patch("src.services.pipeline.EPSSLoader"),
        patch("src.services.pipeline.KEVLoader"),
        patch("src.services.pipeline.CWELoader"),
    ]
    started = [p.start() for p in patches]

    started[0].return_value.load.return_value = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "cvss_base_score": [7.5, 9.1],
            "cvss_bt_score": [7.0, 8.5],
            "epss": [0.15, 0.85],
            "cvss_base_vector": [
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ],
            "cwe_id": [264, 79],
        }
    )
    started[1].return_value.load.return_value = pl.DataFrame(
        {
            "cve_id": ["CVE-2024-0001", "CVE-2024-0002"],
            "epss": [0.15, 0.85],
        }
    )
    started[2].return_value.load.return_value = pl.DataFrame(
        {
            "CISA/VN Number": ["CVE-2024-0002"],
        }
    )
    started[3].return_value.batch_get = AsyncMock(
        return_value={
            "264": {"cwe_name": "Permissions Management"},
            "79": {"cwe_name": "XSS"},
        }
    )

    yield
    for p in patches:
        p.stop()


class TestAPIIntegration:
    """Full API workflow: profile -> scan -> results."""

    def test_create_profile(self, client: TestClient) -> None:
        """POST /api/profiles creates a profile."""
        resp = client.post(
            "/api/profiles",
            json={
                "name": "test-env",
                "org_size": "small",
                "org_reach": "internal",
                "industry": "technology",
                "environment": "development",
                "security_maturity": 0.5,
                "image_inventory": ["nginx:latest"],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "test-env"
        assert data["id"] is not None

    def test_trigger_scan_completes(
        self,
        client: TestClient,
        mock_scanner: None,
        mock_loaders: None,
    ) -> None:
        """POST /api/profiles/{id}/scans triggers and completes pipeline."""
        # Create profile
        profile_resp = client.post(
            "/api/profiles",
            json={
                "name": "test-env",
                "org_size": "small",
                "org_reach": "internal",
                "industry": "technology",
                "environment": "development",
                "security_maturity": 0.5,
                "image_inventory": ["nginx:latest"],
            },
        )
        profile_id = profile_resp.json()["id"]

        # Trigger scan
        scan_resp = client.post(f"/api/profiles/{profile_id}/scans")
        assert scan_resp.status_code == 201
        scan_id = scan_resp.json()["id"]

        # Background task runs synchronously in TestClient
        # Check scan completed
        status_resp = client.get(f"/api/profiles/{profile_id}/scans/{scan_id}")
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert status_data["status"] == "DONE"
        assert status_data["severity_counts"] is not None
        assert status_data["avg_bayesian_risk"] is not None
        assert 0.0 <= status_data["avg_bayesian_risk"] <= 1.0

    def test_list_scans(self, client: TestClient) -> None:
        """GET /api/profiles/{id}/scans returns scan runs."""
        profile_resp = client.post(
            "/api/profiles",
            json={
                "name": "test-env",
                "org_size": "small",
                "org_reach": "internal",
                "industry": "technology",
                "environment": "development",
                "security_maturity": 0.5,
                "image_inventory": ["nginx:latest"],
            },
        )
        profile_id = profile_resp.json()["id"]

        resp = client.get(f"/api/profiles/{profile_id}/scans")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_scan_finding_stored_in_duckdb(
        self,
        client: TestClient,
        mock_scanner: None,
        mock_loaders: None,
    ) -> None:
        """Pipeline stores findings in DuckDB."""
        profile_resp = client.post(
            "/api/profiles",
            json={
                "name": "test-env",
                "org_size": "small",
                "org_reach": "internal",
                "industry": "technology",
                "environment": "development",
                "security_maturity": 0.5,
                "image_inventory": ["nginx:latest"],
            },
        )
        profile_id = profile_resp.json()["id"]

        client.post(f"/api/profiles/{profile_id}/scans")

        # Verify findings stored in DuckDB
        from src.api.main import _get_duckdb_store

        store = _get_duckdb_store()
        df = store.read_table("findings")
        assert len(df) == 2
        assert set(df["cve_id"].to_list()) == {"CVE-2024-0001", "CVE-2024-0002"}
