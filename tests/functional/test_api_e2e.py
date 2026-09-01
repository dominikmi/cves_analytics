"""End-to-end functional tests for the API layer.

Exercises the full request path: profile CRUD -> scan trigger -> background
pipeline (scanner + reference loaders stubbed at the module boundary) -> SSE
stream -> stored findings. The SQLite engine is isolated to a temp file per
test; the DuckDB store and job-queue registry are module singletons, so they
are reset between tests.
"""

import json
import time
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from queue import Queue

import polars as pl
import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, create_engine

import src.api.dependencies as api_dependencies
from src.api.main import create_app
from src.db import sqlite_models
from src.db.sqlite_models import Profile, ScanRun


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Point the module-level engine at a throwaway SQLite file."""
    db_file = tmp_path / "test.db"
    engine = create_engine(
        f"sqlite:///{db_file}", connect_args={"check_same_thread": False}
    )
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(sqlite_models, "_engine", engine)
    monkeypatch.setattr(sqlite_models, "_session_factory", None)
    yield
    # Close pooled connections before the engine is garbage-collected;
    # otherwise sqlite3 emits ResourceWarning at GC time.
    engine.dispose()


@pytest.fixture()
def fresh_singletons(isolated_db: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset module singletons so each test starts clean."""
    import src.api.main as api_main

    monkeypatch.setattr(api_main, "_duckdb_store", None)
    monkeypatch.setattr(api_dependencies, "_job_queues", defaultdict(lambda: Queue()))


@pytest.fixture()
def client(fresh_singletons: None) -> TestClient:
    """TestClient with lifespan active (startup + shutdown run)."""
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def stub_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub every external-data boundary of the pipeline (no network, no CLI)."""

    def fake_scan_batch(self: object, images: list[str]) -> pl.DataFrame:
        return pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
                "package": ["openssl", "curl"],
                "version": ["3.0.0", "8.0.0"],
                "image": [images[0]] * 2,
                "severity": ["HIGH", "CRITICAL"],
            }
        )

    monkeypatch.setattr(
        "src.services.pipeline.DockerScanner.scan_batch", fake_scan_batch
    )
    monkeypatch.setattr(
        "src.services.pipeline.CVSSBTLoader.load",
        lambda self: pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234", "CVE-2024-5678"],
                "cvss_base_score": [7.5, 9.8],
                "cvss_bt_score": [7.0, 9.1],
                "cvss_base_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]
                * 2,
                "cwe_id": [327, 79],
            }
        ),
    )
    monkeypatch.setattr(
        "src.services.pipeline.EPSSLoader.load",
        lambda self: pl.DataFrame(
            {"cve": ["CVE-2024-1234", "CVE-2024-5678"], "epss": [0.1, 0.9]}
        ),
    )
    monkeypatch.setattr(
        "src.services.pipeline.KEVLoader.load",
        lambda self: pl.DataFrame({"cveID": ["CVE-2024-5678"]}),
    )

    async def fake_batch_get(self: object, cwe_ids: list[str]) -> dict:
        return {
            cid: {
                "cwe_id": cid,
                "cwe_name": f"CWE-{cid}",
                "cwe_desc": "desc",
                "cwe_cc_scope": "scope",
                "cwe_cc_impact": "impact",
            }
            for cid in cwe_ids
        }

    monkeypatch.setattr("src.services.pipeline.CWELoader.batch_get", fake_batch_get)


def _create_profile(client: TestClient, name: str = "e2e-profile") -> dict:
    resp = client.post(
        "/api/profiles",
        json={
            "name": name,
            "org_size": "mid",
            "org_reach": "global",
            "industry": "on-line-store",
            "environment": "prod",
            "security_maturity": 0.6,
            "image_inventory": ["myapp:1.0", "web:2.0"],
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _wait_for_status(
    client: TestClient,
    profile_id: int,
    run_id: int,
    expected: str,
    timeout_s: float = 20.0,
) -> dict:
    """Poll the scan run until it reaches ``expected`` status."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        body = client.get(f"/api/profiles/{profile_id}/scans/{run_id}").json()
        if body["status"] == expected:
            return body
        time.sleep(0.1)
    raise AssertionError(f"Scan {run_id} did not reach {expected}")


class TestProfileCrud:
    def test_full_crud_cycle(self, client: TestClient) -> None:
        created = _create_profile(client)
        profile_id = created["id"]

        listed = client.get("/api/profiles").json()
        assert [p["id"] for p in listed] == [profile_id]

        fetched = client.get(f"/api/profiles/{profile_id}").json()
        assert fetched["name"] == "e2e-profile"
        assert fetched["image_inventory"] == ["myapp:1.0", "web:2.0"]
        assert fetched["total_scans"] == 0

        patched = client.patch(
            f"/api/profiles/{profile_id}", json={"image_inventory": ["solo:1.0"]}
        )
        assert patched.status_code == 200
        assert patched.json()["image_inventory"] == ["solo:1.0"]

        deleted = client.delete(f"/api/profiles/{profile_id}")
        assert deleted.status_code == 204
        assert client.get(f"/api/profiles/{profile_id}").status_code == 404


class TestScanEndToEnd:
    def test_scan_completes_and_streams(
        self, client: TestClient, stub_pipeline: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profile = _create_profile(client)
        profile_id = profile["id"]

        # keep the queue alive after completion so the SSE endpoint can drain it
        monkeypatch.setattr(api_dependencies.job_queues, "remove", lambda job_id: None)

        resp = client.post(f"/api/profiles/{profile_id}/scans")
        assert resp.status_code == 201, resp.text
        body = resp.json()
        run_id = body["id"]
        assert body["status"] == "PENDING"
        job_id = body["job_id"]
        assert job_id  # SSE endpoint is addressable from the response

        done = _wait_for_status(client, profile_id, run_id, "DONE")
        assert done["severity_counts"] == {"HIGH": 1, "CRITICAL": 1}
        assert done["avg_bayesian_risk"] is not None
        assert 0.0 <= done["avg_bayesian_risk"] <= 1.0
        assert done["completed_at"] is not None

        # SSE stream replays queued progress events and terminates
        stream_resp = client.get(f"/api/stream/{job_id}")
        assert stream_resp.status_code == 200
        assert stream_resp.headers["content-type"].startswith("text/event-stream")
        events = [
            json.loads(line[6:])
            for line in stream_resp.text.splitlines()
            if line.startswith("data: ")
        ]
        assert {"type": "complete"} in events
        progress = [e for e in events if e.get("type") == "progress"]
        assert any("Scanning" in e["message"] for e in progress)
        assert any("Storing findings" in e["message"] for e in progress)

        # findings landed in the DuckDB store with run attribution
        from src.api.main import _get_duckdb_store

        findings = _get_duckdb_store().read_table("findings")
        assert len(findings) == 2
        assert set(findings["run_id"].to_list()) == {run_id}

        # listed scans carry the job id too
        runs = client.get(f"/api/profiles/{profile_id}/scans").json()
        assert runs[0]["job_id"] == job_id

    def test_scan_failure_is_recorded(
        self, client: TestClient, stub_pipeline: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        profile = _create_profile(client)
        profile_id = profile["id"]

        # stub_pipeline fakes the loaders; override the scanner to explode
        def exploding_scan_batch(self: object, images: list[str]) -> pl.DataFrame:
            raise RuntimeError("scanner exploded")

        monkeypatch.setattr(
            "src.services.pipeline.DockerScanner.scan_batch", exploding_scan_batch
        )

        resp = client.post(f"/api/profiles/{profile_id}/scans")
        assert resp.status_code == 201, resp.text
        run_id = resp.json()["id"]

        failed = _wait_for_status(client, profile_id, run_id, "FAILED")
        assert "scanner exploded" in failed["error_message"]

    def test_trigger_scan_unknown_profile_404(self, client: TestClient) -> None:
        assert client.post("/api/profiles/999/scans").status_code == 404

    def test_get_scan_unknown_run_404(
        self, client: TestClient, stub_pipeline: None
    ) -> None:
        profile = _create_profile(client)
        assert client.get(f"/api/profiles/{profile['id']}/scans/999").status_code == 404


class TestScenarioEndpoint:
    def test_generate_scenario(self, client: TestClient) -> None:
        profile = _create_profile(client)

        # real generator: YAML catalog falls back to the project root, so this
        # works regardless of CWD and exercises faker + catalog sampling
        resp = client.post(f"/api/profiles/{profile['id']}/generate-scenario")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["metadata"]["industry"] == "on-line-store"
        assert len(body["services"]) > 0

    def test_generate_scenario_unknown_profile_404(self, client: TestClient) -> None:
        assert client.post("/api/profiles/999/generate-scenario").status_code == 404


class TestReaper:
    def test_lifespan_reaps_orphaned_runs(
        self, isolated_db: None, fresh_singletons: None
    ) -> None:
        """A run left RUNNING by a previous process is marked FAILED on startup."""
        session = sqlite_models.get_session()
        profile = Profile(
            name="orphaned",
            org_size="small",
            org_reach="local",
            industry="consulting",
            environment="prod",
            security_maturity=0.5,
            image_inventory=["a:1"],
        )
        session.add(profile)
        session.commit()
        run = ScanRun(
            profile_id=profile.id, status="RUNNING", started_at="2026-01-01T00:00:00Z"
        )
        session.add(run)
        session.commit()
        run_id = run.id
        session.close()

        app = create_app()
        with TestClient(app):  # lifespan runs reap_stale_runs on startup
            pass

        session = sqlite_models.get_session()
        reaped = session.get(ScanRun, run_id)
        assert reaped.status == "FAILED"
        assert reaped.error_message == "Interrupted by server restart"
        session.close()


class TestStreamEndpoint:
    def test_unknown_job_404(self, client: TestClient) -> None:
        assert client.get("/api/stream/no-such-job").status_code == 404
