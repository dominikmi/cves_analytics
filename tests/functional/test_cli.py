"""Functional tests for the CLI entry point (src.cli.pipeline.main).

Runs the real ``main()`` against an isolated SQLite database with every
external boundary (scanner + reference loaders) stubbed, verifying the full
orchestration contract: profile bootstrapping, scenario generation, pipeline
execution, and exit codes.
"""

import sys
from collections.abc import Iterator
from pathlib import Path

import polars as pl
import pytest
from sqlmodel import SQLModel, create_engine, select

from src.db import sqlite_models
from src.db.sqlite_models import Profile


@pytest.fixture()
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Point the module-level engine at a throwaway SQLite file."""
    db_file = tmp_path / "cli.db"
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
def stub_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub every external-data boundary of the pipeline (no network, no CLI)."""

    def fake_scan_batch(self: object, images: list[str]) -> pl.DataFrame:
        return pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "package": ["openssl"],
                "version": ["3.0.0"],
                "image": images[0] if images else "unknown",
                "severity": ["HIGH"],
            }
        )

    monkeypatch.setattr(
        "src.services.pipeline.DockerScanner.scan_batch", fake_scan_batch
    )
    monkeypatch.setattr(
        "src.services.pipeline.CVSSBTLoader.load",
        lambda self: pl.DataFrame(
            {
                "cve_id": ["CVE-2024-1234"],
                "cvss_base_score": [7.5],
                "cvss_bt_score": [7.0],
            }
        ),
    )
    monkeypatch.setattr(
        "src.services.pipeline.EPSSLoader.load",
        lambda self: pl.DataFrame({"cve": ["CVE-2024-1234"], "epss": [0.5]}),
    )
    monkeypatch.setattr(
        "src.services.pipeline.KEVLoader.load",
        lambda self: pl.DataFrame({"cveID": ["CVE-2024-1234"]}),
    )

    async def fake_batch_get(self: object, cwe_ids: list[str]) -> dict:
        return {}

    monkeypatch.setattr("src.services.pipeline.CWELoader.batch_get", fake_batch_get)


def _run_cli(monkeypatch: pytest.MonkeyPatch, *args: str) -> int:
    """Invoke main() with the given argv and return its exit code."""
    monkeypatch.setattr(sys, "argv", ["cves-analytics", *args])
    from src.cli.pipeline import main

    with pytest.raises(SystemExit) as exc_info:
        main()
    return int(exc_info.value.code or 0)


class TestCli:
    def test_full_run_creates_profile_and_reports(
        self,
        isolated_db: None,
        stub_pipeline: None,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        code = _run_cli(
            monkeypatch,
            "--data-dir",
            str(tmp_path / "data"),
            "--profile",
            "1",
            "--images",
            "nginx:alpine",
            "web:2.0",
        )
        assert code == 0

        out = capsys.readouterr().out
        assert "Pipeline complete" in out
        assert "Findings: 1" in out

        session = sqlite_models.get_session()
        profiles = session.exec(select(Profile)).all()
        assert len(profiles) == 1
        assert profiles[0].image_inventory == ["nginx:alpine", "web:2.0"]
        session.close()

    def test_generate_scenario_flag(
        self,
        isolated_db: None,
        stub_pipeline: None,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        code = _run_cli(
            monkeypatch,
            "--data-dir",
            str(tmp_path / "data"),
            "--profile",
            "7",
            "--images",
            "nginx:alpine",
            "--generate-scenario",
            "--size",
            "mid",
            "--reach",
            "global",
            "--industry",
            "on-line-store",
            "--env-type",
            "prod",
        )
        assert code == 0

        out = capsys.readouterr().out
        assert "Generated scenario" in out
        assert "Topology:" in out
        session = sqlite_models.get_session()
        profile = session.get(Profile, 7)
        assert profile is not None
        assert profile.org_size == "mid"
        session.close()

    def test_existing_profile_is_reused(
        self,
        isolated_db: None,
        stub_pipeline: None,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        session = sqlite_models.get_session()
        session.add(
            Profile(
                id=1,
                name="pre-existing",
                org_size="small",
                org_reach="local",
                industry="consulting",
                environment="dev",
                security_maturity=0.5,
                image_inventory=["original:1.0"],
            )
        )
        session.commit()
        session.close()

        code = _run_cli(
            monkeypatch,
            "--data-dir",
            str(tmp_path / "data"),
            "--profile",
            "1",
        )
        assert code == 0

        out = capsys.readouterr().out
        assert "not found" not in out

        session = sqlite_models.get_session()
        profile = session.get(Profile, 1)
        # no --images flag -> original inventory untouched
        assert profile.image_inventory == ["original:1.0"]
        session.close()

    def test_pipeline_failure_exits_nonzero(
        self,
        isolated_db: None,
        stub_pipeline: None,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def exploding_scan_batch(self: object, images: list[str]) -> pl.DataFrame:
            raise RuntimeError("scan exploded")

        monkeypatch.setattr(
            "src.services.pipeline.DockerScanner.scan_batch", exploding_scan_batch
        )

        code = _run_cli(
            monkeypatch,
            "--data-dir",
            str(tmp_path / "data"),
            "--profile",
            "1",
            "--images",
            "nginx:alpine",
        )
        assert code == 1
