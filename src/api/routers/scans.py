"""Scan management router."""

import uuid
from datetime import UTC, datetime
from queue import Queue
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlmodel import Session, select

from src.api.dependencies import job_queues, session_dep
from src.data.stores.duckdb_store import DuckDBStore
from src.db.sqlite_models import (
    Job,
    Profile,
    ScanRun,
    ScanRunOut,
    get_session,
)
from src.services.pipeline import VulnerabilityAssessmentPipeline
from src.simulation.scenario_generator import ScenarioGenerator
from src.utils.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


def _get_duckdb() -> DuckDBStore:
    from src.api.main import _get_duckdb_store

    return _get_duckdb_store()


def _job_id_for(session: Session, scan_run: ScanRun) -> str | None:
    """Return the SSE job id for a scan run, if one was registered."""
    job = session.exec(select(Job).where(Job.scan_run_id == scan_run.id)).first()
    return job.job_id if job else None


@router.get("/{profile_id}/scans", response_model=list[ScanRunOut])
def list_scans(  # noqa: B008
    profile_id: int, session: Session = Depends(session_dep)
) -> list[ScanRunOut]:
    """List all scan runs for a profile."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    runs = session.exec(select(ScanRun).where(ScanRun.profile_id == profile_id)).all()
    return [
        ScanRunOut(
            id=r.id,
            profile_id=r.profile_id,
            status=r.status,
            job_id=_job_id_for(session, r),
            epss_vintage=r.epss_vintage,
            cve_vintage=r.cve_vintage,
            severity_counts=r.severity_counts,
            avg_bayesian_risk=r.avg_bayesian_risk,
            error_message=r.error_message,
            report_path=r.report_path,
            started_at=r.started_at,
            completed_at=r.completed_at,
        )
        for r in runs
    ]


@router.post(
    "/{profile_id}/scans",
    response_model=ScanRunOut,
    status_code=status.HTTP_201_CREATED,
)
def trigger_scan(  # noqa: B008
    profile_id: int,
    background_tasks: BackgroundTasks,
    duckdb_store: DuckDBStore = Depends(_get_duckdb),
    session: Session = Depends(session_dep),
) -> ScanRunOut:
    """Trigger a new vulnerability scan for a profile."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    job_id = str(uuid.uuid4())
    queue: Queue[Any] = job_queues.create(job_id)

    now = datetime.now(tz=UTC).isoformat()
    scan_run = ScanRun(
        profile_id=profile_id,
        status="PENDING",
        started_at=now,
    )
    session.add(scan_run)
    session.commit()
    session.refresh(scan_run)

    job = Job(scan_run_id=scan_run.id, job_id=job_id)
    session.add(job)
    session.commit()
    session.refresh(job)

    background_tasks.add_task(
        _run_pipeline_background,
        profile_id=profile_id,
        scan_run_id=scan_run.id or 0,
        job_id=job_id,
        queue=queue,
        duckdb_store=duckdb_store,
    )

    return ScanRunOut(
        id=scan_run.id,
        profile_id=scan_run.profile_id,
        status=scan_run.status,
        job_id=job.job_id,
        started_at=scan_run.started_at,
        completed_at=scan_run.completed_at,
    )


@router.get("/{profile_id}/scans/{run_id}", response_model=ScanRunOut)
def get_scan(  # noqa: B008
    profile_id: int,
    run_id: int,
    session: Session = Depends(session_dep),
) -> ScanRunOut:
    """Get a scan run by ID."""
    scan_run = session.get(ScanRun, run_id)
    if not scan_run or scan_run.profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Scan run not found")

    return ScanRunOut(
        id=scan_run.id,
        profile_id=scan_run.profile_id,
        status=scan_run.status,
        job_id=_job_id_for(session, scan_run),
        epss_vintage=scan_run.epss_vintage,
        cve_vintage=scan_run.cve_vintage,
        severity_counts=scan_run.severity_counts,
        avg_bayesian_risk=scan_run.avg_bayesian_risk,
        error_message=scan_run.error_message,
        report_path=scan_run.report_path,
        started_at=scan_run.started_at,
        completed_at=scan_run.completed_at,
    )


@router.post("/{profile_id}/generate-scenario", response_model=dict)
def generate_scenario(  # noqa: B008
    profile_id: int,
    session: Session = Depends(session_dep),
) -> dict[str, Any]:
    """Generate a simulated environment scenario for a profile."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    generator = ScenarioGenerator()
    scenario = generator.generate_scenario(
        size=profile.org_size or "small",
        reach=profile.org_reach or "local",
        industry=profile.industry or "technology",
        environment_type=profile.environment or "prod",
    )

    return scenario if isinstance(scenario, dict) else {"csv": scenario}


def _run_pipeline_background(
    profile_id: int,
    scan_run_id: int,
    job_id: str,
    queue: Queue[Any],
    duckdb_store: DuckDBStore,
) -> None:
    """Execute the vulnerability assessment pipeline in background."""
    session = get_session()

    try:
        scan_run = session.get(ScanRun, scan_run_id)
        if not scan_run:
            raise ValueError(f"ScanRun {scan_run_id} not found")

        scan_run.status = "RUNNING"
        session.commit()

        profile = session.get(Profile, profile_id)
        if not profile:
            raise ValueError(f"Profile {profile_id} not found")

        def _report_progress(step: str) -> None:
            queue.put({"type": "progress", "message": step})

        pipeline = VulnerabilityAssessmentPipeline(
            profile=profile,
            duckdb_store=duckdb_store,
        )
        result = pipeline.run(run_id=scan_run.id, on_progress=_report_progress)

        scan_run.status = "DONE"
        scan_run.completed_at = datetime.now(tz=UTC).isoformat()
        scan_run.severity_counts = result.severity_counts
        scan_run.avg_bayesian_risk = result.avg_bayesian_risk
        session.commit()

        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if job:
            job.finished_at = datetime.now(tz=UTC).isoformat()
            session.commit()

        queue.put(None)

    except Exception as exc:
        logger.error("Pipeline failed for scan %d: %s", scan_run_id, exc)
        scan_run = session.get(ScanRun, scan_run_id)
        if scan_run:
            scan_run.status = "FAILED"
            scan_run.error_message = str(exc)
            scan_run.completed_at = datetime.now(tz=UTC).isoformat()
            session.commit()

        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if job:
            job.finished_at = datetime.now(tz=UTC).isoformat()
            job.error_message = str(exc)
            session.commit()

        queue.put(None)
    finally:
        session.close()
        job_queues.remove(job_id)
