"""Scan management and findings router."""

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlmodel import Session, select

from src.api.dependencies import JobEventStream, job_queues, session_dep
from src.api.schemas import FindingsPage, finding_from_row
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


def _scan_run_out(session: Session, scan_run: ScanRun) -> ScanRunOut:
    """Map a scan run ORM object to its API response model."""
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


@router.get("/{profile_id}/scans", response_model=list[ScanRunOut])
def list_scans(  # noqa: B008
    profile_id: int, session: Session = Depends(session_dep)
) -> list[ScanRunOut]:
    """List all scan runs for a profile."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    runs = session.exec(select(ScanRun).where(ScanRun.profile_id == profile_id)).all()
    return [_scan_run_out(session, run) for run in runs]


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
    stream = job_queues.create(job_id)

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
        stream=stream,
        duckdb_store=duckdb_store,
    )

    return _scan_run_out(session, scan_run)


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

    return _scan_run_out(session, scan_run)


@router.delete(
    "/{profile_id}/scans/{run_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_scan(  # noqa: B008
    profile_id: int,
    run_id: int,
    duckdb_store: DuckDBStore = Depends(_get_duckdb),
    session: Session = Depends(session_dep),
) -> None:
    """Delete a completed scan run and its stored findings."""
    scan_run = session.get(ScanRun, run_id)
    if not scan_run or scan_run.profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Scan run not found")
    if scan_run.status in {"PENDING", "RUNNING"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete an active scan run",
        )

    job = session.exec(select(Job).where(Job.scan_run_id == run_id)).first()
    if job:
        job_queues.remove(job.job_id)
        session.delete(job)

    session.delete(scan_run)
    session.flush()
    deleted_findings = duckdb_store.delete_findings(run_id)
    session.commit()
    logger.info(
        "Deleted scan run %d for profile %d (%d findings)",
        run_id,
        profile_id,
        deleted_findings,
    )


@router.get(
    "/{profile_id}/scans/{run_id}/findings",
    response_model=FindingsPage,
)
def get_findings(  # noqa: B008
    profile_id: int,
    run_id: int,
    duckdb_store: DuckDBStore = Depends(_get_duckdb),
    session: Session = Depends(session_dep),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    finding_status: str | None = Query(default=None, alias="status"),
    image: str | None = Query(default=None),
    sort: Literal[
        "cve",
        "image",
        "service",
        "severity",
        "reassessed",
        "cvss",
        "epss",
        "risk",
        "kev",
    ]
    | None = Query(default=None),
    order: Literal["asc", "desc"] = Query(default="desc"),
) -> FindingsPage:
    """Return paginated findings for a scan run."""
    scan_run = session.get(ScanRun, run_id)
    if not scan_run or scan_run.profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Scan run not found")

    findings = duckdb_store.query_findings(
        run_id,
        limit=limit,
        offset=offset,
        severity=severity,
        status=finding_status,
        image=image,
        sort=sort,
        order=order,
    )
    total = duckdb_store.count_findings(
        run_id,
        severity=severity,
        status=finding_status,
        image=image,
    )
    items = [
        finding_from_row(
            row,
            profile_id=profile_id,
            run_id=run_id,
            index=offset + index,
            epss_vintage=scan_run.epss_vintage,
        )
        for index, row in enumerate(findings.to_dicts())
    ]
    return FindingsPage(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        scan_run_id=run_id,
    )


@router.get("/{profile_id}/scans/{run_id}/report")
def get_scan_report(  # noqa: B008
    profile_id: int,
    run_id: int,
    duckdb_store: DuckDBStore = Depends(_get_duckdb),
    session: Session = Depends(session_dep),
) -> dict[str, Any]:
    """Aggregate report for one scan run: coverage, severity + risk
    distributions, threat-intel hits, kill chain, and top findings."""
    scan_run = session.get(ScanRun, run_id)
    if not scan_run or scan_run.profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Scan run not found")
    profile = session.get(Profile, profile_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    from src.services.report import ScanReportBuilder

    return ScanReportBuilder(duckdb_store, scan_run, profile).build()


@router.get("/{profile_id}/scans/{run_id}/images")
def get_scan_image_stats(  # noqa: B008
    profile_id: int,
    run_id: int,
    duckdb_store: DuckDBStore = Depends(_get_duckdb),
    session: Session = Depends(session_dep),
) -> list[dict[str, Any]]:
    """Per-image finding aggregates for a scan run (drives the tabs UI)."""
    scan_run = session.get(ScanRun, run_id)
    if not scan_run or scan_run.profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return duckdb_store.findings_by_image(run_id)


@router.get("/{profile_id}/scenario", response_model=dict)
def get_scenario(  # noqa: B008
    profile_id: int,
    session: Session = Depends(session_dep),
) -> dict[str, Any]:
    """Return the profile's durable environment scenario."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    if not profile.scenario_snapshot:
        raise HTTPException(
            status_code=404,
            detail="No scenario yet — POST generate-scenario first",
        )
    return profile.scenario_snapshot


@router.post("/{profile_id}/generate-scenario", response_model=dict)
def generate_scenario(  # noqa: B008
    profile_id: int,
    session: Session = Depends(session_dep),
) -> dict[str, Any]:
    """Generate or return the durable environment scenario for a profile."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    if profile.scenario_snapshot:
        return profile.scenario_snapshot

    generator = ScenarioGenerator()
    scenario = generator.generate_scenario(
        size=profile.org_size or "small",
        reach=profile.org_reach or "local",
        industry=profile.industry or "technology",
        environment_type=profile.environment or "prod",
    )
    if isinstance(scenario, dict):
        profile.scenario_snapshot = scenario
        profile.updated_at = datetime.now(tz=UTC).isoformat()
        session.add(profile)
        session.commit()
        return scenario
    return {"csv": scenario}


def _run_pipeline_background(
    profile_id: int,
    scan_run_id: int,
    job_id: str,
    stream: JobEventStream,
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

        pipeline = VulnerabilityAssessmentPipeline(
            profile=profile,
            duckdb_store=duckdb_store,
        )
        result = pipeline.run(run_id=scan_run.id, on_progress=stream.push)

        scan_run.status = "DONE"
        scan_run.completed_at = datetime.now(tz=UTC).isoformat()
        scan_run.severity_counts = result.severity_counts
        scan_run.avg_bayesian_risk = result.avg_bayesian_risk
        session.commit()

        job = session.exec(select(Job).where(Job.job_id == job_id)).first()
        if job:
            job.finished_at = datetime.now(tz=UTC).isoformat()
            session.commit()

        stream.push({"type": "done", "status": "DONE"})

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

        stream.push({"type": "error", "message": str(exc)})
    finally:
        # Keep the event buffer so late-joining clients can replay the
        # full run; delete_scan/delete_profile own its cleanup.
        stream.close()
        session.close()
