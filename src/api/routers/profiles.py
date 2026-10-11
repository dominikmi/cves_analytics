"""Profile CRUD router."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.api.dependencies import duckdb_store_dep, job_queues, session_dep
from src.data.stores.duckdb_store import DuckDBStore
from src.db.sqlite_models import (
    Job,
    Profile,
    ProfileCreate,
    ProfileOut,
    ProfilePatch,
    ScanRun,
)
from src.services.profiles import build_profile_snapshot
from src.utils.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


def _profile_out(profile: Profile) -> ProfileOut:
    """Map a profile ORM object to its API response model."""
    return ProfileOut(
        id=profile.id,
        name=profile.name,
        org_size=profile.org_size,
        org_reach=profile.org_reach,
        industry=profile.industry,
        environment=profile.environment,
        security_maturity=profile.security_maturity,
        image_inventory=profile.image_inventory,
        controls_snapshot=profile.controls_snapshot or {},
        total_scans=len(profile.scan_runs),
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.get("", response_model=list[ProfileOut])
def list_profiles(session: Session = Depends(session_dep)) -> list[ProfileOut]:  # noqa: B008
    """List all profiles."""
    profiles = session.exec(select(Profile)).all()
    return [_profile_out(profile) for profile in profiles]


@router.post("", response_model=ProfileOut, status_code=status.HTTP_201_CREATED)
def create_profile(  # noqa: B008
    data: ProfileCreate, session: Session = Depends(session_dep)
) -> ProfileOut:
    """Create a new environment profile with a stable starting snapshot."""
    profile = Profile.model_validate(data)
    snapshot = build_profile_snapshot(
        org_size=data.org_size,
        org_reach=data.org_reach,
        industry=data.industry,
        environment=data.environment,
        security_maturity=data.security_maturity,
        image_inventory=data.image_inventory,
    )
    profile.image_inventory = snapshot.image_inventory
    profile.controls_snapshot = snapshot.controls_snapshot
    profile.scenario_snapshot = snapshot.scenario_snapshot

    session.add(profile)
    session.commit()
    session.refresh(profile)
    logger.info("Created profile %s (id=%d)", profile.name, profile.id)
    return _profile_out(profile)


@router.get("/{profile_id}", response_model=ProfileOut)
def get_profile(  # noqa: B008
    profile_id: int, session: Session = Depends(session_dep)
) -> ProfileOut:
    """Get a profile by ID."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _profile_out(profile)


@router.patch("/{profile_id}", response_model=ProfileOut)
def patch_profile(  # noqa: B008
    profile_id: int,
    data: ProfilePatch,
    session: Session = Depends(session_dep),
) -> ProfileOut:
    """Patch a profile."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(profile, key, value)

    profile.updated_at = datetime.now(tz=UTC).isoformat()
    session.add(profile)
    session.commit()
    session.refresh(profile)
    return _profile_out(profile)


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(  # noqa: B008
    profile_id: int,
    duckdb_store: DuckDBStore = Depends(duckdb_store_dep),
    session: Session = Depends(session_dep),
) -> None:
    """Delete a profile and all completed scan data owned by it."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    scan_runs = session.exec(
        select(ScanRun).where(ScanRun.profile_id == profile_id)
    ).all()
    if any(run.status.upper() in {"PENDING", "RUNNING"} for run in scan_runs):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete a profile with active scan runs",
        )

    run_ids = [run.id or 0 for run in scan_runs]
    for run in scan_runs:
        jobs = session.exec(select(Job).where(Job.scan_run_id == run.id)).all()
        for job in jobs:
            job_queues.remove(job.job_id)
            session.delete(job)
        session.delete(run)

    session.delete(profile)
    session.flush()
    deleted_findings = sum(duckdb_store.delete_findings(run_id) for run_id in run_ids)
    session.commit()
    logger.info(
        "Deleted profile %s (id=%d) with %d scans and %d findings",
        profile.name,
        profile.id,
        len(scan_runs),
        deleted_findings,
    )
