"""Profile CRUD router."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from src.api.dependencies import session_dep
from src.db.sqlite_models import (
    Profile,
    ProfileCreate,
    ProfileOut,
    ProfilePatch,
)
from src.utils.logging_config import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.get("", response_model=list[ProfileOut])
def list_profiles(session: Session = Depends(session_dep)) -> list[ProfileOut]:  # noqa: B008
    """List all profiles."""
    profiles = session.exec(select(Profile)).all()
    return [
        ProfileOut(
            id=p.id,
            name=p.name,
            org_size=p.org_size,
            org_reach=p.org_reach,
            industry=p.industry,
            environment=p.environment,
            security_maturity=p.security_maturity,
            image_inventory=p.image_inventory,
            total_scans=len(p.scan_runs),
            created_at=p.created_at,
            updated_at=p.updated_at,
        )
        for p in profiles
    ]


@router.post("", response_model=ProfileOut, status_code=status.HTTP_201_CREATED)
def create_profile(  # noqa: B008
    data: ProfileCreate, session: Session = Depends(session_dep)
) -> ProfileOut:
    """Create a new environment profile."""
    profile = Profile.model_validate(data)
    session.add(profile)
    session.commit()
    session.refresh(profile)
    logger.info("Created profile %s (id=%d)", profile.name, profile.id)
    return ProfileOut(
        id=profile.id,
        name=profile.name,
        org_size=profile.org_size,
        org_reach=profile.org_reach,
        industry=profile.industry,
        environment=profile.environment,
        security_maturity=profile.security_maturity,
        image_inventory=profile.image_inventory,
        total_scans=0,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.get("/{profile_id}", response_model=ProfileOut)
def get_profile(  # noqa: B008
    profile_id: int, session: Session = Depends(session_dep)
) -> ProfileOut:
    """Get a profile by ID."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return ProfileOut(
        id=profile.id,
        name=profile.name,
        org_size=profile.org_size,
        org_reach=profile.org_reach,
        industry=profile.industry,
        environment=profile.environment,
        security_maturity=profile.security_maturity,
        image_inventory=profile.image_inventory,
        total_scans=len(profile.scan_runs),
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


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

    return ProfileOut(
        id=profile.id,
        name=profile.name,
        org_size=profile.org_size,
        org_reach=profile.org_reach,
        industry=profile.industry,
        environment=profile.environment,
        security_maturity=profile.security_maturity,
        image_inventory=profile.image_inventory,
        total_scans=len(profile.scan_runs),
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_profile(  # noqa: B008
    profile_id: int, session: Session = Depends(session_dep)
) -> None:
    """Delete a profile."""
    profile = session.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    session.delete(profile)
    session.commit()
    logger.info("Deleted profile %s (id=%d)", profile.name, profile.id)
