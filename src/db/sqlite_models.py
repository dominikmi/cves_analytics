"""SQLModel ORM models for metadata storage."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select

# Module-level engine/session factory
_engine = None
_session_factory = None


class ProfileBase(SQLModel):
    """Shared profile fields."""

    name: str = Field(index=True)
    org_size: str
    org_reach: str
    industry: str
    environment: str
    security_maturity: float
    image_inventory: list[str] = Field(default_factory=list, sa_type=JSON)


class ProfileCreate(ProfileBase):
    """Request model for creating a profile."""

    pass


class ProfilePatch(SQLModel):
    """Partial update model for profiles."""

    image_inventory: list[str] | None = None


class ProfileOut(ProfileBase):
    """Response model for profiles."""

    id: int | None = None
    total_scans: int = 0
    created_at: str
    updated_at: str


class Profile(ProfileBase, table=True):
    """SQLite ORM model for environment profiles."""

    id: int | None = Field(default=None, primary_key=True)
    scan_runs: list["ScanRun"] = Relationship(back_populates="profile")
    created_at: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


class ScanRunBase(SQLModel):
    """Shared scan run fields."""

    profile_id: int = Field(foreign_key="profile.id")
    status: str = "PENDING"
    epss_vintage: str | None = None
    cve_vintage: str | None = None
    severity_counts: dict[str, Any] | None = Field(default=None, sa_type=JSON)
    avg_bayesian_risk: float | None = None
    error_message: str | None = None
    report_path: str | None = None


class ScanRunOut(ScanRunBase):
    """Response model for scan runs."""

    id: int | None = None
    profile_id: int
    job_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None


class ScanRun(ScanRunBase, table=True):
    """SQLite ORM model for scan runs."""

    id: int | None = Field(default=None, primary_key=True)
    profile: Profile = Relationship(back_populates="scan_runs")
    started_at: str | None = None
    completed_at: str | None = None


class JobBase(SQLModel):
    """Shared job fields."""

    scan_run_id: int = Field(foreign_key="scanrun.id")
    job_id: str = Field(unique=True, index=True)


class Job(JobBase, table=True):
    """SQLite ORM model for background job tracking."""

    id: int | None = Field(default=None, primary_key=True)
    finished_at: str | None = None
    error_message: str | None = None


def get_engine() -> Any:
    """Get or create SQLite engine."""
    global _engine
    if _engine is None:
        # check_same_thread=False: the engine's pooled connections are shared
        # between API request threads and background pipeline workers. SQLite
        # serializes writers internally, so this is safe for our workload.
        _engine = create_engine(
            "sqlite:///analytics.db", connect_args={"check_same_thread": False}
        )
        SQLModel.metadata.create_all(_engine)
    return _engine


def get_session() -> Session:
    """Get a new SQLModel session."""
    return Session(get_engine())


def reap_stale_runs() -> int:
    """Mark runs left RUNNING/PENDING by a previous process as FAILED.

    Background jobs live in process memory, so any run still active when a
    new process starts was orphaned by a restart/crash.

    Returns:
        Number of runs marked FAILED.
    """
    session = get_session()
    try:
        # .in_() exists at runtime (SQLAlchemy instruments the field) but the
        # class-level annotation is plain str, so silence the checker.
        stale = session.exec(
            select(ScanRun).where(ScanRun.status.in_(["PENDING", "RUNNING"]))  # type: ignore[attr-defined]
        ).all()
        now = datetime.now(tz=UTC).isoformat()
        for run in stale:
            run.status = "FAILED"
            run.error_message = "Interrupted by server restart"
            run.completed_at = now
        session.commit()
        return len(stale)
    finally:
        session.close()
