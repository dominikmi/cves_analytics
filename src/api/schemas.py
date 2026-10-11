"""Pydantic response schemas for API resources outside SQLite."""

import math
from typing import Any

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    """Normalized vulnerability finding returned by the findings API."""

    id: str
    profile_id: int
    scan_run_id: int
    cve_id: str | None = None
    image_name: str | None = None
    image_tag: str | None = None
    service_name: str | None = None
    severity: str | None = None
    severity_reassessed: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_vintage_date: str | None = None
    epss_snapshotted_at: str | None = None
    bayesian_risk: float | None = None
    bayesian_risk_low: float | None = None
    bayesian_risk_high: float | None = None
    is_kev: bool | None = None
    cwe_id: str | None = None
    description: str | None = None
    status: str = "open"
    first_seen_run_id: int | None = None
    resolved_run_id: int | None = None
    reassessment_reason: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)


class FindingsPage(BaseModel):
    """Paginated findings response."""

    items: list[FindingOut]
    total: int
    limit: int
    offset: int
    scan_run_id: int


def _value(row: dict[str, Any], *names: str) -> Any:
    """Return the first non-null, finite value from a DuckDB result row."""
    for name in names:
        value = row.get(name)
        if value is None:
            continue
        if isinstance(value, float) and not math.isfinite(value):
            continue
        return value
    return None


def _as_bool(value: Any) -> bool | None:
    """Normalize heterogeneous boolean representations from analytics data."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


def _split_image(image: Any) -> tuple[str | None, str | None]:
    """Split an image reference into repository/name and tag components."""
    if image is None:
        return None, None
    reference = str(image)
    name, separator, tag = reference.rpartition(":")
    if separator and "/" not in tag:
        return name, tag
    return reference, None


def finding_from_row(
    row: dict[str, Any],
    *,
    profile_id: int,
    run_id: int,
    index: int,
    epss_vintage: str | None,
) -> FindingOut:
    """Normalize one heterogeneous DuckDB finding row for API output."""
    image_name, image_tag = _split_image(_value(row, "image_name", "image"))
    cve_id = _value(row, "cve_id", "vulnerability_id")
    cvss_vector = _value(row, "cvss_vector", "cvss_base_vector", "cvss_bt_vector")
    return FindingOut(
        id=str(_value(row, "id", "finding_id") or f"{run_id}:{index}"),
        profile_id=profile_id,
        scan_run_id=run_id,
        cve_id=str(cve_id) if cve_id is not None else None,
        image_name=image_name,
        image_tag=_value(row, "image_tag") or image_tag,
        service_name=(
            str(service)
            if (service := _value(row, "service_name", "package", "artifact_name"))
            is not None
            else None
        ),
        severity=(
            str(severity) if (severity := _value(row, "severity")) is not None else None
        ),
        severity_reassessed=(
            str(severity)
            if (severity := _value(row, "severity_reassessed", "risk_category"))
            is not None
            else None
        ),
        cvss_score=_value(row, "cvss_score", "cvss_base_score", "cvss_bt_score"),
        cvss_vector=str(cvss_vector) if cvss_vector is not None else None,
        cvss_version=_value(row, "cvss_version")
        or (
            str(cvss_vector).split(":", 1)[1].split("/", 1)[0] if cvss_vector else None
        ),
        epss_score=_value(row, "epss_score", "epss"),
        epss_percentile=_value(row, "epss_percentile"),
        epss_vintage_date=_value(row, "epss_vintage_date") or epss_vintage,
        epss_snapshotted_at=_value(row, "epss_snapshotted_at"),
        bayesian_risk=_value(row, "bayesian_risk", "posterior_probability"),
        bayesian_risk_low=_value(row, "bayesian_risk_low", "credible_lower"),
        bayesian_risk_high=_value(row, "bayesian_risk_high", "credible_upper"),
        is_kev=_as_bool(_value(row, "is_kev", "is_kev_from_catalog", "is_cisa_kev")),
        cwe_id=(str(cwe_id) if (cwe_id := _value(row, "cwe_id")) is not None else None),
        description=(
            str(description)
            if (description := _value(row, "description", "cwe_desc")) is not None
            else None
        ),
        status=str(_value(row, "status") or "open"),
        first_seen_run_id=_value(row, "first_seen_run_id"),
        resolved_run_id=_value(row, "resolved_run_id"),
        reassessment_reason=_value(row, "reassessment_reason", "explanation"),
        raw=row,
    )
