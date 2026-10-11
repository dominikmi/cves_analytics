"""Tests for scan-scoped DuckDB finding queries."""

import polars as pl

from src.data.stores.duckdb_store import DuckDBStore


def _store_with_findings() -> DuckDBStore:
    store = DuckDBStore(":memory:")
    store.write_table(
        "findings",
        pl.DataFrame(
            {
                "run_id": [1, 1, 1, 2],
                "cve_id": ["CVE-1", "CVE-2", "CVE-3", "CVE-4"],
                "severity": ["HIGH", "CRITICAL", "LOW", "HIGH"],
                "cvss_score": [7.0, 9.0, 2.0, 8.0],
                "status": ["open", "open", "resolved", "open"],
            }
        ),
    )
    return store


def test_query_findings_filters_and_paginates() -> None:
    """Findings can be filtered by run, severity, and status."""
    store = _store_with_findings()
    try:
        page = store.query_findings(
            1,
            limit=1,
            offset=0,
            severity="critical",
            status="open",
        )
        assert page["cve_id"].to_list() == ["CVE-2"]
        assert store.count_findings(1, severity="critical", status="open") == 1

        ordered = store.query_findings(1, limit=2, offset=0)
        assert ordered["cve_id"].to_list() == ["CVE-2", "CVE-1"]
        assert store.count_findings(1) == 3
    finally:
        store.close()


def test_query_findings_missing_table_returns_empty_frame() -> None:
    """An absent findings table behaves as an empty result set."""
    store = DuckDBStore(":memory:")
    try:
        assert store.query_findings(1).is_empty()
        assert store.count_findings(1) == 0
        assert store.delete_findings(1) == 0
    finally:
        store.close()


def test_delete_findings_is_scoped_to_run() -> None:
    """Deleting a run removes only that run's findings."""
    store = _store_with_findings()
    try:
        assert store.delete_findings(1) == 3
        remaining = store.read_table("findings")
        assert remaining["run_id"].to_list() == [2]
    finally:
        store.close()
