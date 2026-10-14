"""Scan report assembly.

Builds the aggregate "what the pipeline found" report for one scan run:
coverage, severity distributions (raw + reassessed), Bayesian risk
decomposition, threat-intel hits, kill-chain profile, and top findings.
Every section is guarded by column presence — findings schema drifts
with enrichment availability.
"""

from datetime import datetime
from typing import Any

from src.data.stores.duckdb_store import DuckDBStore
from src.db.sqlite_models import Profile, ScanRun
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

_TOP_FINDINGS = 10
_TOP_CWES = 10


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class ScanReportBuilder:
    """Composes the per-scan report from DuckDB findings + run metadata."""

    def __init__(self, store: DuckDBStore, scan_run: ScanRun, profile: Profile) -> None:
        self.store = store
        self.run = scan_run
        self.profile = profile
        self.columns: set[str] = (
            set(store.execute("PRAGMA table_info(findings)")["name"].to_list())
            if store.table_exists("findings")
            else set()
        )

    def _pick(self, *candidates: str) -> str | None:
        return next((c for c in candidates if c in self.columns), None)

    def _query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        return self.store.execute(sql, params).to_dicts()

    def _scalar(self, sql: str, params: list[Any] | None = None) -> Any:
        df = self.store.execute(sql, params)
        return df.item(0, 0) if df.height else None

    def _distribution(self, column: str) -> dict[str, int]:
        if column not in self.columns:
            return {}
        rows = self._query(
            f'SELECT "{column}" AS k, COUNT(*) AS n FROM findings '  # noqa: S608  # nosec B608 - column name comes from the table's own schema
            "WHERE run_id = ? GROUP BY 1 ORDER BY 2 DESC",
            [self.run.id],
        )
        return {
            str(r["k"] if r["k"] is not None else "null"): int(r["n"]) for r in rows
        }

    def _bool_count(self, *columns: str) -> int:
        """Count rows where ANY of the given boolean-ish columns is true."""
        present = [c for c in columns if c in self.columns]
        if not present:
            return 0
        expr = " OR ".join(f'COALESCE("{c}", FALSE)' for c in present)
        return int(
            self._scalar(
                f"SELECT COUNT(*) FROM findings WHERE run_id = ? AND ({expr})",  # noqa: S608  # nosec B608 - schema-derived identifiers
                [self.run.id],
            )
            or 0
        )

    def build(self) -> dict[str, Any]:
        """Assemble the full scan report."""
        started = _parse_ts(self.run.started_at)
        completed = _parse_ts(self.run.completed_at)
        duration = (
            round((completed - started).total_seconds(), 1)
            if started and completed
            else None
        )

        requested = list(self.profile.image_inventory or [])
        scanned = (
            sorted(
                r["image"]
                for r in self._query(
                    "SELECT DISTINCT image FROM findings WHERE run_id = ?",
                    [self.run.id],
                )
            )
            if "image" in self.columns
            else []
        )
        silent = sorted(set(requested) - set(scanned))

        return {
            "scan_run_id": self.run.id,
            "profile_id": self.run.profile_id,
            "profile_name": self.profile.name,
            "status": self.run.status,
            "started_at": self.run.started_at,
            "completed_at": self.run.completed_at,
            "duration_seconds": duration,
            "epss_vintage": self.run.epss_vintage,
            "cve_vintage": self.run.cve_vintage,
            "coverage": {
                "images_requested": len(requested),
                "images_with_findings": len(scanned),
                "images_without_findings": silent,
            },
            "totals": {
                "findings": self.store.count_findings(self.run.id or 0),
                "unique_cves": (
                    int(
                        self._scalar(
                            "SELECT COUNT(DISTINCT cve_id) FROM findings "
                            "WHERE run_id = ?",
                            [self.run.id],
                        )
                        or 0
                    )
                    if "cve_id" in self.columns
                    else 0
                ),
            },
            "severity": {
                "scanner": self._distribution(self._pick("severity") or "__none__"),
                "reassessed": self._distribution(
                    self._pick("risk_category", "severity_reassessed") or "__none__"
                ),
            },
            "risk": self._risk_summary(),
            "threat_intel": self._threat_intel(),
            "kill_chain": self._kill_chain(),
            "top_findings": self._top_findings(),
            "top_cwes": self._top_cwes(),
            "per_image": self.store.findings_by_image(self.run.id or 0),
        }

    def _risk_summary(self) -> dict[str, Any]:
        posterior = self._pick("posterior_probability", "bayesian_risk")
        lr_cols = {
            key: self._pick(col)
            for key, col in {
                "controls": "control_lr",
                "threat": "threat_lr",
                "cvss_vector": "cvss_vector_lr",
                "exposure": "exposure_lr",
                "criticality": "criticality_lr",
            }.items()
        }
        if posterior is None:
            return {"available": False}
        stats = self._query(
            f'SELECT AVG("{posterior}") AS avg_p, MAX("{posterior}") AS max_p '  # noqa: S608  # nosec B608 - schema-derived identifier
            "FROM findings WHERE run_id = ?",
            [self.run.id],
        )
        avg_lr: dict[str, float | None] = {}
        for key, col in lr_cols.items():
            if col:
                avg_lr[key] = self._scalar(
                    f'SELECT ROUND(AVG("{col}"), 4) FROM findings WHERE run_id = ?',  # noqa: S608  # nosec B608 - schema-derived identifier
                    [self.run.id],
                )
        return {
            "available": True,
            "avg_posterior": stats[0]["avg_p"] if stats else None,
            "max_posterior": stats[0]["max_p"] if stats else None,
            "avg_likelihood_ratios": avg_lr,
        }

    def _threat_intel(self) -> dict[str, int | float | None]:
        epss = self._pick("epss_score", "epss")
        return {
            "kev": self._bool_count("is_kev", "is_cisa_kev", "is_kev_from_catalog"),
            "public_exploit": self._bool_count("has_public_exploit"),
            "exploitdb": self._bool_count("has_exploitdb"),
            "metasploit": self._bool_count("has_metasploit"),
            "nuclei": self._bool_count("has_nuclei"),
            "poc_github": self._bool_count("has_poc_github"),
            "epss_ge_50pct": (
                int(
                    self._scalar(
                        f'SELECT COUNT(*) FROM findings WHERE run_id = ? AND "{epss}" >= 0.5',  # noqa: S608  # nosec B608 - schema-derived identifier
                        [self.run.id],
                    )
                    or 0
                )
                if epss
                else None
            ),
        }

    def _kill_chain(self) -> list[dict[str, Any]]:
        phase = self._pick("kill_chain_phase")
        if phase is None:
            return []
        prob = self._pick("kill_chain_probability")
        prob_expr = f'ROUND(AVG("{prob}"), 4)' if prob else "NULL"
        return self._query(
            f'SELECT "{phase}" AS phase, COUNT(*) AS count, '  # noqa: S608  # nosec B608 - schema-derived identifiers
            f"{prob_expr} AS avg_probability FROM findings WHERE run_id = ? "
            f"GROUP BY 1 ORDER BY 2 DESC",
            [self.run.id],
        )

    def _top_findings(self) -> list[dict[str, Any]]:
        posterior = self._pick("posterior_probability", "bayesian_risk")
        if posterior is None:
            return []
        wanted = [
            "cve_id",
            "image",
            "package",
            "version",
            "severity",
            "risk_category",
            "posterior_probability",
            "epss_score",
            "is_kev",
            "explanation",
        ]
        cols = [c for c in wanted if c in self.columns]
        select = ", ".join(f'"{c}"' for c in cols)
        return self._query(
            f"SELECT {select} FROM findings WHERE run_id = ? "  # noqa: S608  # nosec B608 - schema-derived identifiers
            f'ORDER BY "{posterior}" DESC NULLS LAST LIMIT ?',
            [self.run.id, _TOP_FINDINGS],
        )

    def _top_cwes(self) -> list[dict[str, Any]]:
        if "cwe_id" not in self.columns:
            return []
        return self._query(
            "SELECT cwe_id, COUNT(*) AS count FROM findings WHERE run_id = ? "
            "AND cwe_id IS NOT NULL GROUP BY 1 ORDER BY 2 DESC "
            "LIMIT ?",
            [self.run.id, _TOP_CWES],
        )
