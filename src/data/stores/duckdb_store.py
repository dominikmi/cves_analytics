"""DuckDB-backed data store for vulnerability analytics."""

import re
import threading
from pathlib import Path
from typing import Any

import duckdb
import polars as pl

from src.utils.logging_config import get_logger

logger = get_logger(__name__)

_TABLE_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _validate_table_name(name: str) -> None:
    """Raise ValueError if name is not a valid SQL identifier."""
    if not _TABLE_NAME_RE.match(name):
        raise ValueError(f"Invalid table name: {name}")


class DuckDBStore:
    """In-process OLAP store using DuckDB.

    Provides table management and polars interop for vulnerability data.

    Args:
        db_path: Path to the DuckDB database file. Use \":memory:\" for
            ephemeral storage.
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._conn = duckdb.connect(database=self.db_path)
        # DuckDB connection objects are not safe for concurrent use from
        # multiple threads (background pipeline workers + API request threads),
        # so all statement execution is serialized through this lock.
        self._lock = threading.Lock()

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "DuckDBStore":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _execute(
        self, sql: str, params: dict[str, Any] | list[Any] | None = None
    ) -> duckdb.DuckDBPyConnection:
        """Execute SQL on the shared connection under the thread lock."""
        with self._lock:
            if params is not None:
                return self._conn.execute(sql, params)
            return self._conn.execute(sql)

    def write_table(
        self,
        name: str,
        df: pl.DataFrame,
        mode: str = "overwrite",
    ) -> None:
        """Write a polars DataFrame to a named table.

        Args:
            name: Table name.
            df: DataFrame to store.
            mode: "overwrite" to replace, "append" to add rows.
        """
        _validate_table_name(name)
        # Note: DuckDB resolves the `df` variable from this frame, so the
        # statements must execute directly here (not via a deeper wrapper).
        with self._lock:
            if mode == "overwrite":
                self._conn.execute(
                    f"CREATE OR REPLACE TABLE {name} AS SELECT * FROM df"  # noqa: S608  # nosec B608 - table identifiers are regex-validated before interpolation
                )
            else:
                self._conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {name} AS SELECT * FROM df LIMIT 0"  # noqa: S608  # nosec B608 - table identifiers are regex-validated before interpolation
                )
                self._conn.execute(
                    f"INSERT INTO {name} SELECT * FROM df"  # noqa: S608  # nosec B608 - table identifiers are regex-validated before interpolation
                )
        logger.info("Wrote %d rows to table '%s' (%s)", len(df), name, mode)

    def read_table(self, name: str) -> pl.DataFrame:
        """Read a table into a polars DataFrame.

        Args:
            name: Table name.

        Returns:
            Polars DataFrame.
        """
        _validate_table_name(name)
        return self._execute(f"SELECT * FROM {name}").pl()  # noqa: S608  # nosec B608 - table identifiers are regex-validated before interpolation

    def _table_columns(self, name: str) -> set[str]:
        """Return column names for an existing table."""
        _validate_table_name(name)
        rows = self._execute(f"PRAGMA table_info({name})").fetchall()  # noqa: S608  # nosec B608 - table identifiers are regex-validated before interpolation
        return {str(row[1]) for row in rows}

    @staticmethod
    def _finding_filters(
        run_id: int,
        columns: set[str],
        severity: str | None,
        status: str | None,
    ) -> tuple[str, list[Any]]:
        """Build a parameterized findings filter against available columns."""
        filters = ["run_id = ?"]
        params: list[Any] = [run_id]

        if severity:
            severity_column = next(
                (
                    column
                    for column in ("severity_reassessed", "severity")
                    if column in columns
                ),
                None,
            )
            if severity_column is None:
                filters.append("1 = 0")
            else:
                filters.append(f"LOWER({severity_column}) = LOWER(?)")
                params.append(severity)

        if status:
            if "status" not in columns:
                filters.append("1 = 0")
            else:
                filters.append("LOWER(status) = LOWER(?)")
                params.append(status)

        return " AND ".join(filters), params

    def query_findings(
        self,
        run_id: int,
        *,
        limit: int = 500,
        offset: int = 0,
        severity: str | None = None,
        status: str | None = None,
    ) -> pl.DataFrame:
        """Return findings for one scan run, optionally filtered."""
        if not self.table_exists("findings"):
            return pl.DataFrame()

        columns = self._table_columns("findings")
        where_clause, params = self._finding_filters(run_id, columns, severity, status)
        order_column = next(
            (
                column
                for column in ("cvss_score", "cvss_base_score", "cvss_bt_score")
                if column in columns
            ),
            None,
        )
        order_clause = (
            f" ORDER BY {order_column} DESC NULLS LAST" if order_column else ""
        )
        return self._execute(
            f"SELECT * FROM findings WHERE {where_clause}{order_clause} LIMIT ? OFFSET ?",  # noqa: S608  # nosec B608 - clauses use schema-derived identifiers and bound parameters
            [*params, limit, offset],
        ).pl()

    def count_findings(
        self,
        run_id: int,
        *,
        severity: str | None = None,
        status: str | None = None,
    ) -> int:
        """Count findings for one scan run with the same filters as queries."""
        if not self.table_exists("findings"):
            return 0
        where_clause, params = self._finding_filters(
            run_id,
            self._table_columns("findings"),
            severity,
            status,
        )
        count_sql = f"SELECT COUNT(*) FROM findings WHERE {where_clause}"  # noqa: S608  # nosec B608 - schema-derived identifiers and bound parameters
        row = self._execute(count_sql, params).fetchone()
        return int(row[0]) if row else 0

    def delete_findings(self, run_id: int) -> int:
        """Delete all stored findings for one scan run."""
        if not self.table_exists("findings"):
            return 0
        count = self.count_findings(run_id)
        self._execute("DELETE FROM findings WHERE run_id = ?", [run_id])
        return count

    def execute(self, sql: str, params: dict[str, Any] | None = None) -> pl.DataFrame:
        """Execute an arbitrary SQL query.

        Args:
            sql: SQL statement.
            params: Named parameters for the query.

        Returns:
            Result as polars DataFrame.
        """
        return self._execute(sql, params).pl()

    def table_exists(self, name: str) -> bool:
        """Check if a table exists.

        Args:
            name: Table name.

        Returns:
            True if the table exists.
        """
        _validate_table_name(name)
        result = self._execute(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
            [name],
        ).fetchone()
        return result[0] > 0 if result else False

    def table_names(self) -> list[str]:
        """List all table names in the database.

        Returns:
            Sorted list of table names.
        """
        rows = self._execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
        return sorted(row[0] for row in rows)
