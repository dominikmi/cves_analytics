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
        self, sql: str, params: dict[str, Any] | None = None
    ) -> duckdb.DuckDBPyConnection:
        """Execute SQL on the shared connection under the thread lock."""
        with self._lock:
            if params:
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
                    f"CREATE OR REPLACE TABLE {name} AS SELECT * FROM df"  # noqa: S608
                )
            else:
                self._conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {name} AS SELECT * FROM df LIMIT 0"  # noqa: S608
                )
                self._conn.execute(
                    f"INSERT INTO {name} SELECT * FROM df"  # noqa: S608
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
        return self._execute(f"SELECT * FROM {name}").pl()  # noqa: S608

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
            f"SELECT COUNT(*) FROM information_schema.tables WHERE table_name = '{name}'"  # noqa: S608
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
