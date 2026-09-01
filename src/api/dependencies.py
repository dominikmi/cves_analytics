"""Dependency injection for FastAPI."""

from collections import defaultdict
from collections.abc import AsyncGenerator, Iterator
from queue import Queue
from typing import Any

from sqlmodel import Session

from src.data.stores.duckdb_store import DuckDBStore

# In-memory job queue registry for SSE streaming
_job_queues: dict[str, Queue[Any]] = defaultdict(lambda: Queue())


class JobQueues:
    """Registry of per-job queues for SSE streaming."""

    def get(self, job_id: str) -> Queue[Any]:
        return _job_queues[job_id]

    def has(self, job_id: str) -> bool:
        return job_id in _job_queues

    def create(self, job_id: str) -> Queue[Any]:
        q: Queue[Any] = Queue()
        _job_queues[job_id] = q
        return q

    def remove(self, job_id: str) -> None:
        _job_queues.pop(job_id, None)


job_queues = JobQueues()


async def duckdb_store_dep() -> AsyncGenerator[DuckDBStore, None]:
    """Provide DuckDB store from app state."""
    from src.api.main import _get_duckdb_store

    yield _get_duckdb_store()


def session_dep() -> Iterator[Session]:
    """Provide a SQLite session, closed after the request.

    Must be a generator dependency: FastAPI only runs teardown for
    generator dependencies, so a plain function would leak the session's
    connection on every request. Kept synchronous (not async) so the
    session object is created, used and closed on the same worker thread.
    """
    from src.db.sqlite_models import get_session

    session = get_session()
    try:
        yield session
    finally:
        session.close()
