"""Dependency injection for FastAPI."""

import threading
from collections import defaultdict
from collections.abc import AsyncGenerator, Iterator
from typing import Any

from sqlmodel import Session

from src.data.stores.duckdb_store import DuckDBStore


class JobEventStream:
    """Replayable, multi-reader event log for one background job.

    Events are appended by the producer thread and read from index 0 by
    every consumer, so a client connecting late (or reconnecting) receives
    the full backlog plus live tail. A plain :class:`queue.Queue` cannot
    provide this: ``get()`` consumes, splitting events between readers.
    The buffer lives until the scan run is deleted.
    """

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._closed = False
        self._cond = threading.Condition()

    def push(self, event: dict[str, Any]) -> None:
        """Append an event and wake all readers."""
        with self._cond:
            self._events.append(event)
            self._cond.notify_all()

    def close(self) -> None:
        """Mark the stream finished; readers drain the backlog then stop."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def wait(
        self, index: int, timeout: float
    ) -> tuple[list[dict[str, Any]], int, bool]:
        """Block until new events exist or the stream closes.

        Args:
            index: Reader offset; events below this index are already seen.
            timeout: Max seconds to block before returning anyway (lets
                callers emit heartbeat comments on the wire).

        Returns:
            ``(new_events, next_index, closed)`` — ``closed`` may be True
            while events remain; they must be drained first.
        """
        with self._cond:
            self._cond.wait_for(
                lambda: index < len(self._events) or self._closed,
                timeout=timeout,
            )
            return self._events[index:], len(self._events), self._closed


# In-memory job event registry for SSE streaming
_job_queues: dict[str, JobEventStream] = defaultdict(JobEventStream)


class JobQueues:
    """Registry of per-job event streams for SSE."""

    def get(self, job_id: str) -> JobEventStream:
        return _job_queues[job_id]

    def has(self, job_id: str) -> bool:
        return job_id in _job_queues

    def create(self, job_id: str) -> JobEventStream:
        stream = JobEventStream()
        _job_queues[job_id] = stream
        return stream

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
