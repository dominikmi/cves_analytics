"""FastAPI application factory."""

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.api.routers import profiles as profiles_router
from src.api.routers import scans as scans_router
from src.api.routers import stream as stream_router
from src.data.stores.duckdb_store import DuckDBStore
from src.db.sqlite_models import reap_stale_runs
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Module-level singleton for DuckDB (analytical findings store)
_duckdb_store: DuckDBStore | None = None


def _get_duckdb_store() -> DuckDBStore:
    global _duckdb_store
    if _duckdb_store is None:
        _duckdb_store = DuckDBStore(":memory:")
    return _duckdb_store


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    """Manage application startup and shutdown."""
    global _duckdb_store
    logger.info("Application starting up")
    app.state.duckdb_store = _get_duckdb_store()
    reaped = reap_stale_runs()
    if reaped:
        logger.warning("Marked %d orphaned scan runs as FAILED", reaped)
    yield
    logger.info("Application shutting down")
    if _duckdb_store:
        _duckdb_store.close()
        # Reset so a subsequently created app gets a fresh store instead of
        # the closed connection.
        _duckdb_store = None


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="CVE Analytics",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(profiles_router.router, prefix="/api/profiles")
    app.include_router(scans_router.router, prefix="/api/profiles")
    app.include_router(stream_router.router, prefix="/api/stream")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Any, exc: Exception) -> JSONResponse:
        logger.error("Unhandled exception: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return app
