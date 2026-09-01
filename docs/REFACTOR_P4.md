# Phase 4: API + Service Layer

## Summary

Migrated the API layer (FastAPI routers, SSE streaming, dependencies) and service layer (pipeline orchestrator, Docker scanner, enrichment, attack path analysis) from the original `cves_analytics` codebase.

## Files Created

### API Layer
- `src/api/main.py` - FastAPI app factory with lifespan, DuckDB store initialization
- `src/api/dependencies.py` - DI for DuckDB store, SQLite session factory, job queues
- `src/api/routers/__init__.py` - Router package
- `src/api/routers/profiles.py` - Profile CRUD (GET/POST/PATCH/DELETE)
- `src/api/routers/scans.py` - Scan management (trigger, status, findings)
- `src/api/routers/stream.py` - SSE streaming for job status updates

### DB Layer
- `src/db/sqlite_models.py` - SQLModel ORM tables (Profile, ScanRun, Job) with JSON type annotations

### Services
- `src/services/__init__.py` - Service package
- `src/services/pipeline.py` - Pipeline orchestrator (scan -> enrich -> Bayesian risk -> analysis)
- `src/services/scanner.py` - Docker image scanner (grype/trivy CLI wrapper)
- `src/services/enrichment.py` - Enrichment service (EPSS, KEV, CVSS-BT, CWE)
- `src/services/analysis.py` - Attack path analysis (kill chain calculator)

## Tests Created
- `tests/unit/test_api_main.py` - App factory, health endpoint, router registration
- `tests/unit/test_enrichment_service.py` - Enrichment service (single/batch, missing data)
- `tests/unit/test_scanner.py` - Docker scanner (CLI parsing, error handling)
- `tests/unit/test_analysis_service.py` - Attack path analysis (empty data, kill chain)

## Issues Fixed
1. `sessionmaker` import from `sqlalchemy.orm` (not `sqlmodel`)
2. `Queue` type args for mypy compliance
3. `BayesianAssessor` -> `BayesianRiskAssessor` (correct class name)
4. `AttackPathAnalyzer` -> `KillChainCalculator` (correct class name)
5. `image_inventory: list[str]` required `sa_type=JSON` for SQLAlchemy
6. `severity_counts: dict` required `sa_type=JSON` for SQLAlchemy
7. B008 FastAPI pattern ignored in `src/api/` (per-file ruff ignore)
8. S603 subprocess ignored in `src/services/scanner.py` (grype CLI invocation)
9. `_IncludedRouter` path resolution in FastAPI 0.114+ (test fix)
10. polars `row_tuples()` -> `iter_rows(named=True)` (API change)

## Dependencies Added
- `fastapi`
- `sqlmodel`
- `sse-starlette`
- `uvicorn`

## Test Results
- **203 tests passing** (152 core + 41 data + 10 API/service)
- **ruff**: Clean (0 issues)
- **mypy**: Clean (0 issues)

## Architecture Notes
- SQLite (SQLModel ORM) for transactional profile/scan/job data
- DuckDB (in-memory) for analytical findings storage
- Job queue system for async scan processing
- SSE streaming for real-time job status updates
- Pipeline orchestrator composes scanner -> enrichment -> Bayesian risk -> kill chain analysis
