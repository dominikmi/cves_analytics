# Phase 1: Project Structure, Dependencies, CI/Pre-commit

## Overview

Phase 1 establishes the foundational project structure, dependency management, tooling configuration, and CI pipeline for the refactored `cves-analytics` codebase.

## Steps Performed

### 1. Directory Structure

Created the following module hierarchy under `src/`:

```
src/
├── core/          # Domain models & pure business logic
│   ├── risk/      # Bayesian risk, CVSS scoring
│   ├── attack/    # Kill chain, attack path analysis
│   └── models/    # Pydantic data models
├── data/          # Data access layer
│   ├── loaders/   # CSV, API, database ingestion
│   ├── transformers/ # Polars transformations
│   └── stores/   # DuckDB operations
├── api/           # FastAPI endpoints
├── cli/           # Command-line interface
└── utils/         # Shared utilities, config
```

Test structure under `tests/`:

```
tests/
├── unit/          # Core logic tests
├── integration/   # Pipeline & API tests
└── fixtures/      # Test data
```

All directories initialized with `__init__.py` for proper Python package recognition.

### 2. pyproject.toml Configuration

**Production Dependencies** (migrated from `cves_analytics`):
- `aiohttp>=3.10.0` - Async HTTP client
- `duckdb>=1.2.0` - In-process OLAP database
- `faker>=36.1.1` - Test data generation
- `fastapi>=0.115.0` - API framework
- `networkx>=3.4.2` - Graph algorithms for attack chains
- `numpy>=1.26.4` - Numerical computing
- `polars>=1.33.0` - DataFrames engine
- `pyarrow>=18.1.0` - Columnar data format
- `pydantic>=2.10.0` - Data validation
- `pydantic-settings>=2.12.0` - Settings management
- `python-dateutil>=2.9.0` - Date parsing
- `python-dotenv>=1.0.1` - Environment loading
- `python-multipart>=0.0.20` - File uploads
- `requests>=2.32.3` - HTTP client
- `ruamel.yaml>=0.18.16` - YAML parsing
- `sqlmodel>=0.0.22` - SQL ORM
- `sse-starlette>=2.1.0` - Server-sent events
- `uvicorn[standard]>=0.30.0` - ASGI server
- `idna>=3.15` - Domain name handling
- `urllib3>=2.7.0` - HTTP library

**Dev Dependencies** (PEP 735 groups):
- `bandit>=1.7.0` - Security linting
- `httpx>=0.28.1` - Async HTTP testing
- `hypothesis>=6.0.0` - Property-based testing
- `mypy>=2.3.0` - Static type checking
- `pre-commit>=4.0.0` - Hook framework
- `pytest>=9.0.3` - Test framework
- `pytest-asyncio>=0.24.0` - Async test support
- `pytest-cov>=7.1.0` - Coverage reporting
- `pytest-mock>=3.15.1` - Mocking utilities
- `ruff>=0.16.2` - Fast linter/formatter
- `uv>=0.5.13` - Package manager

**Tool Configuration:**
- **Ruff**: Line length 88, select rules `E, F, I, UP, B, S, G, SIM`, per-file ignores for tests (`S101`)
- **MyPy**: Python 3.12, strict mode, overrides for untyped third-party packages
- **Pytest**: Auto asyncio mode, test paths configured
- **Coverage**: 99% fail-under threshold, source set to `src/`

### 3. Pre-commit Hooks

`.pre-commit-config.yaml` configured with:
- **Ruff Check**: Linting on staged files
- **Ruff Format**: Formatting on staged files
- **MyPy**: Type checking on staged files
- **TruffleHog**: Secret scanning
- **UV Audit**: Dependency vulnerability scanning
- **Bandit**: Security linting on source

### 4. CI Workflow

`.github/workflows/ci.yml` triggers on push/PR to `main`/`master`:
1. Checkout code
2. Install `uv` with caching
3. Pin Python 3.12
4. Install dependencies with `uv sync --frozen`
5. Run Ruff check & format verification
6. Run MyPy type checking
7. Run `uv audit` for dependency vulnerabilities
8. Run Bandit security scan
9. Run pytest with 99% coverage gate
10. Upload coverage to Codecov

### 5. Bootstrap Modules

Created minimal entry points to verify structure:
- `src/utils/config.py` - Pydantic v2 `BaseSettings` with `CVE_` env prefix
- `src/api/app.py` - FastAPI factory with health check endpoint
- `src/cli/pipeline.py` - Argparse CLI entry point

### 6. Smoke Tests

`tests/unit/test_smoke.py` validates:
- Settings default values and type
- FastAPI app creation and title
- Health endpoint returns 200 with expected JSON
- CLI initialization

Coverage: **100%** (5 tests, 28 statements)

### 7. Verification Results

All gates passing:
- `uv run ruff check .` → All checks passed
- `uv run mypy src/` → Success: no issues found
- `uv run pytest --cov=src --cov-fail-under=99` → 5 passed, 100% coverage

## Design Decisions

1. **Strict layering**: `core/` has zero I/O dependencies; `data/` depends only on `core/` models; `api/` and `cli/` depend on both
2. **No backward compatibility**: API endpoints redesigned for clean architecture
3. **99% coverage gate**: Enforced in CI and local pytest config
4. **Freshness gate**: `uv sync` respects 7-day window via CI script (not `exclude-newer` in pyproject.toml, which requires ISO date format)
5. **Pragma over config**: Used `# pragma: no cover` on `__main__` guards rather than coverage config exclusions

## Next Phase

Phase 2: Migrate `core/` modules from `cves_analytics` with pure function extraction, comprehensive unit tests, and property-based tests for numerical computations.
