# CVEs Analytics

Vulnerability analytics platform that scans container images, enriches findings with threat intelligence, computes Bayesian risk scores, and models attack paths through the cyber kill chain.

## Quick Start

```bash
# 1. Install dependencies
uv sync

# 2. Run the pipeline (CLI)
uv run cves-analytics --images nginx:latest

# 3. Start the REST API
uv run uvicorn src.api.main:create_app --factory --host 0.0.0.0 --port 8000
```

## CLI

Run the vulnerability assessment pipeline from the command line:

```bash
# Default profile, single image
uv run cves-analytics --images nginx:latest

# Custom data directory and multiple images
uv run cves-analytics --data-dir ./data --images nginx:latest redis:7-alpine

# Specific profile ID
uv run cves-analytics --profile 1 --images myapp:latest

# Generate a simulated environment scenario
uv run cves-analytics --generate-scenario --size mid --reach global --industry financial-services --env-type prod
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--data-dir` | `data` | Reference data cache directory |
| `--upload-dir` | `uploads` | Upload directory |
| `--profile` | `1` | Profile ID to scan |
| `--images` | `nginx:latest` | Docker images to scan |
| `--generate-scenario` | `false` | Generate a simulated environment |
| `--size` | `small` | Organization size (small, mid) |
| `--reach` | `local` | Geographic reach (local, global) |
| `--industry` | `technology` | Industry type |
| `--env-type` | `prod` | Environment type (dev, test, qa, stage, prod) |

## REST API

Start the server:

```bash
uv run uvicorn src.api.main:create_app --factory --host 0.0.0.0 --port 8000
```

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/profiles` | List profiles |
| `POST` | `/api/profiles` | Create profile |
| `GET` | `/api/profiles/{id}` | Get profile |
| `PATCH` | `/api/profiles/{id}` | Update profile |
| `DELETE` | `/api/profiles/{id}` | Delete profile |
| `POST` | `/api/profiles/{id}/scans` | Trigger scan |
| `GET` | `/api/profiles/{id}/scans` | List scan runs |
| `GET` | `/api/profiles/{id}/scans/{run_id}` | Get scan details |
| `POST` | `/api/profiles/{id}/generate-scenario` | Generate simulated environment |
| `GET` | `/api/stream/{job_id}` | SSE job status stream |

**Example workflow:**

```bash
# Create profile
curl -X POST http://localhost:8000/api/profiles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-cluster",
    "org_size": "enterprise",
    "org_reach": "public",
    "industry": "finance",
    "environment": "production",
    "security_maturity": 0.7,
    "image_inventory": ["myapp:latest"]
  }'

# Trigger scan (returns job_id)
curl -X POST http://localhost:8000/api/profiles/1/scans

# Stream job status
curl -N http://localhost:8000/api/stream/<job_id>

# Generate simulated environment scenario
curl -X POST http://localhost:8000/api/profiles/1/generate-scenario
```

## Configuration

Settings are loaded from environment variables with prefix `CVE_` or from `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `CVE_DATA_DIR` | `data` | Reference data cache directory |
| `CVE_UPLOAD_DIR` | `uploads` | Upload directory |
| `CVE_LOG_LEVEL` | `INFO` | Logging level |
| `CVE_DEBUG` | `false` | Debug mode |

## Development

```bash
# Lint
uv run ruff check .

# Format
uv run ruff format .

# Type check
uv run mypy src/

# Test
uv run pytest

# Test with coverage (fail_under is set in pyproject.toml)
uv run pytest --cov=src

# Security audit
uv audit
uv run bandit -r src/ -c .bandit
```

## Pipeline Overview

```
Profile (image list) → Scanner → Raw findings → Enrichment (CVSS-BT, EPSS, KEV, CWE)
→ Bayesian risk scoring → Kill chain analysis → DuckDB storage
```

For detailed architecture, data flow, and module map see [docs/README.md](docs/README.md).

## Storage

- **SQLite** (SQLModel ORM): Profiles, scan runs, job tracking
- **DuckDB**: In-process analytical store for findings DataFrames
