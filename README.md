# CVEs Analytics

Vulnerability analytics for container images. It scans images, enriches
findings with threat intelligence, scores risk, and models attack paths.

## What it is for

Scanners produce long CVE lists. Most findings do not matter. This tool
ranks them. It answers: which vulnerabilities are actually dangerous in
your environment, and why.

## How it works

Given a list of Docker images, the pipeline:

1. **Scans** each image for known CVEs (Grype/Trivy).
2. **Enriches** findings with CVSS-BT scores, EPSS exploitation
   probability, CISA KEV status, and CWE metadata.
3. **Scores** each finding with a Bayesian risk posterior. It fuses CVSS,
   EPSS, deployed security controls, and threat intelligence.
4. **Models** attack paths through the cyber kill chain: initial access,
   execution, lateral movement, objective.
5. **Stores** results in DuckDB for analytics and SQLite for metadata.

The output is a ranked finding list. Each finding has a posterior risk
score, a credible interval, a risk category, and attack-path probability.

```
Images → Scanner → Raw findings → Enrichment (CVSS-BT, EPSS, KEV, CWE)
→ Bayesian risk scoring → Kill chain analysis → DuckDB + SQLite
```

## Quick start

```bash
# Install dependencies
uv sync

# Run the pipeline (CLI)
uv run cves-analytics --images nginx:latest

# Start the REST API
uv run uvicorn src.api.main:create_app --factory --host 0.0.0.0 --port 8000

# Start the frontend (separate terminal)
cd frontend
npm ci
npm run dev
```

## Deployment

The whole stack runs in containers. Everything goes through `make`.

```bash
make install   # check prerequisites; offers to install missing pieces
cp .env.example .env   # fill in your secrets
make up        # render config, build images, start the stack
```

Then open http://localhost:8080.

What happens:

1. `make install` checks for python3, curl, tar, docker or podman, and a
   compose plugin. Missing pieces are installed via brew (macOS) or apt
   (Linux). Every install asks for confirmation first.
2. `make config` renders `config.yaml` from `.env`. The rendered file
   holds the secrets. It is gitignored and never enters an image. It is
   mounted read-only into the api container.
3. `make build` builds two images from Ubuntu 24.04. `cves-analytics-api`
   runs uvicorn with the app installed from a wheel. `cves-analytics-web`
   serves the frontend through nginx. Both run as non-root.
4. `make up` starts three services: web, api, and a local OCI registry.

Topology:

```
browser → nginx :8080 → /api/* → api :8000 (internal only)
                        static files → SPA
api → registry.local:5000 (loopback-only on the host at 127.0.0.1:5000)
```

The api container has no published port. No container is privileged. No
docker or podman socket is mounted.

Scanning host-local images:

```bash
make mirror IMAGE=myapp:dev              # push into the local registry
make scan IMAGE=registry.local:5000/myapp:dev
make scan IMAGE=nginx:latest             # pull straight from Docker Hub
```

The registry sidecar also caches pulled images between scans.

Useful targets:

```bash
make ps          # container status
make logs        # follow logs
make down        # stop the stack
make version     # print the current semver (from pyproject.toml)
make release BUMP=patch   # bump version, tag, rebuild images
make clean       # stop stack and delete volumes (asks first)
```

Works with both `docker compose` and `podman compose`. The Makefile picks
whatever is installed.

## CLI

```bash
# Default profile, single image
uv run cves-analytics --images nginx:latest

# Custom data directory, multiple images
uv run cves-analytics --data-dir ./data --images nginx:latest redis:7-alpine

# Specific profile ID
uv run cves-analytics --profile 1 --images myapp:latest

# Generate a simulated environment scenario
uv run cves-analytics --generate-scenario --size mid --reach global \
  --industry financial-services --env-type prod
```

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

```bash
uv run uvicorn src.api.main:create_app --factory --host 0.0.0.0 --port 8000
```

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
| `GET` | `/api/profiles/{id}/scans/{run_id}/findings` | Paginated findings (`limit`, `offset`, `severity`, `status`) |
| `DELETE` | `/api/profiles/{id}/scans/{run_id}` | Delete a completed scan and its findings |
| `POST` | `/api/profiles/{id}/generate-scenario` | Return the profile's durable scenario snapshot |
| `GET` | `/api/stream/{job_id}` | SSE job status stream |

Scan statuses: `PENDING`, `RUNNING`, `DONE`, `FAILED`. Profiles and scans
cannot be deleted while a scan is active. Deleting a profile removes its
scan metadata and DuckDB findings.

**Example workflow:**

```bash
# Create a profile
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

# Trigger a scan (returns job_id)
curl -X POST http://localhost:8000/api/profiles/1/scans

# Stream job status
curl -N http://localhost:8000/api/stream/<job_id>

# Read the first page of CRITICAL findings for scan run 3
curl 'http://localhost:8000/api/profiles/1/scans/3/findings?severity=CRITICAL&limit=100&offset=0'
```

## Optional RAG calibration

An extra module calibrates risk parameters against threat-intelligence
documents. It embeds PDFs and markdown into a local vector store, then
asks a local LLM (LM Studio) to estimate parameters with citations.

It lives in the `rag` dependency group. Not installed by default.

```bash
uv sync --group rag

# Ingest threat intel documents (PDF/markdown) into the vector store
uv run python -m src.rag.cli ingest --dir data/threat_intel

# Check vector store and LLM status
uv run python -m src.rag.cli status

# Run calibration (requires LM Studio at RAG_LLM_BASE_URL)
uv run python -m src.rag.cli calibrate
```

Stack: embedded Qdrant for storage, FastEmbed (ONNX) for embeddings. No
external services except the LLM endpoint.

## Configuration

Settings load from environment variables (prefix `CVE_`) or `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `CVE_DATA_DIR` | `data` | Reference data cache directory |
| `CVE_UPLOAD_DIR` | `uploads` | Upload directory |
| `CVE_LOG_LEVEL` | `INFO` | Logging level |
| `CVE_DEBUG` | `false` | Debug mode |
| `CVE_GITHUB_CVE_URL` | CVEProject cvelistV5 API | CVE data source URL |
| `CVE_GITHUB_MAX_CVE_FILES` | `10` | Max CVE files to download |

RAG settings use the `RAG_` prefix (`RAG_VECTOR_STORE_DIR`,
`RAG_LLM_BASE_URL`, `RAG_LLM_MODEL`, `RAG_TOP_K`, and more). See
`src/rag/config.py` for the full list.

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

## Storage

- **SQLite** (SQLModel ORM): profiles, scan runs, job tracking.
- **DuckDB**: in-process analytical store for findings DataFrames.
- **Qdrant** (embedded, optional): threat-intel document chunks for RAG.

For detailed architecture, data flow, and module map see
[docs/README.md](docs/README.md).
