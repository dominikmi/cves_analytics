# Forward Plan

**Status**: Living roadmap
**Updated**: 2026-10-12
**Supersedes**: PLAN_FORWARD.md v2.0 (2026-05-02)

This document tracks what the v0.3 platform set out to build, what is
shipped, and what remains. For the implemented system see
[README.md](../README.md) and [docs/README.md](README.md).

---

## 1. Vision

CVEs Analytics answers two questions:

1. What is the risk now?
2. How is the risk changing over time? Is the remediation programme working?

The second question drives the design. A **Profile** is the primary
entity — a persistent, deterministic environment definition scanned
repeatedly. A one-off scan is a special case: a profile with one run.

This enables burn-down tracking, MTTR measurement, EPSS drift analysis,
and remediation velocity.

---

## 2. Current state

### Done

| Area | State |
|------|-------|
| Pre-conditions | Resolved. Duplicate logging/config removed, Pydantic response models in place, EPSS vintage snapshotted on `ScanRun`. |
| Core API | Profile CRUD, scan trigger/list/detail/delete, paginated findings, scenario generation. Integer IDs; statuses `PENDING`/`RUNNING`/`DONE`/`FAILED`. |
| Real-time | SSE job stream at `/api/stream/{job_id}`. |
| Storage | SQLite via SQLModel (profiles, runs, jobs). DuckDB findings store (`src/data/stores/duckdb_store.py`). Parquet caches for CVE/EPSS reference data. |
| Frontend shell | React + Vite SPA. Profiles list and profile detail pages. |
| CI | GitHub Actions: ruff, mypy, `uv audit`, bandit, pytest with coverage. |
| RAG calibration | Optional `rag` dep group. Embedded Qdrant + FastEmbed. Calibrates risk parameters against threat-intel documents via a local LLM. Added after this plan was written. |

### Data model (implemented)

```
profiles                          scan_runs
┌──────────────────────────────┐  ┌──────────────────────────────────┐
│ id (INTEGER)                 │──│ id (INTEGER)                     │
│ name                         │  │ profile_id → profiles.id         │
│ org_size                     │  │ started_at, completed_at         │
│ industry                     │  │ status (PENDING/RUNNING/         │
│ environment                  │  │        DONE/FAILED)              │
│ org_reach                    │  │ epss_vintage (YYYY-MM)           │
│ security_maturity            │  │ cve_vintage (date)               │
│ controls_snapshot (JSON)     │  │ total_findings                   │
│ image_inventory (JSON)       │  │ critical_count, high_count       │
│ created_at, updated_at       │  │ avg_bayesian_risk                │
└──────────────────────────────┘  │ kill_chain_json                  │
                                  └──────────────────────────────────┘
                                              │
                                              ▼
                                     findings (DuckDB)
                             ┌────────────────────────────────────────┐
                             │ profile_id, scan_run_id, cve_id        │
                             │ image_name, image_tag, service_name    │
                             │ cvss_score, epss_score,                │
                             │ epss_percentile   ← snapshotted        │
                             │ bayesian_risk, ci bounds, severity     │
                             │ lifecycle status, first/resolved run   │
                             └────────────────────────────────────────┘
```

Key invariant: EPSS and CVSS are snapshotted at scan time. Without this,
every new EPSS download silently rewrites history.

### Temporal metrics (design intent)

| Metric | Formula | Answers |
|--------|---------|---------|
| Burn-down ratio | `open(run_N) / open(run_1)` | Is the backlog shrinking? |
| Remediation velocity | `resolved(run_N) − new(run_N)` per run | Closing faster than new findings arrive? |
| MTTR by severity | `avg(resolved − first_seen)` per severity | How long to fix Critical vs High? |
| Time to Arrival | `first_seen − cve.date_published` | How fast do we detect new CVEs? |
| EPSS drift | `epss(now) − epss(first_seen)` for open findings | Which open CVEs heat up? |
| Recurrence rate | Findings resolved, then reappearing | Are fixes permanent? |
| Risk trend | `avg(bayesian_risk)` over runs | Is posture improving? |
| Kill-chain trend | Kill-chain probability over runs | Is defence-in-depth improving? |

DuckDB handles these as window functions over findings. It can also query
the Parquet EPSS history in the same statement — no ETL.

---

## 3. Remaining work

### 3.1. Backend — findings lifecycle

```
PUT    /api/profiles/{id}/findings/{finding_id}   Status update (in_progress / accepted_risk / wont_fix)
GET    /api/profiles/{id}/findings                All findings across runs (filterable)
GET    /api/profiles/{id}/findings/persistent     CVEs open across all scans
GET    /api/profiles/{id}/findings/new            First seen in latest run
GET    /api/profiles/{id}/findings/resolved       Resolved in latest run
```

### 3.2. Backend — temporal analytics

```
GET    /api/profiles/{id}/trends               All temporal metrics (combined)
GET    /api/profiles/{id}/trends/burndown      Severity count per run (stacked area)
GET    /api/profiles/{id}/trends/velocity      Opened vs closed per run (bar)
GET    /api/profiles/{id}/trends/mttr          MTTR distributions by severity (box plot)
GET    /api/profiles/{id}/trends/tta           Time-to-arrival distribution (histogram)
GET    /api/profiles/{id}/trends/epss-drift    EPSS change for open findings
GET    /api/profiles/{id}/trends/risk-score    Average Bayesian risk over runs (line)
GET    /api/profiles/{id}/trends/killchain     Kill-chain probability over runs
```

### 3.3. Backend — single-run detail

```
GET    /api/profiles/{id}/scans/{run_id}/risk         Bayesian risk summary + distribution
GET    /api/profiles/{id}/scans/{run_id}/killchain    Stage probabilities + controls
GET    /api/profiles/{id}/scans/{run_id}/attackpaths  Graph nodes/edges for Cytoscape
GET    /api/profiles/{id}/scans/{run_id}/remediation  Phased remediation roadmap
GET    /api/profiles/{id}/scans/{run_id}/export       Text/markdown report
GET    /api/epss/trajectory/{cve_id}                  90-day EPSS series
```

### 3.4. Backend — housekeeping

- Alembic migrations for the SQLite schema. Currently none.
- Consider `structlog` for JSON request/pipeline logs. Optional.
- Performance targets: API single-run query < 100ms; burn-down over 12
  runs / 3k findings < 200ms; SSE first event < 2s.

### 3.5. Frontend — persona views

Planned stack stays valid: React 19, Tailwind, TanStack Query + Table,
Zustand, Plotly.js for charts, Cytoscape.js for kill-chain graphs,
openapi-typescript for codegen from `/api/openapi.json`.

```
/profiles/:id/executive   KPI cards, risk trend, burn-down, velocity
/profiles/:id/manager     Severity×service heatmap, EPSS drift, MTTR,
                          persistent threats, remediation roadmap
/profiles/:id/engineer    Virtualized findings table, attack-path graph,
                          kill-chain diagram, per-CVE risk intervals
```

| Metric | Target |
|--------|--------|
| Lighthouse score | > 90 |
| Time to Interactive | < 2s |
| CVE table (7k rows) | Smooth scroll (virtualized) |
| Initial bundle | < 400KB gzipped (Plotly/Cytoscape lazy-loaded) |

### 3.6. Deployment

No Docker artefacts yet. Plan:

```yaml
services:
  backend:    # python:3.12-slim + uv; volumes: data, output, db
  frontend:   # node build → nginx serve
  nginx:      # reverse proxy: /api/* → backend, /* → frontend
```

Homelab scope: single instance, no Prometheus/ELK. File-rotated logs and
`GET /api/health` suffice. Apprise for failure alerts, optional.

---

## 4. Risks

| Risk | Mitigation |
|------|------------|
| EPSS score rewrite | Done — snapshotted on findings at scan time. |
| ScenarioGenerator randomness | Frozen `controls_snapshot` per profile; repeat scans load, not regenerate. |
| Image tag ambiguity | Store `image_tag` on finding; flag floating tags (`:latest`) as unresolvable for MTTR. |
| DuckDB write contention | Pipeline writes on completion only; API reads only. |
| Schema drift (CVE 5.x) | Pydantic strict validation at ingest; version-tagged caches. |
| Frontend bundle size | Lazy-load Plotly/Cytoscape per route. |

---

## 5. Decisions log

| Decision | Rationale | Rejected |
|----------|-----------|----------|
| DuckDB for findings | Window functions, direct Parquet joins | SQLite (slow at scale), Postgres (over-engineered) |
| Profile as primary entity | Temporal tracking needs stable identity | Scan-first model |
| Parquet stays as CVE cache | 175k records load in ~0.1s; Polars-native | Migration to SQL |
| Qdrant + FastEmbed for RAG | ChromaDB had unfixable CVEs; FastEmbed needs no torch | sqlite-vec (too low-level), LanceDB (pulls torch) |
| Zustand over Redux | Same guarantees, ~10x less boilerplate | Redux Toolkit |
| Plotly + Cytoscape over D3 | Statistical charts and graph layouts built in | Raw D3 (weeks of work) |
| shadcn/ui | Headless, owned code, accessible | MUI, Ant Design |

---

## 6. Glossary

| Term | Definition |
|------|------------|
| CVE | Common Vulnerabilities and Exposures |
| CVSS | Common Vulnerability Scoring System |
| EPSS | Exploit Prediction Scoring System — probability of exploitation |
| KEV | CISA Known Exploited Vulnerabilities catalogue |
| LR | Likelihood Ratio — evidence weight in Bayesian scoring |
| MTTR | Mean Time to Remediate |
| TTA | Time to Arrival — lag between CVE publication and first detection |
| Profile | Persistent environment definition, scanned repeatedly |
| Finding | A CVE instance in a profile, with lifecycle state across runs |
