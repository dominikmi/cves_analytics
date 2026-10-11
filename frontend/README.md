# CVEs Analytics Frontend

React 19 + Vite dashboard for environment profiles, scan runs, and paginated vulnerability findings.

## Development

From the repository root, start the API first:

```bash
uv run uvicorn src.api.main:create_app --factory --host 127.0.0.1 --port 8000
```

Then start the frontend:

```bash
cd frontend
npm ci
npm run dev
```

Vite proxies `/api` requests to the FastAPI backend.

## Verification

```bash
npm ci
npm run lint
npm run build
npm audit --omit=dev   # production dependency audit
```

`npm audit` without `--omit=dev` also audits the local build toolchain. At the
time of this integration, remaining advisories are in development/build
dependencies; production dependencies are clean.
