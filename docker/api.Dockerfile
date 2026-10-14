# syntax=docker/dockerfile:1
# API image: Ubuntu 24.04 LTS (stripped) + app installed from wheel.

# ---------------------------------------------------------------------------
# Build stage: build the wheel, install it (and deps as wheels) into a venv.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive
COPY --from=ghcr.io/astral-sh/uv:0.9.25 /uv /uvx /usr/local/bin/

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.12 \
        python3.12-venv \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# Build the project wheel, then install it — every Python lib lands as a wheel.
RUN uv build --wheel --out-dir /dist \
    && uv venv /opt/venv --python 3.12 \
    && uv pip install --python /opt/venv/bin/python --no-cache /dist/*.whl

# ---------------------------------------------------------------------------
# Runtime stage: minimal Ubuntu 24.04, non-root, pinned grype.
# ---------------------------------------------------------------------------
FROM ubuntu:24.04

ARG GRYPE_VERSION=0.120.1
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.12 \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home app

# Pinned grype release, verified against the release's own checksums file.
RUN cd /tmp \
    && curl -fsSLO \
        "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && curl -fsSLO \
        "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_checksums.txt" \
    && grep "linux_${TARGETARCH}\.tar\.gz$" \
        "grype_${GRYPE_VERSION}_checksums.txt" | sha256sum -c - \
    && tar -xzf "grype_${GRYPE_VERSION}_linux_${TARGETARCH}.tar.gz" \
        -C /usr/local/bin grype \
    && rm -f /tmp/grype_*.tar.gz /tmp/grype_*_checksums.txt

COPY --from=build /opt/venv /opt/venv

# Static reference data the pipeline reads relative to cwd
# (config.yaml itself is mounted at runtime, never baked in).
COPY config/services.yaml config/security_controls.yaml /app/config/

WORKDIR /app
RUN mkdir -p /app/data /app/db /app/output /app/uploads \
    && chown -R app:app /app

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "src.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
