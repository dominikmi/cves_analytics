"""Docker image vulnerability scanner service.

Wraps Grype or Trivy CLI tools for container image scanning.
"""

import json as _json
import os
import re
import subprocess
from collections.abc import Callable

import polars as pl

from src.utils.config import get_config
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

_SCHEMA = {
    "cve_id": pl.Utf8,
    "package": pl.Utf8,
    "version": pl.Utf8,
    "image": pl.Utf8,
    "severity": pl.Utf8,
}

_ALLOWED_TOOLS = frozenset({"grype", "trivy"})
# Docker image reference: registry host, path segments, tag and digest.
# Rejects leading "-" (CLI flag injection) and shell metacharacters.
_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*$")
_MAX_IMAGE_REF_LEN = 512


class DockerScanner:
    """Scan Docker images for known vulnerabilities.

    Args:
        tool: Scanner tool to use ("grype" or "trivy"). Defaults to "grype".

    Raises:
        ValueError: If ``tool`` is not a supported scanner binary.
    """

    def __init__(self, tool: str = "grype") -> None:
        if tool not in _ALLOWED_TOOLS:
            raise ValueError(
                f"Unsupported scanner tool: {tool!r} "
                f"(expected one of: {', '.join(sorted(_ALLOWED_TOOLS))})"
            )
        self.tool = tool
        # GRYPE_BINARY_PATH may point at a non-PATH grype install.
        env_key = f"{tool.upper()}_BINARY_PATH"
        self._binary = os.environ.get(env_key, tool)

    def _validate_image(self, image: str) -> bool:
        """Return True if ``image`` is a safe Docker image reference."""
        if not image or len(image) > _MAX_IMAGE_REF_LEN:
            return False
        return _IMAGE_REF_RE.match(image) is not None

    def scan(self, image: str) -> pl.DataFrame:
        """Scan a single Docker image.

        Args:
            image: Docker image reference (e.g. "nginx:latest").

        Returns:
            DataFrame of vulnerabilities with image column populated.
        """
        df, _error = self._scan(image)
        return df

    def _scan(self, image: str) -> tuple[pl.DataFrame, str | None]:
        """Scan one image, returning ``(findings, error)``.

        ``error`` is a short human-readable reason when the scan could not
        produce results (invalid ref, registry failure, timeout); the
        DataFrame is empty in that case. ``None`` means the scan ran.
        """
        if not self._validate_image(image):
            logger.error("Rejecting invalid image reference: %r", image)
            return self._empty_schema(), "invalid image reference"

        logger.info("Scanning image %s with %s", image, self.tool)
        try:
            fmt_flag = "-o" if self.tool == "grype" else "--format"
            result = subprocess.run(
                [self._binary, image, fmt_flag, "json"],
                capture_output=True,
                timeout=300,
                env=self._subprocess_env(image),
            )
            if result.returncode != 0:
                detail = self._stderr_summary(result.stderr)
                logger.warning("Scanner failed for %s: %s", image, detail)
                return self._empty_schema(), detail

            df = self._parse_output(result.stdout)
            # Tag every row with the scanned image name (overwrites the
            # all-null placeholder column from _parse_output's schema)
            df = df.with_columns(pl.lit(image).alias("image"))
            return df, None
        except subprocess.TimeoutExpired:
            logger.error("Scanner timed out for %s", image)
            return self._empty_schema(), "scanner timed out"
        except FileNotFoundError as exc:
            logger.error("Scanner error for %s: %s", image, exc)
            return self._empty_schema(), f"scanner binary not found: {exc}"

    @staticmethod
    def _stderr_summary(stderr: bytes) -> str:
        """Extract the last non-empty stderr line as the failure reason."""
        lines = stderr.decode(errors="replace").strip().splitlines()
        return lines[-1].strip() if lines else "scanner exited non-zero"

    def scan_batch(
        self,
        images: list[str],
        on_image: Callable[[int, int, str, str, str | None], None] | None = None,
    ) -> pl.DataFrame:
        """Scan multiple Docker images sequentially.

        Args:
            images: List of Docker image references.
            on_image: Optional progress callback invoked per image as
                ``on_image(index, total, image, phase, detail)``. Phase is
                ``"start"`` before scanning, ``"done"`` with the finding
                count in ``detail``, or ``"failed"`` with the error reason.

        Returns:
            Combined DataFrame of all vulnerabilities.
        """
        total = len(images)
        frames = []
        for index, image in enumerate(images, start=1):
            if on_image is not None:
                on_image(index, total, image, "start", None)
            df, error = self._scan(image)
            if on_image is not None:
                if error is None:
                    on_image(index, total, image, "done", f"{len(df)} findings")
                else:
                    on_image(index, total, image, "failed", error)
            frames.append(df)
        if not frames:
            return self._empty_schema()
        return pl.concat(frames, rechunk=True)

    def _parse_output(self, raw: bytes) -> pl.DataFrame:
        """Parse scanner JSON output into DataFrame."""
        try:
            data = _json.loads(raw)
        except _json.JSONDecodeError:
            return self._empty_schema()

        vulns = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            pkg = match.get("artifact", {})
            vulns.append(
                {
                    "cve_id": vuln.get("id", "UNKNOWN"),
                    "package": pkg.get("name", "unknown"),
                    "version": pkg.get("version", "0.0.0"),
                    "severity": vuln.get("severity", "UNKNOWN"),
                }
            )

        return pl.DataFrame(vulns, schema=_SCHEMA) if vulns else self._empty_schema()

    def _subprocess_env(self, image: str) -> dict[str, str] | None:
        """Allow plain HTTP only for the configured local registry.

        The compose stack's registry sidecar serves plain HTTP. Scanners
        default to HTTPS, so refs pointing at ``settings.registry_host``
        get the per-tool insecure flag scoped to this invocation — remote
        registries keep TLS.
        """
        registry_host = get_config().registry_host
        image_host = image.split("/", 1)[0]
        if not registry_host or image_host != registry_host:
            return None
        if self.tool == "grype":
            return {**os.environ, "GRYPE_REGISTRY_INSECURE_USE_HTTP": "true"}
        return {**os.environ, "TRIVY_INSECURE": "true"}

    def _empty_schema(self) -> pl.DataFrame:
        """Return empty DataFrame with expected schema."""
        return pl.DataFrame(schema=_SCHEMA)
