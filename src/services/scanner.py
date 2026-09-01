"""Docker image vulnerability scanner service.

Wraps Grype or Trivy CLI tools for container image scanning.
"""

import json as _json
import re
import subprocess

import polars as pl

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
        if not self._validate_image(image):
            logger.error("Rejecting invalid image reference: %r", image)
            return self._empty_schema()

        logger.info("Scanning image %s with %s", image, self.tool)
        try:
            fmt_flag = "-o" if self.tool == "grype" else "--format"
            result = subprocess.run(
                [self.tool, image, fmt_flag, "json"],
                capture_output=True,
                timeout=300,
            )
            if result.returncode != 0:
                logger.warning("Scanner failed for %s: %s", image, result.stderr)
                return self._empty_schema()

            df = self._parse_output(result.stdout)
            # Tag every row with the scanned image name (overwrites the
            # all-null placeholder column from _parse_output's schema)
            df = df.with_columns(pl.lit(image).alias("image"))
            return df
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            logger.error("Scanner error for %s: %s", image, exc)
            return self._empty_schema()

    def scan_batch(self, images: list[str]) -> pl.DataFrame:
        """Scan multiple Docker images.

        Args:
            images: List of Docker image references.

        Returns:
            Combined DataFrame of all vulnerabilities.
        """
        frames = [self.scan(img) for img in images]
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

    def _empty_schema(self) -> pl.DataFrame:
        """Return empty DataFrame with expected schema."""
        return pl.DataFrame(schema=_SCHEMA)
