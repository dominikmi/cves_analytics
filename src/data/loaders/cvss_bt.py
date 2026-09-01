"""CVSS-BT dataset loader.

Downloads and caches the CVSS-BT dataset from t0sche/cvss-bt GitHub repo.
Primary source for CVE attribution data with exploitability metrics.
"""

from datetime import UTC, datetime
from pathlib import Path

import polars as pl
import requests

from src.utils.logging_config import get_logger

logger = get_logger(__name__)

CVSS_BT_URL = "https://raw.githubusercontent.com/t0sche/cvss-bt/main/cvss-bt.csv"
CVSS_BT_FILENAME = "cvss-bt.csv"


class CVSSBTLoader:
    """Loader for the CVSS-BT dataset with caching and column standardization.

    Args:
        data_dir: Directory to cache downloaded data.
        cache_days: Number of days before cache is considered stale.
    """

    def __init__(self, data_dir: str | Path, cache_days: int = 1) -> None:
        self.data_dir = Path(data_dir)
        self.cache_days = cache_days
        self._cache_dir = self.data_dir / "CVSS_BT"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self) -> Path:
        return self._cache_dir / CVSS_BT_FILENAME

    def _cache_valid(self) -> bool:
        path = self._cache_path()
        if not path.exists():
            return False
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        return (datetime.now(tz=UTC) - mtime).days < self.cache_days

    def download(self, force: bool = False) -> Path | None:
        """Download CVSS-BT CSV, respecting cache TTL.

        Args:
            force: Bypass cache and re-download.

        Returns:
            Path to the CSV file, or None on failure.
        """
        cache = self._cache_path()
        if not force and self._cache_valid():
            logger.info("Using cached CVSS-BT: %s", cache)
            return cache

        logger.info("Downloading CVSS-BT from %s", CVSS_BT_URL)
        try:
            resp = requests.get(CVSS_BT_URL, timeout=60)
            resp.raise_for_status()
            cache.write_text(resp.text)
            logger.info("Saved CVSS-BT to %s", cache)
            return cache
        except requests.RequestException as exc:
            logger.warning("CVSS-BT download failed: %s", exc)
            if cache.exists():
                logger.info("Falling back to stale cache")
                return cache
            return None

    def load(self, force_download: bool = False) -> pl.DataFrame:
        """Load and standardize the CVSS-BT dataset.

        Args:
            force_download: Re-download regardless of cache.

        Returns:
            Polars DataFrame with standardized columns.
        """
        path = self.download(force=force_download)
        if path is None:
            logger.warning("CVSS-BT unavailable, returning empty DataFrame")
            return _empty_cvss_bt_schema()

        try:
            df = pl.read_csv(path)
            logger.info("Loaded %d CVSS-BT records", len(df))
            return _standardize_cvss_bt(df)
        except Exception as exc:
            logger.error("Failed to parse CVSS-BT: %s", exc)
            return _empty_cvss_bt_schema()


def _empty_cvss_bt_schema() -> pl.DataFrame:
    """Return an empty DataFrame with the expected CVSS-BT schema."""
    return pl.DataFrame(
        schema={
            "cve_id": pl.Utf8,
            "cvss_bt_score": pl.Float64,
            "cvss_bt_severity": pl.Utf8,
            "cvss_bt_vector": pl.Utf8,
            "cvss_base_score": pl.Float64,
            "cvss_base_severity": pl.Utf8,
            "cvss_base_vector": pl.Utf8,
            "epss": pl.Float64,
            "is_kev": pl.Boolean,
            "is_cisa_kev": pl.Boolean,
            "is_vulncheck_kev": pl.Boolean,
            "has_public_exploit": pl.Boolean,
            "has_exploitdb": pl.Boolean,
            "has_metasploit": pl.Boolean,
            "has_nuclei": pl.Boolean,
            "has_poc_github": pl.Boolean,
        }
    )


def _standardize_cvss_bt(df: pl.DataFrame) -> pl.DataFrame:
    """Rename and type-cast CVSS-BT columns to canonical schema."""
    rename_map = {
        "cve": "cve_id",
        "cvss-bt_score": "cvss_bt_score",
        "cvss-bt_severity": "cvss_bt_severity",
        "cvss-bt_vector": "cvss_bt_vector",
        "base_score": "cvss_base_score",
        "base_severity": "cvss_base_severity",
        "base_vector": "cvss_base_vector",
        "cisa_kev": "is_cisa_kev",
        "vulncheck_kev": "is_vulncheck_kev",
        "exploitdb": "has_exploitdb",
        "metasploit": "has_metasploit",
        "nuclei": "has_nuclei",
        "poc_github": "has_poc_github",
    }
    existing = {k: v for k, v in rename_map.items() if k in df.columns}
    if existing:
        df = df.rename(existing)

    bool_cols = [
        "is_cisa_kev",
        "is_vulncheck_kev",
        "has_exploitdb",
        "has_metasploit",
        "has_nuclei",
        "has_poc_github",
    ]
    existing_bools = [c for c in bool_cols if c in df.columns]
    if existing_bools:
        df = df.with_columns([pl.col(c).cast(pl.Boolean) for c in existing_bools])

    # Combined KEV flag
    if "is_cisa_kev" in df.columns:
        if "is_vulncheck_kev" in df.columns:
            df = df.with_columns(
                (pl.col("is_cisa_kev") | pl.col("is_vulncheck_kev")).alias("is_kev")
            )
        else:
            df = df.with_columns(pl.col("is_cisa_kev").alias("is_kev"))

    # Combined exploit flag
    exploit_cols = [
        "has_exploitdb",
        "has_metasploit",
        "has_nuclei",
        "has_poc_github",
    ]
    existing_exploits = [c for c in exploit_cols if c in df.columns]
    if existing_exploits:
        df = df.with_columns(
            pl.any_horizontal([pl.col(c) for c in existing_exploits]).alias(
                "has_public_exploit"
            )
        )

    return df
