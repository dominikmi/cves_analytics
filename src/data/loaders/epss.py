"""EPSS (Exploit Prediction Scoring System) data loader.

Downloads daily EPSS scores from empiricalsecurity.com with async support
and gzip decompression.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiohttp
import polars as pl
import requests

from src.utils.logging_config import get_logger

logger = get_logger(__name__)

EPSS_BASE_URL = "https://epss.empiricalsecurity.com"


class EPSSLoader:
    """Loader for EPSS daily score files with caching.

    Args:
        data_dir: Directory to cache downloaded EPSS files.
    """

    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir) / "EPSS"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _file_path(self, date: str) -> tuple[Path, Path]:
        gz = self.data_dir / f"epss_scores-{date}.csv.gz"
        csv = self.data_dir / f"epss_scores-{date}.csv"
        return gz, csv

    def download(
        self,
        date: str | None = None,
        force: bool = False,
    ) -> Path | None:
        """Download and decompress EPSS scores for a date.

        Args:
            date: Target date (YYYY-MM-DD). Defaults to yesterday.
            force: Re-download even if cached.

        Returns:
            Path to decompressed CSV, or None on failure.
        """
        if date is None:
            date = (datetime.now(tz=UTC) - timedelta(days=1)).strftime("%Y-%m-%d")

        gz, csv = self._file_path(date)
        if csv.exists() and not force:
            logger.info("EPSS cached: %s", csv)
            return csv

        url = f"{EPSS_BASE_URL}/epss_scores-{date}.csv.gz"
        try:
            if gz.exists() and not force:
                logger.info("EPSS gz exists, decompressing: %s", gz)
            else:
                logger.info("Downloading EPSS: %s", url)
                resp = requests.get(url, timeout=60)
                resp.raise_for_status()
                gz.write_bytes(resp.content)

            import gzip

            with gzip.open(gz, "rb") as f_in:
                csv.write_bytes(f_in.read())
            logger.info("Saved EPSS CSV: %s", csv)
            return csv
        except Exception as exc:
            logger.error("EPSS download failed for %s: %s", date, exc)
            if csv.exists() and not force:
                return csv
            return None

    def load(self, date: str | None = None) -> pl.DataFrame:
        """Load EPSS scores into a polars DataFrame.

        Args:
            date: Target date. Defaults to yesterday.

        Returns:
            DataFrame with 'cve' and 'epss' columns.
        """
        path = self.download(date=date)
        if path is None:
            return pl.DataFrame(schema={"cve": pl.Utf8, "epss": pl.Float64})

        try:
            df = pl.read_csv(path, skip_rows=1)
            logger.info("Loaded %d EPSS records", len(df))
            return df
        except Exception as exc:
            logger.error("Failed to parse EPSS: %s", exc)
            return pl.DataFrame(schema={"cve": pl.Utf8, "epss": pl.Float64})

    async def download_async(
        self,
        date: str | None = None,
        force: bool = False,
    ) -> Path | None:
        """Async version of download.

        Args:
            date: Target date. Defaults to yesterday.
            force: Re-download even if cached.

        Returns:
            Path to decompressed CSV, or None on failure.
        """
        if date is None:
            date = (datetime.now(tz=UTC) - timedelta(days=1)).strftime("%Y-%m-%d")

        gz, csv = self._file_path(date)
        if csv.exists() and not force:
            return csv

        url = f"{EPSS_BASE_URL}/epss_scores-{date}.csv.gz"
        try:
            import gzip

            async with aiohttp.ClientSession() as session:
                if not gz.exists() or force:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(60)
                    ) as resp:
                        resp.raise_for_status()
                        gz.write_bytes(await resp.read())

            with gzip.open(gz, "rb") as f_in:
                csv.write_bytes(f_in.read())
            return csv
        except Exception as exc:
            logger.error("EPSS async download failed for %s: %s", date, exc)
            if csv.exists() and not force:
                return csv
            return None
