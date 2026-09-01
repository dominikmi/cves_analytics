"""KEV (Known Exploited Vulnerabilities) loader.

Downloads CISA's Known Exploited Vulnerabilities catalog.
"""

from pathlib import Path

import polars as pl
import requests

from src.utils.logging_config import get_logger

logger = get_logger(__name__)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)


class KEVLoader:
    """Loader for CISA KEV catalog with local caching.

    Args:
        data_dir: Directory to cache the KEV CSV.
    """

    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir) / "KEV"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._file_path = self.data_dir / "known_exploited_vulnerabilities.csv"

    def load(self, force_download: bool = False) -> pl.DataFrame | None:
        """Download (if needed) and load the KEV catalog.

        Args:
            force_download: Re-download regardless of local cache.

        Returns:
            Polars DataFrame or None on failure.
        """
        if self._file_path.exists() and not force_download:
            logger.info("KEV cached: %s", self._file_path)
            try:
                return pl.read_csv(str(self._file_path))
            except Exception as exc:
                logger.error("Failed to parse KEV cache: %s", exc)
                return None

        logger.info("Downloading KEV from %s", KEV_URL)
        try:
            resp = requests.get(KEV_URL, timeout=30)
            resp.raise_for_status()
            self._file_path.write_bytes(resp.content)
            df = pl.read_csv(str(self._file_path))
            logger.info("Loaded %d KEV records", len(df))
            return df
        except requests.RequestException as exc:
            logger.error("KEV download failed: %s", exc)
            return None
