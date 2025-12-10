"""CVSS-BT (Bayesian Threat) data processor.

Uses cvss-bt.csv from https://github.com/t0sche/cvss-bt as the primary
source for CVE attribution data. This dataset includes:
- CVSS-BT adjusted scores (incorporates exploitability)
- EPSS scores
- KEV flags (CISA and VulnCheck)
- Exploit availability (ExploitDB, Metasploit, Nuclei, GitHub PoC)
"""

from datetime import datetime
from pathlib import Path

import pandas as pd
import requests

from src.utils.logging_config import get_logger

logger = get_logger(__name__)

CVSS_BT_URL = "https://raw.githubusercontent.com/t0sche/cvss-bt/main/cvss-bt.csv"
CVSS_BT_FILENAME = "cvss-bt.csv"


class CVSSBTProcessor:
    """Processor for CVSS-BT dataset."""

    def __init__(self, data_dir: str | Path, cache_days: int = 1):
        """
        Initialize the CVSS-BT processor.

        Args:
            data_dir: Directory to store downloaded data
            cache_days: Number of days to cache the data before re-downloading
        """
        self.data_dir = Path(data_dir)
        self.cache_days = cache_days
        self.cvss_bt_dir = self.data_dir / "CVSS_BT"
        self.cvss_bt_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self) -> Path:
        """Get the path to the cached CVSS-BT file."""
        return self.cvss_bt_dir / CVSS_BT_FILENAME

    def _is_cache_valid(self) -> bool:
        """Check if the cached file is still valid."""
        cache_path = self._get_cache_path()
        if not cache_path.exists():
            return False

        # Check file age
        file_mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
        age_days = (datetime.now() - file_mtime).days
        return age_days < self.cache_days

    def download(self, force: bool = False) -> Path | None:
        """
        Download the CVSS-BT dataset.

        Args:
            force: Force download even if cache is valid

        Returns:
            Path to the downloaded file, or None if download failed
        """
        cache_path = self._get_cache_path()

        if not force and self._is_cache_valid():
            logger.info(f"Using cached CVSS-BT data: {cache_path}")
            return cache_path

        logger.info(f"Downloading CVSS-BT data from {CVSS_BT_URL}")

        try:
            response = requests.get(CVSS_BT_URL, timeout=60)
            response.raise_for_status()

            with open(cache_path, "w") as f:
                f.write(response.text)

            logger.info(f"Downloaded CVSS-BT data to {cache_path}")
            return cache_path

        except requests.RequestException as e:
            logger.warning(f"Failed to download CVSS-BT data: {e}")
            # Return cached file if available
            if cache_path.exists():
                logger.info("Using stale cached CVSS-BT data")
                return cache_path
            return None

    def load(self, force_download: bool = False) -> pd.DataFrame:
        """
        Load the CVSS-BT dataset.

        Args:
            force_download: Force re-download of the data

        Returns:
            DataFrame with CVSS-BT data
        """
        file_path = self.download(force=force_download)

        if file_path is None:
            logger.warning("CVSS-BT data not available")
            return pd.DataFrame()

        try:
            df = pd.read_csv(file_path)
            logger.info(f"Loaded {len(df)} records from CVSS-BT dataset")

            # Standardize column names
            df = df.rename(
                columns={
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
            )

            # Convert boolean columns
            bool_cols = [
                "is_cisa_kev",
                "is_vulncheck_kev",
                "has_exploitdb",
                "has_metasploit",
                "has_nuclei",
                "has_poc_github",
            ]
            for col in bool_cols:
                if col in df.columns:
                    df[col] = df[col].astype(bool)

            # Create combined KEV flag
            if "is_cisa_kev" in df.columns:
                df["is_kev"] = df["is_cisa_kev"]
                if "is_vulncheck_kev" in df.columns:
                    df["is_kev"] = df["is_cisa_kev"] | df["is_vulncheck_kev"]

            # Create combined exploit flag
            exploit_cols = [
                "has_exploitdb",
                "has_metasploit",
                "has_nuclei",
                "has_poc_github",
            ]
            existing_exploit_cols = [c for c in exploit_cols if c in df.columns]
            if existing_exploit_cols:
                df["has_public_exploit"] = df[existing_exploit_cols].any(axis=1)

            return df

        except Exception as e:
            logger.error(f"Failed to load CVSS-BT data: {e}")
            return pd.DataFrame()

    def enrich_with_cvss_bt(
        self,
        scan_results: pd.DataFrame,
        cve_id_col: str = "cve_id",
    ) -> tuple[pd.DataFrame, int]:
        """
        Enrich scan results with CVSS-BT data.

        Args:
            scan_results: DataFrame with vulnerability scan results
            cve_id_col: Column name containing CVE IDs

        Returns:
            Tuple of (enriched DataFrame, count of enriched records)
        """
        if scan_results.empty:
            return scan_results, 0

        cvss_bt_data = self.load()
        if cvss_bt_data.empty:
            logger.warning("CVSS-BT data not available, skipping enrichment")
            return scan_results, 0

        # Columns to merge from CVSS-BT
        merge_cols = [
            "cve_id",
            "cvss_bt_score",
            "cvss_bt_severity",
            "cvss_bt_vector",
            "cvss_version",
            "cvss_base_score",
            "cvss_base_severity",
            "cvss_base_vector",
            "epss",
            "is_kev",
            "is_cisa_kev",
            "is_vulncheck_kev",
            "has_public_exploit",
            "has_exploitdb",
            "has_metasploit",
            "has_nuclei",
            "has_poc_github",
        ]

        # Only include columns that exist
        available_cols = [c for c in merge_cols if c in cvss_bt_data.columns]
        cvss_bt_subset = cvss_bt_data[available_cols].drop_duplicates(subset=["cve_id"])

        # Merge with scan results
        before_count = len(scan_results)
        enriched = pd.merge(
            scan_results,
            cvss_bt_subset,
            left_on=cve_id_col,
            right_on="cve_id",
            how="left",
            suffixes=("", "_bt"),
        )

        # Count how many records were enriched
        enriched_count = enriched["cvss_bt_score"].notna().sum()
        logger.info(
            f"Enriched {enriched_count}/{before_count} records with CVSS-BT data"
        )

        return enriched, enriched_count


def download_cvss_bt_data(data_dir: str | Path) -> Path | None:
    """
    Convenience function to download CVSS-BT data.

    Args:
        data_dir: Directory to store downloaded data

    Returns:
        Path to the downloaded file, or None if download failed
    """
    processor = CVSSBTProcessor(data_dir)
    return processor.download()


def load_cvss_bt_data(data_dir: str | Path) -> pd.DataFrame:
    """
    Convenience function to load CVSS-BT data.

    Args:
        data_dir: Directory containing CVSS-BT data

    Returns:
        DataFrame with CVSS-BT data
    """
    processor = CVSSBTProcessor(data_dir)
    return processor.load()
