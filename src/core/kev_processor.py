"""Known Exploited Vulnerabilities (KEV) processing module."""

from pathlib import Path

import pandas as pd
import requests

from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


@error_handler()
def download_known_exploited_vulnerabilities(
    directory: str,
) -> pd.DataFrame | None:
    """
    Download the known exploited vulnerabilities data from CISA.

    Args:
        directory: Directory to save the file

    Returns:
        DataFrame with KEV data or None if download failed
    """
    url = (
        "https://www.cisa.gov/sites/default/files/csv/"
        "known_exploited_vulnerabilities.csv"
    )

    dir_path = Path(directory) / "KEV"
    dir_path.mkdir(parents=True, exist_ok=True)

    file_path = dir_path / "known_exploited_vulnerabilities.csv"

    try:
        # Check if file already exists
        if file_path.exists():
            logger.info(f"KEV data already exists at {file_path}, loading from disk")
            return pd.read_csv(file_path)

        logger.info("Downloading known exploited vulnerabilities from CISA")
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        with open(file_path, "wb") as f:
            f.write(response.content)

        logger.info(f"Downloaded known exploited vulnerabilities to {file_path}")
        return pd.read_csv(file_path)
    except requests.RequestException as e:
        logger.error(f"Failed to download KEV data: {e}")
        return None
    except Exception as e:
        logger.error(f"Error processing KEV data: {e}")
        return None


@error_handler()
def load_known_exploited_vulnerabilities(
    file_path: str,
) -> pd.DataFrame | None:
    """
    Load known exploited vulnerabilities from a CSV file.

    Args:
        file_path: Path to the KEV CSV file

    Returns:
        DataFrame with KEV data or None if load failed
    """
    try:
        logger.debug(f"Loading KEV data from {file_path}")
        return pd.read_csv(file_path)
    except Exception as e:
        logger.error(f"Error loading KEV data from {file_path}: {e}")
        return None
