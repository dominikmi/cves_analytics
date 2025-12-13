"""EPSS score processing module."""

import asyncio
import gzip
from datetime import datetime, timedelta
from pathlib import Path

import aiohttp
import pandas as pd
import requests
from dateutil import relativedelta

from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


@error_handler()
def download_epss_scores(date: str, directory: str) -> str | None:
    """Download EPSS scores for a given date and ungzip it.

    Args:
        date: Date string in format "YYYY-MM-DD"
        directory: Directory to save the file

    Returns:
        Path to unzipped file or None if download failed

    """
    # Ensure directory ends with /EPSS
    dir_path = Path(directory)
    if dir_path.name != "EPSS":
        dir_path = dir_path / "EPSS"

    dir_path.mkdir(parents=True, exist_ok=True)

    # Download for yesterday (EPSS publishes data with 1-day delay)
    yesterday = (datetime.strptime(date, "%Y-%m-%d") - timedelta(days=1)).strftime(
        "%Y-%m-%d",
    )
    file_path = dir_path / f"epss_scores-{yesterday}.csv.gz"
    unzipped_path = file_path.with_suffix("")

    try:
        # Check if unzipped file already exists
        if unzipped_path.exists():
            logger.info(
                f"EPSS scores already exist at {unzipped_path}, skipping download",
            )
            return str(unzipped_path)

        # Check if gzipped file exists, if so just ungzip it
        if file_path.exists():
            logger.info(f"EPSS gzipped file exists at {file_path}, unzipping...")
        else:
            logger.info(f"Downloading EPSS scores for date {yesterday}")
            url = f"https://epss.empiricalsecurity.com/epss_scores-{yesterday}.csv.gz"
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            with open(file_path, "wb") as f:
                f.write(response.content)
            logger.info(f"Downloaded {file_path}")

        # Ungzip the file
        logger.info(f"Unzipping {file_path}")
        with gzip.open(file_path, "rb") as f_in:
            with open(unzipped_path, "wb") as f_out:
                f_out.write(f_in.read())

        return str(unzipped_path)
    except requests.RequestException as e:
        logger.error(f"Failed to download EPSS scores for date {date}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error processing EPSS file: {e}")
        return None


@error_handler()
async def _download_epss_async(
    session: aiohttp.ClientSession,
    date: str,
    directory: str,
) -> str | None:
    """Async helper to download a single EPSS file.

    Args:
        session: aiohttp session
        date: Date string in format "YYYY-MM-DD"
        directory: Directory to save the file

    Returns:
        Path to downloaded file or None if failed

    """
    dir_path = Path(directory) / "EPSS"
    dir_path.mkdir(parents=True, exist_ok=True)

    yesterday = (datetime.strptime(date, "%Y-%m-%d") - timedelta(days=1)).strftime(
        "%Y-%m-%d",
    )
    file_path = dir_path / f"epss_scores-{yesterday}.csv.gz"
    unzipped_path = file_path.with_suffix("")

    try:
        if unzipped_path.exists():
            return str(unzipped_path)

        if file_path.exists():
            logger.info("EPSS gzipped file exists, unzipping...")
        else:
            url = f"https://epss.empiricalsecurity.com/epss_scores-{yesterday}.csv.gz"
            async with session.get(url, timeout=30) as response:
                response.raise_for_status()
                with open(file_path, "wb") as f:
                    f.write(await response.read())
            logger.info(f"Downloaded {file_path}")

        with gzip.open(file_path, "rb") as f_in:
            with open(unzipped_path, "wb") as f_out:
                f_out.write(f_in.read())

        return str(unzipped_path)
    except Exception as e:
        logger.error(f"Failed to download EPSS scores for date {date}: {e}")
        return None


@error_handler()
def download_epss_scores_for_months(months: int, directory: str) -> list[str]:
    """Download EPSS scores for a given number of months back from today (async).

    Args:
        months: Number of months to go back
        directory: Directory to save the files

    Returns:
        List of downloaded file paths

    """
    today_date = datetime.now().strftime("%Y-%m-%d")
    dir_path = Path(directory) / "EPSS"
    dir_path.mkdir(parents=True, exist_ok=True)

    # Generate dates for all months
    dates = []
    for i in range(months):
        date = (
            datetime.strptime(today_date, "%Y-%m-%d").replace(day=1)
            - relativedelta.relativedelta(months=i)
        ).strftime("%Y-%m-%d")
        dates.append(date)

    # Download in parallel using async
    async def download_all():
        async with aiohttp.ClientSession() as session:
            tasks = [_download_epss_async(session, date, directory) for date in dates]
            return await asyncio.gather(*tasks)

    try:
        file_paths = asyncio.run(download_all())
    except Exception as e:
        logger.error(f"Failed to download EPSS scores in parallel: {e}")
        # Fallback to sequential download
        file_paths = [download_epss_scores(date, directory) for date in dates]

    files = []
    for file_path in file_paths:
        if file_path:
            try:
                epss_scores = pd.read_csv(file_path, skiprows=1)
                output_path = dir_path / f"epss_scores-{Path(file_path).stem}.csv"
                epss_scores.to_csv(output_path, index=False)
                files.append(str(output_path))
            except Exception as e:
                logger.error(f"Failed to process EPSS file {file_path}: {e}")

    logger.info(f"Downloaded {len(files)} EPSS files")
    return files


@error_handler()
def epss_time_machine(number: int, directory: str, unit: str = "months") -> list[str]:
    """Download EPSS scores for a given number of months or days back from today.

    Args:
        number: Number of time units to go back
        directory: Directory to save the files
        unit: Time unit to use ('months' or 'days')

    Returns:
        List of downloaded file paths

    """
    dir_path = Path(directory) / "EPSS"
    dir_path.mkdir(parents=True, exist_ok=True)

    today_date = datetime.now().strftime("%Y-%m-%d")
    files = []

    for i in range(number):
        date = datetime.strptime(today_date, "%Y-%m-%d")

        if unit == "months":
            # For months, set to 1st of month and subtract months
            date = date.replace(day=1)
            date = date - relativedelta.relativedelta(months=i)
        else:
            # For days, just subtract days
            date = date - timedelta(days=i)

        date_str = date.strftime("%Y-%m-%d")
        file_path = download_epss_scores(date_str, str(dir_path.parent))

        if file_path:
            files.append(file_path)

    return files
