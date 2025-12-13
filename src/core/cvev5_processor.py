"""CVE v5 data processing module from GitHub."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import requests

from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# GitHub API endpoint for CVE v5 releases
GITHUB_API_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
GITHUB_RELEASES_URL = "https://github.com/CVEProject/cvelistV5/releases/download"


@error_handler()
def download_cvev5_cve_data(start_year: int, end_year: int, directory: str) -> None:
    """Download CVE v5 data from GitHub for a given range of years.

    Args:
        start_year: Starting year (inclusive)
        end_year: Ending year (inclusive)
        directory: Directory to save downloaded files

    """
    base_path = Path(directory)
    cve_dir = base_path / "CVEV5"
    cve_dir.mkdir(parents=True, exist_ok=True)

    # Check if today's zip file already exists
    today = datetime.now().strftime("%Y-%m-%d")
    today_zip = cve_dir / f"{today}_all_CVEs_at_midnight.zip"

    if today_zip.exists():
        logger.info(
            f"CVE v5 data for today already exists at {today_zip}, skipping download.",
        )
        return

    # Get the latest release with all CVEs
    try:
        logger.info("Checking GitHub for latest CVE v5 release...")
        response = requests.get(GITHUB_API_URL, timeout=30)
        response.raise_for_status()
        releases = response.json()

        if not releases:
            logger.error("No releases found in CVE v5 repository")
            return

        # Find the latest baseline release (all_CVEs_at_midnight)
        latest_baseline = None
        for release in releases:
            for asset in release.get("assets", []):
                if "all_CVEs_at_midnight" in asset["name"]:
                    latest_baseline = asset
                    break
            if latest_baseline:
                break

        if not latest_baseline:
            logger.error("No baseline CVE release found")
            return

        file_path = cve_dir / latest_baseline["name"]

        # Skip if already downloaded
        if file_path.exists():
            logger.info(f"CVE v5 zip already exists at {file_path}, skipping download.")
            return

        logger.info(f"Downloading CVE v5 data: {latest_baseline['name']}")
        download_url = latest_baseline["browser_download_url"]

        response = requests.get(download_url, timeout=60)
        response.raise_for_status()

        with open(file_path, "wb") as f:
            f.write(response.content)
        logger.info(f"Downloaded {file_path}")

    except requests.RequestException as e:
        logger.error(f"Failed to download CVE v5 data: {e}")


@error_handler()
def unzip_files(directory: str) -> None:
    """Unzip all found files in the CVEV5 directory.

    Args:
        directory: Base directory containing CVEV5 folder

    """
    import zipfile

    cve_dir = Path(directory) / "CVEV5"

    for file_path in cve_dir.glob("*.zip"):
        try:
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                zip_ref.extractall(cve_dir)
            logger.info(f"Unzipped {file_path}")
            file_path.unlink()
        except Exception as e:
            logger.error(f"Failed to unzip {file_path}: {e}")


@error_handler()
def load_cvev5_cve_data(
    start_year: int,
    end_year: int,
    directory: str,
    cve_ids: list[str] = None,
) -> pd.DataFrame:
    """Load CVE v5 data into a DataFrame with optimized filtering.

    Args:
        start_year: Start year for CVE data
        end_year: End year for CVE data
        directory: Directory containing CVE data
        cve_ids: Optional list of specific CVE IDs to load

    Returns:
        DataFrame with CVE data

    """
    # Import config here to avoid circular imports
    try:
        from src.utils.config import get_config

        config = get_config()
        max_files = config.max_cve_files
    except (ImportError, AttributeError) as e:
        logger.debug(f"Failed to load config: {e}, using default max_files=5000")
        max_files = 5000  # Default fallback

    logger.info(f"Loading CVE v5 data for years {start_year}-{end_year}")

    cve_dir = Path(directory) / "CVEV5" / "cves"
    if not cve_dir.exists():
        logger.error(f"CVE directory not found: {cve_dir}")
        return pd.DataFrame()

    # If specific CVE IDs requested, load only those
    if cve_ids:
        return _load_specific_cves(cve_dir, cve_ids)

    # Collect JSON files with year filtering
    json_files = []
    for year in range(start_year, end_year + 1):
        year_dir = cve_dir / str(year)
        if year_dir.exists():
            json_files.extend(year_dir.rglob("CVE-*.json"))

    logger.info(
        f"Found {len(json_files)} CVE JSON files for years {start_year}-{end_year}",
    )

    if not json_files:
        return pd.DataFrame()

    # Apply processing limit
    if len(json_files) > max_files:
        logger.info(f"Limiting processing to {max_files} files")
        json_files = json_files[:max_files]

    # Process files with progress tracking
    data = []
    processed_count = 0
    skipped_count = 0
    total_files = len(json_files)

    for file_path in json_files:
        try:
            cve_data = _process_cve_file(file_path)
            if cve_data:
                data.append(cve_data)
                processed_count += 1

            # Progress logging
            if processed_count % 1000 == 0:
                logger.info(f"Processed {processed_count}/{total_files} files")

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            skipped_count += 1

    logger.info(
        f"CVE loading complete: {processed_count} processed, {skipped_count} skipped, {total_files} total",
    )

    if data:
        logger.info(f"Creating DataFrame with {len(data)} CVE records...")
        df = pd.DataFrame(data)

        # Optimize data types
        numeric_columns = [
            "cvss_v4_0_score",
            "cvss_v3_1_score",
            "cvss_v3_0_score",
            "cvss_v2_0_score",
        ]

        for col in numeric_columns:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce")

        logger.info(f"DataFrame created with shape {df.shape}")
        return df

    return pd.DataFrame()


def _load_specific_cves(cve_dir: Path, cve_ids: list[str]) -> pd.DataFrame:
    """Load specific CVEs by ID."""
    data = []

    for cve_id in cve_ids:
        # Construct path based on CVE ID format CVE-YYYY-NNNN
        try:
            parts = cve_id.split("-")
            if len(parts) >= 3 and parts[0] == "CVE":
                year = parts[1]
                # Find the file
                cve_file = cve_dir / year / f"{cve_id}.json"
                if cve_file.exists():
                    cve_data = _process_cve_file(cve_file)
                    if cve_data:
                        data.append(cve_data)
        except Exception as e:
            logger.error(f"Error loading {cve_id}: {e}")

    if data:
        return pd.DataFrame(data)
    return pd.DataFrame()


def _process_cve_file(file_path: Path) -> dict[str, Any] | None:
    """Process a single CVE JSON file.

    Args:
        file_path: Path to CVE JSON file

    Returns:
        Parsed CVE data or None if parsing fails

    """
    try:
        with open(file_path) as f:
            cve_record = json.load(f)

        return _parse_cve_v5_record(cve_record)
    except Exception as e:
        logger.error(f"Error processing {file_path}: {e}")
        return None


def _parse_cve_v5_record(cve_record: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a single CVE record from CVE v5 JSON format.

    Args:
        cve_record: CVE record from CVE v5 JSON

    Returns:
        Parsed CVE data or None if parsing fails

    """
    try:
        cve_id = cve_record.get("cveMetadata", {}).get("cveId", "")

        if not cve_id:
            return None

        # Extract description
        descriptions = (
            cve_record.get("containers", {}).get("cna", {}).get("descriptions", [])
        )
        description = descriptions[0].get("value", "") if descriptions else ""

        # Extract CWE
        problem_types = (
            cve_record.get("containers", {}).get("cna", {}).get("problemTypes", [])
        )
        cwe_id = ""
        if problem_types:
            descriptions_list = problem_types[0].get("descriptions", [])
            if descriptions_list:
                cwe_id = descriptions_list[0].get("cweId", "")

        # Extract dates
        published_date = cve_record.get("cveMetadata", {}).get("datePublished", "")
        last_modified_date = cve_record.get("cveMetadata", {}).get("dateUpdated", "")

        # Parse CVSS metrics from metrics container
        # CVE v5 can have multiple metric formats (cvssV4_0, cvssV3_1, cvssV3_0, cvssV2_0)
        # Process in explicit precedence order: v4.0 > v3.1 > v3.0 > v2.0
        metrics = cve_record.get("containers", {}).get("cna", {}).get("metrics", [])
        cvss_metrics = {}

        if metrics:
            # Define metric versions in precedence order
            metric_versions = [
                ("cvssV4_0", "cvss_v4_0"),
                ("cvssV3_1", "cvss_v3_1"),
                ("cvssV3_0", "cvss_v3_0"),
                ("cvssV2_0", "cvss_v2_0"),
            ]

            # Process each version in order, only adding if not already present
            for version_key, prefix in metric_versions:
                for metric in metrics:
                    if version_key in metric and f"{prefix}_score" not in cvss_metrics:
                        cvss_data = metric[version_key]
                        cvss_metrics.update(
                            {
                                f"{prefix}_score": cvss_data.get("baseScore"),
                                f"{prefix}_severity": cvss_data.get("baseSeverity"),
                                f"{prefix}_vector": cvss_data.get("vectorString"),
                            },
                        )
                        break  # Move to next version after finding this one

        return {
            "cve_id": cve_id,
            "description": description,
            "cwe_id": cwe_id,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
            **cvss_metrics,
        }
    except Exception as e:
        logger.warning(f"Failed to parse CVE v5 record: {e}")
        return None
