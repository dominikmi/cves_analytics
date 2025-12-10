"""Vulnerability enrichment processing module (CISAGOV vulnrichment)."""

import json
from pathlib import Path
from typing import Any

import pandas as pd

from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


def _get_metric_position_of_other(metrics_list: list[dict[str, Any]]) -> int | None:
    """
    Find the position in metrics list where "other" key exists.

    Args:
        metrics_list: List of metric dictionaries

    Returns:
        Index of the metric with "other" key, or None if not found
    """
    for i, metric in enumerate(metrics_list):
        if "other" in metric:
            return i
    return None


def _flatten_vulnrichment_output(
    vulnrichment_output: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """
    Flatten vulnrichment output from list of dicts to single dict.

    Args:
        vulnrichment_output: List of dictionaries to flatten

    Returns:
        Flattened dictionary or None if input is None
    """
    if vulnrichment_output is None:
        return None

    flattened = {}
    for item in vulnrichment_output:
        if isinstance(item, dict):
            flattened.update(item)
        else:
            return None

    return flattened


@error_handler()
def get_cve_vulnrichment(cve_id: str) -> list[dict[str, Any]] | None:
    """
    Get vulnerability enrichment data for a CVE from CISAGOV repository.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-1234")

    Returns:
        List of enrichment options or default list if not found
    """
    logger.debug(f"Processing cve_id -> {cve_id}")

    directory = "data/download/vulnrichment"
    year = cve_id.split("-")[1]
    number = int(cve_id.split("-")[2])

    # Calculate folder name (e.g., "1xxx" for CVE-2021-1234)
    thousands_group = f"{(number // 1000)}xxx"
    cve_dir = Path(directory) / year / thousands_group
    file_path = cve_dir / f"{cve_id}.json"

    logger.debug(f"File path: {file_path}")

    # Default response for not found or rejected CVEs
    default_response = [
        {"Exploitation": None},
        {"Automatable": None},
        {"Technical Impact": None},
    ]

    if not file_path.exists():
        logger.debug(f"Vulnrichment file not found: {file_path}")
        return default_response

    try:
        logger.debug(f"Processing data in {file_path}")
        with open(file_path) as f:
            cve_data = json.load(f)

        # Check if CVE is rejected
        if cve_data.get("cveMetadata", {}).get("state") == "REJECTED":
            return default_response

        # Extract ADP list
        containers = cve_data.get("containers", {})
        adp_list = containers.get("adp", [])

        if not adp_list:
            return default_response

        # Find CISA ADP Vulnrichment entry
        adp_position = None
        for i, item in enumerate(adp_list):
            if "CISA ADP Vulnrichment" in item.get("title", ""):
                adp_position = i
                break

        if adp_position is None:
            return default_response

        # Extract metrics
        metrics = adp_list[adp_position].get("metrics", {})
        position = _get_metric_position_of_other(metrics)

        if position is None:
            return default_response

        # Extract options
        options = metrics[position].get("other", {}).get("content", {}).get("options")
        return options if options else default_response

    except Exception as e:
        logger.error(f"Error processing vulnrichment for {cve_id}: {e}")
        return default_response


@error_handler()
def update_row_with_vulnrichment_details(
    row: pd.Series,
) -> pd.Series:
    """
    Update a DataFrame row with vulnerability enrichment details.

    Args:
        row: DataFrame row to update

    Returns:
        Updated row with enrichment details
    """
    cve_id = row.get("cve_id")
    if not cve_id:
        return row

    enrichment_data = get_cve_vulnrichment(cve_id)
    details = _flatten_vulnrichment_output(enrichment_data)

    if details:
        for key, value in details.items():
            row[key] = value

    return row
