"""CWE (Common Weakness Enumeration) processing module."""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp
import requests

from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Semaphore for limiting concurrent API calls
CWE_SEMAPHORE = asyncio.Semaphore(4)


def _get_cwe_cache_file(data_dir: str) -> Path:
    """
    Get the CWE baseline cache file path for today.

    Args:
        data_dir: Data directory path

    Returns:
        Path to CWE baseline cache file
    """
    today = datetime.now().strftime("%Y-%m-%d")
    return Path(data_dir) / f"CWE_baseline_{today}.json"


def _load_cwe_cache(cache_file: Path) -> dict[str, Any]:
    """
    Load CWE cache from disk.

    Args:
        cache_file: Path to cache file

    Returns:
        Dictionary with cached CWE data or empty dict if not found
    """
    if not cache_file.exists():
        return {}

    try:
        with open(cache_file) as f:
            cache = json.load(f)
        logger.info(f"Loaded CWE cache from {cache_file} with {len(cache)} entries")
        return cache
    except Exception as e:
        logger.error(f"Failed to load CWE cache from {cache_file}: {e}")
        return {}


def _save_cwe_cache(cache_file: Path, cache: dict[str, Any]) -> None:
    """
    Save CWE cache to disk.

    Args:
        cache_file: Path to cache file
        cache: Dictionary with CWE data to save
    """
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w") as f:
            json.dump(cache, f, indent=2)
        logger.info(f"Saved CWE cache to {cache_file} with {len(cache)} entries")
    except Exception as e:
        logger.error(f"Failed to save CWE cache to {cache_file}: {e}")


def _list_to_csv(items: list[str] | None) -> str:
    """
    Convert a list of strings to a comma-separated string.

    Args:
        items: List of items to convert

    Returns:
        Comma-separated string or "not_found" if empty
    """
    if not items:
        return "not_found"
    return ", ".join(str(item).strip() for item in items if item)


async def _fetch_cwe_async(
    session: aiohttp.ClientSession, cwe_id: str
) -> dict[str, Any]:
    """
    Async fetch CWE data from MITRE API with semaphore.

    Args:
        session: aiohttp session
        cwe_id: CWE identifier (e.g., "CWE-79")

    Returns:
        Dictionary with CWE metadata
    """
    # Handle special cases
    if cwe_id in ["not_found", "NVD-CWE-noinfo", "NVD-CWE-Other"] or not cwe_id:
        return {
            "cwe_id": cwe_id,
            "cwe_name": "not_found",
            "cwe_desc": "not_found",
            "cwe_cc_scope": "not_found",
            "cwe_cc_impact": "not_found",
        }

    async with CWE_SEMAPHORE:
        try:
            # Extract CWE number from CWE-XXX format
            cwe_number = cwe_id.split("-")[1]
            url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_number}"

            async with session.get(url, timeout=30) as response:
                response.raise_for_status()
                cwe_data = await response.json()
            logger.debug(f"Fetched CWE data for {cwe_id}")

            # Check if CWE was found
            if isinstance(cwe_data, str) and "not found" in cwe_data:
                return {
                    "cwe_id": cwe_id,
                    "cwe_name": "not_found",
                    "cwe_desc": "not_found",
                    "cwe_cc_scope": "not_found",
                    "cwe_cc_impact": "not_found",
                }

            # Extract weakness data
            weaknesses = cwe_data.get("Weaknesses", [])
            if not weaknesses:
                return {
                    "cwe_id": cwe_id,
                    "cwe_name": "not_found",
                    "cwe_desc": "not_found",
                    "cwe_cc_scope": "not_found",
                    "cwe_cc_impact": "not_found",
                }

            weakness = weaknesses[0]

            # Extract CWE name
            cwe_name = weakness.get("Name", "not_found")

            # Extract CWE description
            cwe_description = weakness.get("Description", "not_found")

            # Extract common consequences
            common_consequences = weakness.get("CommonConsequences", [])
            if common_consequences:
                consequence = common_consequences[0]
                cwe_cc_impact = _list_to_csv(consequence.get("Impact"))
                cwe_cc_scope = _list_to_csv(consequence.get("Scope"))
            else:
                cwe_cc_impact = "not_found"
                cwe_cc_scope = "not_found"

            return {
                "cwe_id": cwe_id,
                "cwe_name": cwe_name,
                "cwe_desc": cwe_description,
                "cwe_cc_scope": cwe_cc_scope,
                "cwe_cc_impact": cwe_cc_impact,
            }

        except Exception as e:
            logger.error(f"Failed to fetch CWE data for {cwe_id}: {e}")
            return {
                "cwe_id": cwe_id,
                "cwe_name": "not_found",
                "cwe_desc": "not_found",
                "cwe_cc_scope": "not_found",
                "cwe_cc_impact": "not_found",
            }


def get_cwe_name_and_description(cwe_id: str) -> dict[str, Any]:
    """
    Get CWE name and description from MITRE CWE API (sync wrapper).

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")

    Returns:
        Dictionary with CWE metadata
    """
    # Handle special cases and NaN values
    import pandas as pd

    if (
        pd.isna(cwe_id)
        or not cwe_id
        or cwe_id in ["not_found", "NVD-CWE-noinfo", "NVD-CWE-Other"]
    ):
        return {
            "cwe_id": str(cwe_id) if not pd.isna(cwe_id) else "nan",
            "cwe_name": "not_found",
            "cwe_desc": "not_found",
            "cwe_cc_scope": "not_found",
            "cwe_cc_impact": "not_found",
        }

    try:
        # Ensure cwe_id is a string
        cwe_id = str(cwe_id).strip()

        # Extract CWE number from CWE-XXX format
        cwe_number = cwe_id.split("-")[1]
        url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_number}"

        response = requests.get(url, timeout=30)
        response.raise_for_status()
        cwe_data = response.json()

        # Check if CWE was found
        if isinstance(cwe_data, str) and "not found" in cwe_data:
            return {
                "cwe_id": cwe_id,
                "cwe_name": "not_found",
                "cwe_desc": "not_found",
                "cwe_cc_scope": "not_found",
                "cwe_cc_impact": "not_found",
            }

        # Extract weakness data
        weaknesses = cwe_data.get("Weaknesses", [])
        if not weaknesses:
            return {
                "cwe_id": cwe_id,
                "cwe_name": "not_found",
                "cwe_desc": "not_found",
                "cwe_cc_scope": "not_found",
                "cwe_cc_impact": "not_found",
            }

        weakness = weaknesses[0]

        # Extract CWE name
        cwe_name = weakness.get("Name", "not_found")

        # Extract CWE description
        cwe_description = weakness.get("Description", "not_found")

        # Extract common consequences
        common_consequences = weakness.get("CommonConsequences", [])
        if common_consequences:
            consequence = common_consequences[0]
            cwe_cc_impact = _list_to_csv(consequence.get("Impact"))
            cwe_cc_scope = _list_to_csv(consequence.get("Scope"))
        else:
            cwe_cc_impact = "not_found"
            cwe_cc_scope = "not_found"

        return {
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "cwe_desc": cwe_description,
            "cwe_cc_scope": cwe_cc_scope,
            "cwe_cc_impact": cwe_cc_impact,
        }

    except requests.RequestException as e:
        logger.error(f"Failed to fetch CWE data for {cwe_id}: {e}")
        return {
            "cwe_id": cwe_id,
            "cwe_name": "not_found",
            "cwe_desc": "not_found",
            "cwe_cc_scope": "not_found",
            "cwe_cc_impact": "not_found",
        }
    except Exception as e:
        logger.error(f"Error processing CWE data for {cwe_id}: {e}")
        return {
            "cwe_id": cwe_id,
            "cwe_name": "not_found",
            "cwe_desc": "not_found",
            "cwe_cc_scope": "not_found",
            "cwe_cc_impact": "not_found",
        }


@error_handler()
async def enrich_cwe_data_async(
    cwe_ids: list[str], data_dir: str
) -> dict[str, dict[str, Any]]:
    """
    Enrich CWE data asynchronously with disk caching.

    Args:
        cwe_ids: List of unique CWE IDs to enrich
        data_dir: Data directory for caching

    Returns:
        Dictionary mapping CWE ID to enriched data
    """
    cache_file = _get_cwe_cache_file(data_dir)
    cache = _load_cwe_cache(cache_file)

    # Find CWEs that need to be fetched
    cwe_ids_to_fetch = [cwe_id for cwe_id in cwe_ids if cwe_id not in cache]

    logger.info(
        f"CWE enrichment: {len(cache)} cached, {len(cwe_ids_to_fetch)} to fetch"
    )

    # Fetch missing CWEs asynchronously
    if cwe_ids_to_fetch:
        async with aiohttp.ClientSession() as session:
            tasks = [_fetch_cwe_async(session, cwe_id) for cwe_id in cwe_ids_to_fetch]
            results = await asyncio.gather(*tasks)

        # Update cache with new results
        for result in results:
            cache[result["cwe_id"]] = result

        # Save updated cache to disk
        _save_cwe_cache(cache_file, cache)

    # Return all requested CWE data
    return {cwe_id: cache.get(cwe_id, {}) for cwe_id in cwe_ids}
