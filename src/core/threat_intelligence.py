"""Threat intelligence module for vulnerability assessment."""

import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


def extract_threat_indicators_from_nvd(cve_data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract threat indicators from NVD CVE data.

    Parses NVD references to identify:
    - Public exploit availability
    - Metasploit module existence
    - Vendor advisories
    - Threat keywords

    Args:
        cve_data: CVE data dictionary from NVD API

    Returns:
        Dictionary with threat indicators
    """
    indicators = {
        "has_exploit_poc": False,
        "has_metasploit": False,
        "has_vendor_advisory": False,
        "exploit_references": [],
        "threat_keywords": [],
        "reference_count": 0,
    }

    references = cve_data.get("references", [])
    indicators["reference_count"] = len(references)

    for ref in references:
        url = ref.get("url", "").lower()

        # Check for exploit indicators
        if any(x in url for x in ["exploit", "poc", "proof", "github.com/exploit"]):
            indicators["has_exploit_poc"] = True
            indicators["exploit_references"].append(url)

        if "metasploit" in url:
            indicators["has_metasploit"] = True
            indicators["exploit_references"].append(url)

        if any(x in url for x in ["advisory", "security-update", "patch", "release"]):
            indicators["has_vendor_advisory"] = True

    # Extract threat keywords from description
    description = ""
    if "descriptions" in cve_data and cve_data["descriptions"]:
        description = cve_data["descriptions"][0].get("value", "").lower()

    threat_keywords = [
        "ransomware",
        "worm",
        "trojan",
        "backdoor",
        "remote code execution",
        "privilege escalation",
        "buffer overflow",
        "injection",
        "authentication bypass",
    ]

    for keyword in threat_keywords:
        if keyword in description:
            indicators["threat_keywords"].append(keyword)

    return indicators


def add_threat_indicators(enriched_results: pd.DataFrame) -> pd.DataFrame:
    """
    Add threat indicators to enriched results.

    Args:
        enriched_results: DataFrame with vulnerability data

    Returns:
        DataFrame with added threat indicator columns
    """
    if enriched_results.empty:
        return enriched_results

    try:
        # Initialize columns
        enriched_results["has_exploit_poc"] = False
        enriched_results["has_metasploit"] = False
        enriched_results["threat_score"] = 0.0

        # Set KEV flag if available
        if "is_kev" not in enriched_results.columns:
            enriched_results["is_kev"] = False

        logger.info("Added threat indicator columns to enriched results")

    except Exception as e:
        logger.error(f"Failed to add threat indicators: {e}")

    return enriched_results


def calculate_threat_score(row: dict[str, Any]) -> float:
    """
    Calculate threat score for a vulnerability.

    Combines:
    - KEV status (in CISA Known Exploited Vulnerabilities)
    - Exploit availability
    - EPSS score (exploitation probability)

    Args:
        row: Dictionary with vulnerability data

    Returns:
        Threat score (0-10)
    """
    score = 0.0

    # KEV status (highest priority)
    if row.get("is_kev", False):
        score += 5.0

    # Exploit availability
    if row.get("has_exploit_poc", False):
        score += 2.0

    if row.get("has_metasploit", False):
        score += 1.5

    # EPSS score (exploitation probability)
    epss = row.get("epss_score", 0.0)
    if epss:
        score += epss * 1.5  # Max 1.5 points

    # Normalize to 0-10
    threat_score = min(10.0, score)

    return round(threat_score, 2)


def categorize_by_threat(enriched_results: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """
    Categorize vulnerabilities by threat level.

    Args:
        enriched_results: DataFrame with threat data

    Returns:
        Dictionary with threat categories
    """
    if enriched_results.empty:
        return {
            "active_exploitation": pd.DataFrame(),
            "exploit_available": pd.DataFrame(),
            "monitored": pd.DataFrame(),
        }

    return {
        "active_exploitation": enriched_results[enriched_results.get("is_kev", False)],
        "exploit_available": enriched_results[
            enriched_results.get("has_exploit_poc", False)
        ],
        "monitored": enriched_results[enriched_results.get("has_metasploit", False)],
    }


def get_threat_summary(enriched_results: pd.DataFrame) -> dict[str, Any]:
    """
    Get summary of threat intelligence.

    Args:
        enriched_results: DataFrame with vulnerability data

    Returns:
        Dictionary with threat summary
    """
    if enriched_results.empty:
        return {
            "kev_count": 0,
            "exploit_poc_count": 0,
            "metasploit_count": 0,
            "high_epss_count": 0,
        }

    return {
        "kev_count": enriched_results.get("is_kev", False).sum()
        if "is_kev" in enriched_results.columns
        else 0,
        "exploit_poc_count": enriched_results.get("has_exploit_poc", False).sum()
        if "has_exploit_poc" in enriched_results.columns
        else 0,
        "metasploit_count": enriched_results.get("has_metasploit", False).sum()
        if "has_metasploit" in enriched_results.columns
        else 0,
        "high_epss_count": (enriched_results.get("epss_score", 0) >= 0.5).sum()
        if "epss_score" in enriched_results.columns
        else 0,
        "total_vulns": len(enriched_results),
    }
