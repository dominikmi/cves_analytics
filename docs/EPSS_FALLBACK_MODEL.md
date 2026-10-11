import re
from typing import Dict, Optional
import numpy as np

# CVSS exploitability weights (CVSS v3.1)
CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
}

# CWE category boosts (additive, 0-0.15)
CWE_BOOSTS = {
    "CWE-787": 0.15,  # Out-of-bounds Write (Memory Corruption)
    "CWE-125": 0.15,  # Out-of-bounds Read (Memory Corruption)
    "CWE-119": 0.15,  # Improper Restriction of Operations within Bounds of Memory Buffer
    "CWE-74": 0.12,   # Injection
    "CWE-89": 0.12,   # SQL Injection
    "CWE-20": 0.12,   # Improper Input Validation
    "CWE-16": 0.10,   # Configuration (e.g., default credentials)
    "CWE-287": 0.10,  # Improper Authentication
    "CWE-310": 0.05,  # Cryptographic Issues
    "CWE-200": 0.05,  # Information Exposure
}

def parse_cvss_vector(vector: str | None) -> Dict[str, str]:
    """Extract CVSS metrics from vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N')."""
    if not vector:
        return {}
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            key, value = part.split(":")
            metrics[key] = value
    return metrics

def calculate_exploitability_score(metrics: Dict[str, str]) -> float:
    """Calculate CVSS exploitability score (0-10)."""
    av = CVSS_WEIGHTS["AV"].get(metrics.get("AV", "P"), 0.2)
    ac = CVSS_WEIGHTS["AC"].get(metrics.get("AC", "H"), 0.44)
    pr = CVSS_WEIGHTS["PR"].get(metrics.get("PR", "H"), 0.27)
    ui = CVSS_WEIGHTS["UI"].get(metrics.get("UI", "R"), 0.62)
    return 8.22 * av * ac * pr * ui

def cvss_to_probability(exploitability_score: float) -> float:
    """Convert CVSS exploitability score to probability using logistic function."""
    k = 0.5  # Steepness
    x0 = 5.0  # Midpoint
    return 1.0 / (1.0 + np.exp(-k * (exploitability_score - x0)))
def get_cwe_boost(cwe_id: str | None) -> float:
    """Return CWE boost (default: 0.0)."""
    if not cwe_id:
        return 0.0
    for cwe, boost in CWE_BOOSTS.items():
        if cwe in cwe_id:
            return boost
    return 0.0

def kev_decay_factor(days_since_added: int) -> float:
    """Calculate temporal decay for KEV entries (0-1)."""
    if days_since_added <= 30:
        return 1.0
    elif days_since_added <= 90:
        return 0.9
    elif days_since_added <= 180:
        return 0.8
    else:
        return 0.7

def estimate_epss(
    cvss_vector: str | None = None,
    cwe_id: str | None = None,
    is_kev: bool = False,
    kev_days: int | None = None,
) -> float:
    """
    Estimate EPSS score for a CVE missing EPSS data.

    Args:
        cvss_vector: CVSS v3.1 vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N').
        cwe_id: CWE identifier (e.g., 'CWE-787').
        is_kev: Whether CVE is in CISA KEV.
        kev_days: Days since added to KEV (for temporal decay).

    Returns:
        Estimated EPSS score (0-1).
    """
    # Base score (conservative default)
    epss = 0.01

    # CVSS exploitability (logistic function)
    if cvss_vector:
        metrics = parse_cvss_vector(cvss_vector)
        exploitability = calculate_exploitability_score(metrics)
        epss += cvss_to_probability(exploitability) * 0.5  # Scale to 0-0.5

    # CWE category boost (additive)
    epss += get_cwe_boost(cwe_id)

    # KEV boost with temporal decay
    if is_kev:
        decay = kev_decay_factor(kev_days) if kev_days else 1.0
        epss = max(epss, 0.7 * decay)  # KEV overrides other factors
    # Cap and round
    epss = min(epss, 0.95)
    return round(epss, 2)