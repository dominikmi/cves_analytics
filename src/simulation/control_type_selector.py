"""Control Type Selector - Probabilistic Selection Logic.

This module provides functions to select control types based on:
- Security maturity level
- Industry sector
- Service exposure
- Random variation

The selection is probabilistic, meaning even mature organizations
may have some legacy implementations.
"""

from __future__ import annotations

import random
from typing import Any

from src.simulation.control_probabilities import (
    ENDPOINT_TYPE_PROBABILITIES,
    EXPOSURE_CONTROL_TYPE_MODIFIERS,
    FIREWALL_TYPE_PROBABILITIES,
    IDS_IPS_TYPE_PROBABILITIES,
    INDUSTRY_CONTROL_TYPE_MODIFIERS,
    MFA_TYPE_PROBABILITIES,
    PATCH_QUALITY_PROBABILITIES,
    SEGMENTATION_TYPE_PROBABILITIES,
    SIEM_MATURITY_PROBABILITIES,
    WAF_TYPE_PROBABILITIES,
)
from src.simulation.control_types import (
    EndpointProtectionType,
    FirewallType,
    IDSIPSType,
    MFAType,
    PatchManagementQuality,
    SegmentationType,
    SIEMMaturity,
    WAFType,
)


def _normalize_probabilities(probs: dict[Any, float]) -> dict[Any, float]:
    """Normalize probabilities to sum to 1.0."""
    total = sum(probs.values())
    if total == 0:
        return probs
    return {k: v / total for k, v in probs.items()}


def _apply_modifiers(
    base_probs: dict[Any, float],
    modifiers: Any,
) -> dict[Any, float]:
    """Apply modifier multipliers to base probabilities."""
    result = base_probs.copy()
    for control_type, multiplier in modifiers.items():
        if control_type in result:
            result[control_type] *= multiplier
    return result


def _select_from_distribution(probs: dict[Any, float]) -> Any:
    """Select a value from a probability distribution."""
    normalized = _normalize_probabilities(probs)
    choices = list(normalized.keys())
    weights = list(normalized.values())
    return random.choices(choices, weights=weights, k=1)[0]


def select_mfa_type(
    maturity: str,
    industry: str | None = None,
    exposure: str | None = None,
) -> MFAType:
    """Select MFA type based on maturity, industry, and exposure."""
    base_probs = MFA_TYPE_PROBABILITIES.get(maturity, MFA_TYPE_PROBABILITIES["defined"])

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get("mfa", {})
        base_probs = _apply_modifiers(base_probs, industry_mods)

    if exposure and exposure in EXPOSURE_CONTROL_TYPE_MODIFIERS:
        exposure_mods = EXPOSURE_CONTROL_TYPE_MODIFIERS[exposure].get("mfa", {})
        base_probs = _apply_modifiers(base_probs, exposure_mods)

    return _select_from_distribution(base_probs)


def select_firewall_type(
    maturity: str,
    industry: str | None = None,
    exposure: str | None = None,
) -> FirewallType:
    """Select firewall type based on maturity, industry, and exposure."""
    base_probs = FIREWALL_TYPE_PROBABILITIES.get(
        maturity, FIREWALL_TYPE_PROBABILITIES["defined"]
    )

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get("firewall", {})
        base_probs = _apply_modifiers(base_probs, industry_mods)

    if exposure and exposure in EXPOSURE_CONTROL_TYPE_MODIFIERS:
        exposure_mods = EXPOSURE_CONTROL_TYPE_MODIFIERS[exposure].get("firewall", {})
        base_probs = _apply_modifiers(base_probs, exposure_mods)

    return _select_from_distribution(base_probs)


def select_waf_type(
    maturity: str,
    industry: str | None = None,
    exposure: str | None = None,
) -> WAFType:
    """Select WAF type based on maturity, industry, and exposure."""
    base_probs = WAF_TYPE_PROBABILITIES.get(maturity, WAF_TYPE_PROBABILITIES["defined"])

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get("waf", {})
        base_probs = _apply_modifiers(base_probs, industry_mods)

    if exposure and exposure in EXPOSURE_CONTROL_TYPE_MODIFIERS:
        exposure_mods = EXPOSURE_CONTROL_TYPE_MODIFIERS[exposure].get("waf", {})
        base_probs = _apply_modifiers(base_probs, exposure_mods)

    return _select_from_distribution(base_probs)


def select_endpoint_type(
    maturity: str,
    industry: str | None = None,
) -> EndpointProtectionType:
    """Select endpoint protection type based on maturity and industry."""
    base_probs = ENDPOINT_TYPE_PROBABILITIES.get(
        maturity, ENDPOINT_TYPE_PROBABILITIES["defined"]
    )

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get("endpoint", {})
        base_probs = _apply_modifiers(base_probs, industry_mods)

    return _select_from_distribution(base_probs)


def select_segmentation_type(
    maturity: str,
    industry: str | None = None,
    exposure: str | None = None,
) -> SegmentationType:
    """Select segmentation type based on maturity, industry, and exposure."""
    base_probs = SEGMENTATION_TYPE_PROBABILITIES.get(
        maturity, SEGMENTATION_TYPE_PROBABILITIES["defined"]
    )

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get(
            "segmentation", {}
        )
        base_probs = _apply_modifiers(base_probs, industry_mods)

    if exposure and exposure in EXPOSURE_CONTROL_TYPE_MODIFIERS:
        exposure_mods = EXPOSURE_CONTROL_TYPE_MODIFIERS[exposure].get(
            "segmentation", {}
        )
        base_probs = _apply_modifiers(base_probs, exposure_mods)

    return _select_from_distribution(base_probs)


def select_ids_ips_type(
    maturity: str,
    industry: str | None = None,
) -> IDSIPSType:
    """Select IDS/IPS type based on maturity and industry."""
    base_probs = IDS_IPS_TYPE_PROBABILITIES.get(
        maturity, IDS_IPS_TYPE_PROBABILITIES["defined"]
    )

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get("ids_ips", {})
        base_probs = _apply_modifiers(base_probs, industry_mods)

    return _select_from_distribution(base_probs)


def select_siem_maturity(
    maturity: str,
    industry: str | None = None,
) -> SIEMMaturity:
    """Select SIEM maturity level based on organization maturity and industry."""
    base_probs = SIEM_MATURITY_PROBABILITIES.get(
        maturity, SIEM_MATURITY_PROBABILITIES["defined"]
    )

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get("siem", {})
        base_probs = _apply_modifiers(base_probs, industry_mods)

    return _select_from_distribution(base_probs)


def select_patch_quality(
    maturity: str,
    industry: str | None = None,
) -> PatchManagementQuality:
    """Select patch management quality based on maturity and industry."""
    base_probs = PATCH_QUALITY_PROBABILITIES.get(
        maturity, PATCH_QUALITY_PROBABILITIES["defined"]
    )

    if industry and industry in INDUSTRY_CONTROL_TYPE_MODIFIERS:
        industry_mods = INDUSTRY_CONTROL_TYPE_MODIFIERS[industry].get("patch", {})
        base_probs = _apply_modifiers(base_probs, industry_mods)

    return _select_from_distribution(base_probs)
