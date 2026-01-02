"""Control Type to Likelihood Ratio Mapper.

This module maps security control types to their effectiveness values (LR)
for use in Bayesian risk assessment.
"""

from __future__ import annotations

from typing import Any

from src.simulation.control_types import (
    ENDPOINT_EFFECTIVENESS,
    FIREWALL_EFFECTIVENESS,
    IDS_IPS_EFFECTIVENESS,
    MFA_EFFECTIVENESS,
    PATCH_EFFECTIVENESS,
    SEGMENTATION_EFFECTIVENESS,
    SIEM_EFFECTIVENESS,
    WAF_EFFECTIVENESS,
    EndpointProtectionType,
    FirewallType,
    IDSIPSType,
    MFAType,
    PatchManagementQuality,
    SegmentationType,
    SIEMMaturity,
    WAFType,
)


def get_control_lr_from_security_controls(
    security_controls: dict[str, Any],
) -> dict[str, float]:
    """Extract LR values from security controls dictionary.

    Args:
        security_controls: Dictionary with control types

    Returns:
        Dictionary mapping control names to LR values
    """
    lr_values = {}

    # MFA
    mfa_type = security_controls.get("mfa_type")
    if mfa_type and mfa_type != "none":
        if isinstance(mfa_type, str):
            mfa_type = MFAType(mfa_type)
        lr_values["mfa"] = MFA_EFFECTIVENESS.get(mfa_type, 1.0)

    # Firewall
    firewall_type = security_controls.get("firewall_type")
    if firewall_type and firewall_type != "none":
        if isinstance(firewall_type, str):
            firewall_type = FirewallType(firewall_type)
        lr_values["firewall"] = FIREWALL_EFFECTIVENESS.get(firewall_type, 1.0)

    # WAF
    waf_type = security_controls.get("waf_type")
    if waf_type and waf_type != "none":
        if isinstance(waf_type, str):
            waf_type = WAFType(waf_type)
        lr_values["waf"] = WAF_EFFECTIVENESS.get(waf_type, 1.0)

    # Segmentation
    segmentation_type = security_controls.get("segmentation_type")
    if segmentation_type and segmentation_type != "none":
        if isinstance(segmentation_type, str):
            segmentation_type = SegmentationType(segmentation_type)
        lr_values["network_segmentation"] = SEGMENTATION_EFFECTIVENESS.get(
            segmentation_type, 1.0
        )

    # IDS/IPS
    ids_ips_type = security_controls.get("ids_ips_type")
    if ids_ips_type and ids_ips_type != "none":
        if isinstance(ids_ips_type, str):
            ids_ips_type = IDSIPSType(ids_ips_type)
        lr_values["ids_ips"] = IDS_IPS_EFFECTIVENESS.get(ids_ips_type, 1.0)

    # Endpoint Protection
    endpoint_type = security_controls.get("endpoint_protection_type")
    if endpoint_type and endpoint_type != "none":
        if isinstance(endpoint_type, str):
            endpoint_type = EndpointProtectionType(endpoint_type)
        lr_values["edr_xdr"] = ENDPOINT_EFFECTIVENESS.get(endpoint_type, 1.0)

    # SIEM
    siem_maturity = security_controls.get("siem_maturity")
    if siem_maturity and siem_maturity != "none":
        if isinstance(siem_maturity, str):
            siem_maturity = SIEMMaturity(siem_maturity)
        lr_values["siem"] = SIEM_EFFECTIVENESS.get(siem_maturity, 1.0)

    # Patch Management
    patch_quality = security_controls.get("patch_management_quality")
    if patch_quality and patch_quality != "none":
        if isinstance(patch_quality, str):
            patch_quality = PatchManagementQuality(patch_quality)
        lr_values["patch_management"] = PATCH_EFFECTIVENESS.get(patch_quality, 1.0)

    # Boolean controls (unchanged)
    if security_controls.get("privileged_access_mgmt"):
        lr_values["privileged_access_mgmt"] = 0.4

    if security_controls.get("soc_24x7"):
        lr_values["soc_24x7"] = 0.5

    if security_controls.get("incident_response_plan"):
        lr_values["incident_response_plan"] = 0.7

    if security_controls.get("security_training"):
        lr_values["security_training"] = 0.8

    if security_controls.get("air_gapped"):
        lr_values["air_gapped"] = 0.1

    return lr_values
