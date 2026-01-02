"""Control Type Enums and Effectiveness Mappings.

This module defines the different types/implementations of security controls
and their associated effectiveness levels (Likelihood Ratios).

Each control can have multiple implementation types with varying effectiveness:
- Basic/Legacy implementations: Lower effectiveness
- Standard implementations: Moderate effectiveness
- Advanced/Modern implementations: Higher effectiveness

The effectiveness values (LR) represent how much the control reduces exploitation
probability in Bayesian risk assessment.
"""

from __future__ import annotations

from enum import Enum


class MFAType(str, Enum):
    """Multi-Factor Authentication implementation types."""

    NONE = "none"
    SMS = "sms"  # SMS-based (weakest)
    AUTHENTICATOR_APP = "authenticator_app"  # TOTP/Google Authenticator
    PUSH_NOTIFICATION = "push_notification"  # Duo Push, Microsoft Authenticator
    FIDO2 = "fido2"  # Hardware keys, passkeys (strongest)


class FirewallType(str, Enum):
    """Firewall implementation types."""

    NONE = "none"
    BASIC = "basic"  # Basic packet filtering
    STATEFUL = "stateful"  # Stateful inspection
    NGFW = "next_gen"  # Next-gen with DPI
    NGFW_ADVANCED = "next_gen_advanced"  # NGFW + threat intel


class WAFType(str, Enum):
    """Web Application Firewall implementation types."""

    NONE = "none"
    BASIC = "basic"  # Basic rules
    MANAGED = "managed"  # Managed rule sets
    OWASP_CRS = "owasp_crs"  # OWASP Core Rule Set
    CUSTOM_TUNED = "custom_tuned"  # Custom + ML/behavioral


class EndpointProtectionType(str, Enum):
    """Endpoint protection implementation types."""

    NONE = "none"
    TRADITIONAL_AV = "traditional_av"  # Signature-based only
    BASIC_EDR = "basic_edr"  # Basic EDR
    ADVANCED_EDR = "advanced_edr"  # EDR with behavioral analysis
    XDR = "xdr"  # Extended Detection & Response


class SegmentationType(str, Enum):
    """Network segmentation implementation types."""

    NONE = "none"  # Flat network
    BASIC_VLAN = "basic_vlan"  # Basic VLANs
    VLAN_ACL = "vlan_with_acl"  # VLANs + ACLs
    MICRO_SEGMENTATION = "micro_seg"  # Micro-segmentation
    ZERO_TRUST = "zero_trust"  # Zero-trust architecture


class IDSIPSType(str, Enum):
    """IDS/IPS implementation types."""

    NONE = "none"
    IDS_ONLY = "ids_only"  # Detection only
    IPS_SIGNATURE = "ips_signature"  # Signature-based IPS
    IPS_BEHAVIORAL = "ips_behavioral"  # Behavioral analysis
    IPS_ML = "ips_ml"  # ML-based detection


class SIEMMaturity(str, Enum):
    """SIEM maturity levels."""

    NONE = "none"
    LOG_COLLECTION = "log_collection"  # Just collecting logs
    BASIC_CORRELATION = "basic_corr"  # Basic correlation rules
    ADVANCED_ANALYTICS = "advanced"  # Advanced analytics
    THREAT_HUNTING = "threat_hunting"  # Active threat hunting + SOAR


class PatchManagementQuality(str, Enum):
    """Patch management quality levels."""

    NONE = "none"  # No patching
    REACTIVE = "reactive"  # Only after incidents
    QUARTERLY = "quarterly"  # Quarterly cycle
    MONTHLY = "monthly"  # Monthly (Patch Tuesday)
    WEEKLY = "weekly"  # Weekly critical patches
    AUTOMATED = "automated"  # Automated with testing


# Effectiveness mappings (Likelihood Ratios)
# LR < 1.0 means the control reduces exploitation probability
# LR = 1.0 means no effect

MFA_EFFECTIVENESS = {
    MFAType.NONE: 1.0,
    MFAType.SMS: 0.35,  # 65% reduction (weak, vulnerable to SIM swap)
    MFAType.AUTHENTICATOR_APP: 0.15,  # 85% reduction
    MFAType.PUSH_NOTIFICATION: 0.15,  # 85% reduction
    MFAType.FIDO2: 0.05,  # 95% reduction (strongest)
}

FIREWALL_EFFECTIVENESS = {
    FirewallType.NONE: 1.0,
    FirewallType.BASIC: 0.7,  # 30% reduction
    FirewallType.STATEFUL: 0.5,  # 50% reduction
    FirewallType.NGFW: 0.4,  # 60% reduction
    FirewallType.NGFW_ADVANCED: 0.3,  # 70% reduction
}

WAF_EFFECTIVENESS = {
    WAFType.NONE: 1.0,
    WAFType.BASIC: 0.6,  # 40% reduction
    WAFType.MANAGED: 0.4,  # 60% reduction
    WAFType.OWASP_CRS: 0.3,  # 70% reduction
    WAFType.CUSTOM_TUNED: 0.25,  # 75% reduction
}

ENDPOINT_EFFECTIVENESS = {
    EndpointProtectionType.NONE: 1.0,
    EndpointProtectionType.TRADITIONAL_AV: 0.7,  # 30% reduction
    EndpointProtectionType.BASIC_EDR: 0.5,  # 50% reduction
    EndpointProtectionType.ADVANCED_EDR: 0.4,  # 60% reduction
    EndpointProtectionType.XDR: 0.3,  # 70% reduction
}

SEGMENTATION_EFFECTIVENESS = {
    SegmentationType.NONE: 1.0,
    SegmentationType.BASIC_VLAN: 0.7,  # 30% reduction
    SegmentationType.VLAN_ACL: 0.5,  # 50% reduction
    SegmentationType.MICRO_SEGMENTATION: 0.3,  # 70% reduction
    SegmentationType.ZERO_TRUST: 0.2,  # 80% reduction
}

IDS_IPS_EFFECTIVENESS = {
    IDSIPSType.NONE: 1.0,
    IDSIPSType.IDS_ONLY: 0.8,  # 20% reduction (detection only)
    IDSIPSType.IPS_SIGNATURE: 0.5,  # 50% reduction
    IDSIPSType.IPS_BEHAVIORAL: 0.4,  # 60% reduction
    IDSIPSType.IPS_ML: 0.35,  # 65% reduction
}

SIEM_EFFECTIVENESS = {
    SIEMMaturity.NONE: 1.0,
    SIEMMaturity.LOG_COLLECTION: 0.8,  # 20% reduction
    SIEMMaturity.BASIC_CORRELATION: 0.6,  # 40% reduction
    SIEMMaturity.ADVANCED_ANALYTICS: 0.5,  # 50% reduction
    SIEMMaturity.THREAT_HUNTING: 0.4,  # 60% reduction
}

PATCH_EFFECTIVENESS = {
    PatchManagementQuality.NONE: 1.0,
    PatchManagementQuality.REACTIVE: 0.9,  # 10% reduction
    PatchManagementQuality.QUARTERLY: 0.7,  # 30% reduction
    PatchManagementQuality.MONTHLY: 0.4,  # 60% reduction
    PatchManagementQuality.WEEKLY: 0.3,  # 70% reduction
    PatchManagementQuality.AUTOMATED: 0.2,  # 80% reduction
}
