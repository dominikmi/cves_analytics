"""Control Type Enums and Effectiveness Mappings."""

from enum import StrEnum


class MFAType(StrEnum):
    """Multi-Factor Authentication implementation types."""

    NONE = "none"
    SMS = "sms"
    AUTHENTICATOR_APP = "authenticator_app"
    PUSH_NOTIFICATION = "push_notification"
    FIDO2 = "fido2"


class FirewallType(StrEnum):
    """Firewall implementation types."""

    NONE = "none"
    BASIC = "basic"
    STATEFUL = "stateful"
    NGFW = "next_gen"
    NGFW_ADVANCED = "next_gen_advanced"


class WAFType(StrEnum):
    """Web Application Firewall implementation types."""

    NONE = "none"
    BASIC = "basic"
    MANAGED = "managed"
    OWASP_CRS = "owasp_crs"
    CUSTOM_TUNED = "custom_tuned"


class EndpointProtectionType(StrEnum):
    """Endpoint protection implementation types."""

    NONE = "none"
    TRADITIONAL_AV = "traditional_av"
    BASIC_EDR = "basic_edr"
    ADVANCED_EDR = "advanced_edr"
    XDR = "xdr"


class SegmentationType(StrEnum):
    """Network segmentation implementation types."""

    NONE = "none"
    BASIC_VLAN = "basic_vlan"
    VLAN_ACL = "vlan_with_acl"
    MICRO_SEGMENTATION = "micro_seg"
    ZERO_TRUST = "zero_trust"


class IDSIPSType(StrEnum):
    """IDS/IPS implementation types."""

    NONE = "none"
    IDS_ONLY = "ids_only"
    IPS_SIGNATURE = "ips_signature"
    IPS_BEHAVIORAL = "ips_behavioral"
    IPS_ML = "ips_ml"


class SIEMMaturity(StrEnum):
    """SIEM maturity levels."""

    NONE = "none"
    LOG_COLLECTION = "log_collection"
    BASIC_CORRELATION = "basic_corr"
    ADVANCED_ANALYTICS = "advanced"
    THREAT_HUNTING = "threat_hunting"


class PatchManagementQuality(StrEnum):
    """Patch management quality levels."""

    NONE = "none"
    REACTIVE = "reactive"
    QUARTERLY = "quarterly"
    MONTHLY = "monthly"
    WEEKLY = "weekly"
    AUTOMATED = "automated"


# Effectiveness mappings (Likelihood Ratios)
MFA_EFFECTIVENESS = {
    MFAType.NONE: 1.0,
    MFAType.SMS: 0.35,
    MFAType.AUTHENTICATOR_APP: 0.15,
    MFAType.PUSH_NOTIFICATION: 0.15,
    MFAType.FIDO2: 0.05,
}

FIREWALL_EFFECTIVENESS = {
    FirewallType.NONE: 1.0,
    FirewallType.BASIC: 0.7,
    FirewallType.STATEFUL: 0.5,
    FirewallType.NGFW: 0.4,
    FirewallType.NGFW_ADVANCED: 0.3,
}

WAF_EFFECTIVENESS = {
    WAFType.NONE: 1.0,
    WAFType.BASIC: 0.6,
    WAFType.MANAGED: 0.4,
    WAFType.OWASP_CRS: 0.3,
    WAFType.CUSTOM_TUNED: 0.25,
}

ENDPOINT_EFFECTIVENESS = {
    EndpointProtectionType.NONE: 1.0,
    EndpointProtectionType.TRADITIONAL_AV: 0.7,
    EndpointProtectionType.BASIC_EDR: 0.5,
    EndpointProtectionType.ADVANCED_EDR: 0.4,
    EndpointProtectionType.XDR: 0.3,
}

SEGMENTATION_EFFECTIVENESS = {
    SegmentationType.NONE: 1.0,
    SegmentationType.BASIC_VLAN: 0.7,
    SegmentationType.VLAN_ACL: 0.5,
    SegmentationType.MICRO_SEGMENTATION: 0.3,
    SegmentationType.ZERO_TRUST: 0.2,
}

IDS_IPS_EFFECTIVENESS = {
    IDSIPSType.NONE: 1.0,
    IDSIPSType.IDS_ONLY: 0.8,
    IDSIPSType.IPS_SIGNATURE: 0.5,
    IDSIPSType.IPS_BEHAVIORAL: 0.4,
    IDSIPSType.IPS_ML: 0.35,
}

SIEM_EFFECTIVENESS = {
    SIEMMaturity.NONE: 1.0,
    SIEMMaturity.LOG_COLLECTION: 0.8,
    SIEMMaturity.BASIC_CORRELATION: 0.6,
    SIEMMaturity.ADVANCED_ANALYTICS: 0.5,
    SIEMMaturity.THREAT_HUNTING: 0.4,
}

PATCH_EFFECTIVENESS = {
    PatchManagementQuality.NONE: 1.0,
    PatchManagementQuality.REACTIVE: 0.9,
    PatchManagementQuality.QUARTERLY: 0.7,
    PatchManagementQuality.MONTHLY: 0.4,
    PatchManagementQuality.WEEKLY: 0.3,
    PatchManagementQuality.AUTOMATED: 0.2,
}
