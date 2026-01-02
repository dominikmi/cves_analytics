"""Control Type Probability Distributions.

This module defines probability distributions for different control types
based on security maturity level, industry, and exposure context.

The probabilities represent realistic adoption patterns where:
- Lower maturity = more basic/legacy implementations
- Higher maturity = more advanced implementations
- Industry modifiers adjust probabilities based on sector characteristics
- Exposure modifiers adjust based on service exposure (internet-facing vs internal)
"""

from __future__ import annotations

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

# Base probability distributions by maturity level
# Each dict maps control type to probability (must sum to 1.0)

MFA_TYPE_PROBABILITIES = {
    "initial": {
        MFAType.NONE: 0.70,
        MFAType.SMS: 0.25,
        MFAType.AUTHENTICATOR_APP: 0.05,
        MFAType.PUSH_NOTIFICATION: 0.0,
        MFAType.FIDO2: 0.0,
    },
    "developing": {
        MFAType.NONE: 0.40,
        MFAType.SMS: 0.35,
        MFAType.AUTHENTICATOR_APP: 0.20,
        MFAType.PUSH_NOTIFICATION: 0.05,
        MFAType.FIDO2: 0.0,
    },
    "defined": {
        MFAType.NONE: 0.15,
        MFAType.SMS: 0.25,
        MFAType.AUTHENTICATOR_APP: 0.35,
        MFAType.PUSH_NOTIFICATION: 0.20,
        MFAType.FIDO2: 0.05,
    },
    "managed": {
        MFAType.NONE: 0.05,
        MFAType.SMS: 0.15,
        MFAType.AUTHENTICATOR_APP: 0.30,
        MFAType.PUSH_NOTIFICATION: 0.35,
        MFAType.FIDO2: 0.15,
    },
    "optimizing": {
        MFAType.NONE: 0.0,
        MFAType.SMS: 0.05,
        MFAType.AUTHENTICATOR_APP: 0.20,
        MFAType.PUSH_NOTIFICATION: 0.35,
        MFAType.FIDO2: 0.40,
    },
}

FIREWALL_TYPE_PROBABILITIES = {
    "initial": {
        FirewallType.NONE: 0.10,
        FirewallType.BASIC: 0.60,
        FirewallType.STATEFUL: 0.25,
        FirewallType.NGFW: 0.05,
        FirewallType.NGFW_ADVANCED: 0.0,
    },
    "developing": {
        FirewallType.NONE: 0.05,
        FirewallType.BASIC: 0.40,
        FirewallType.STATEFUL: 0.40,
        FirewallType.NGFW: 0.15,
        FirewallType.NGFW_ADVANCED: 0.0,
    },
    "defined": {
        FirewallType.NONE: 0.0,
        FirewallType.BASIC: 0.20,
        FirewallType.STATEFUL: 0.45,
        FirewallType.NGFW: 0.30,
        FirewallType.NGFW_ADVANCED: 0.05,
    },
    "managed": {
        FirewallType.NONE: 0.0,
        FirewallType.BASIC: 0.10,
        FirewallType.STATEFUL: 0.30,
        FirewallType.NGFW: 0.45,
        FirewallType.NGFW_ADVANCED: 0.15,
    },
    "optimizing": {
        FirewallType.NONE: 0.0,
        FirewallType.BASIC: 0.0,
        FirewallType.STATEFUL: 0.10,
        FirewallType.NGFW: 0.50,
        FirewallType.NGFW_ADVANCED: 0.40,
    },
}

WAF_TYPE_PROBABILITIES = {
    "initial": {
        WAFType.NONE: 0.80,
        WAFType.BASIC: 0.15,
        WAFType.MANAGED: 0.05,
        WAFType.OWASP_CRS: 0.0,
        WAFType.CUSTOM_TUNED: 0.0,
    },
    "developing": {
        WAFType.NONE: 0.60,
        WAFType.BASIC: 0.25,
        WAFType.MANAGED: 0.12,
        WAFType.OWASP_CRS: 0.03,
        WAFType.CUSTOM_TUNED: 0.0,
    },
    "defined": {
        WAFType.NONE: 0.40,
        WAFType.BASIC: 0.20,
        WAFType.MANAGED: 0.25,
        WAFType.OWASP_CRS: 0.12,
        WAFType.CUSTOM_TUNED: 0.03,
    },
    "managed": {
        WAFType.NONE: 0.20,
        WAFType.BASIC: 0.15,
        WAFType.MANAGED: 0.30,
        WAFType.OWASP_CRS: 0.25,
        WAFType.CUSTOM_TUNED: 0.10,
    },
    "optimizing": {
        WAFType.NONE: 0.10,
        WAFType.BASIC: 0.05,
        WAFType.MANAGED: 0.20,
        WAFType.OWASP_CRS: 0.40,
        WAFType.CUSTOM_TUNED: 0.25,
    },
}

ENDPOINT_TYPE_PROBABILITIES = {
    "initial": {
        EndpointProtectionType.NONE: 0.15,
        EndpointProtectionType.TRADITIONAL_AV: 0.70,
        EndpointProtectionType.BASIC_EDR: 0.15,
        EndpointProtectionType.ADVANCED_EDR: 0.0,
        EndpointProtectionType.XDR: 0.0,
    },
    "developing": {
        EndpointProtectionType.NONE: 0.05,
        EndpointProtectionType.TRADITIONAL_AV: 0.50,
        EndpointProtectionType.BASIC_EDR: 0.35,
        EndpointProtectionType.ADVANCED_EDR: 0.10,
        EndpointProtectionType.XDR: 0.0,
    },
    "defined": {
        EndpointProtectionType.NONE: 0.0,
        EndpointProtectionType.TRADITIONAL_AV: 0.30,
        EndpointProtectionType.BASIC_EDR: 0.40,
        EndpointProtectionType.ADVANCED_EDR: 0.25,
        EndpointProtectionType.XDR: 0.05,
    },
    "managed": {
        EndpointProtectionType.NONE: 0.0,
        EndpointProtectionType.TRADITIONAL_AV: 0.15,
        EndpointProtectionType.BASIC_EDR: 0.30,
        EndpointProtectionType.ADVANCED_EDR: 0.40,
        EndpointProtectionType.XDR: 0.15,
    },
    "optimizing": {
        EndpointProtectionType.NONE: 0.0,
        EndpointProtectionType.TRADITIONAL_AV: 0.05,
        EndpointProtectionType.BASIC_EDR: 0.15,
        EndpointProtectionType.ADVANCED_EDR: 0.40,
        EndpointProtectionType.XDR: 0.40,
    },
}

SEGMENTATION_TYPE_PROBABILITIES = {
    "initial": {
        SegmentationType.NONE: 0.60,
        SegmentationType.BASIC_VLAN: 0.35,
        SegmentationType.VLAN_ACL: 0.05,
        SegmentationType.MICRO_SEGMENTATION: 0.0,
        SegmentationType.ZERO_TRUST: 0.0,
    },
    "developing": {
        SegmentationType.NONE: 0.35,
        SegmentationType.BASIC_VLAN: 0.45,
        SegmentationType.VLAN_ACL: 0.18,
        SegmentationType.MICRO_SEGMENTATION: 0.02,
        SegmentationType.ZERO_TRUST: 0.0,
    },
    "defined": {
        SegmentationType.NONE: 0.15,
        SegmentationType.BASIC_VLAN: 0.35,
        SegmentationType.VLAN_ACL: 0.35,
        SegmentationType.MICRO_SEGMENTATION: 0.12,
        SegmentationType.ZERO_TRUST: 0.03,
    },
    "managed": {
        SegmentationType.NONE: 0.05,
        SegmentationType.BASIC_VLAN: 0.20,
        SegmentationType.VLAN_ACL: 0.35,
        SegmentationType.MICRO_SEGMENTATION: 0.30,
        SegmentationType.ZERO_TRUST: 0.10,
    },
    "optimizing": {
        SegmentationType.NONE: 0.0,
        SegmentationType.BASIC_VLAN: 0.10,
        SegmentationType.VLAN_ACL: 0.20,
        SegmentationType.MICRO_SEGMENTATION: 0.40,
        SegmentationType.ZERO_TRUST: 0.30,
    },
}

IDS_IPS_TYPE_PROBABILITIES = {
    "initial": {
        IDSIPSType.NONE: 0.50,
        IDSIPSType.IDS_ONLY: 0.30,
        IDSIPSType.IPS_SIGNATURE: 0.18,
        IDSIPSType.IPS_BEHAVIORAL: 0.02,
        IDSIPSType.IPS_ML: 0.0,
    },
    "developing": {
        IDSIPSType.NONE: 0.30,
        IDSIPSType.IDS_ONLY: 0.25,
        IDSIPSType.IPS_SIGNATURE: 0.35,
        IDSIPSType.IPS_BEHAVIORAL: 0.10,
        IDSIPSType.IPS_ML: 0.0,
    },
    "defined": {
        IDSIPSType.NONE: 0.15,
        IDSIPSType.IDS_ONLY: 0.15,
        IDSIPSType.IPS_SIGNATURE: 0.45,
        IDSIPSType.IPS_BEHAVIORAL: 0.20,
        IDSIPSType.IPS_ML: 0.05,
    },
    "managed": {
        IDSIPSType.NONE: 0.05,
        IDSIPSType.IDS_ONLY: 0.10,
        IDSIPSType.IPS_SIGNATURE: 0.35,
        IDSIPSType.IPS_BEHAVIORAL: 0.35,
        IDSIPSType.IPS_ML: 0.15,
    },
    "optimizing": {
        IDSIPSType.NONE: 0.0,
        IDSIPSType.IDS_ONLY: 0.05,
        IDSIPSType.IPS_SIGNATURE: 0.20,
        IDSIPSType.IPS_BEHAVIORAL: 0.45,
        IDSIPSType.IPS_ML: 0.30,
    },
}

SIEM_MATURITY_PROBABILITIES = {
    "initial": {
        SIEMMaturity.NONE: 0.70,
        SIEMMaturity.LOG_COLLECTION: 0.25,
        SIEMMaturity.BASIC_CORRELATION: 0.05,
        SIEMMaturity.ADVANCED_ANALYTICS: 0.0,
        SIEMMaturity.THREAT_HUNTING: 0.0,
    },
    "developing": {
        SIEMMaturity.NONE: 0.45,
        SIEMMaturity.LOG_COLLECTION: 0.35,
        SIEMMaturity.BASIC_CORRELATION: 0.18,
        SIEMMaturity.ADVANCED_ANALYTICS: 0.02,
        SIEMMaturity.THREAT_HUNTING: 0.0,
    },
    "defined": {
        SIEMMaturity.NONE: 0.25,
        SIEMMaturity.LOG_COLLECTION: 0.30,
        SIEMMaturity.BASIC_CORRELATION: 0.30,
        SIEMMaturity.ADVANCED_ANALYTICS: 0.12,
        SIEMMaturity.THREAT_HUNTING: 0.03,
    },
    "managed": {
        SIEMMaturity.NONE: 0.10,
        SIEMMaturity.LOG_COLLECTION: 0.20,
        SIEMMaturity.BASIC_CORRELATION: 0.30,
        SIEMMaturity.ADVANCED_ANALYTICS: 0.30,
        SIEMMaturity.THREAT_HUNTING: 0.10,
    },
    "optimizing": {
        SIEMMaturity.NONE: 0.05,
        SIEMMaturity.LOG_COLLECTION: 0.10,
        SIEMMaturity.BASIC_CORRELATION: 0.20,
        SIEMMaturity.ADVANCED_ANALYTICS: 0.40,
        SIEMMaturity.THREAT_HUNTING: 0.25,
    },
}

PATCH_QUALITY_PROBABILITIES = {
    "initial": {
        PatchManagementQuality.NONE: 0.30,
        PatchManagementQuality.REACTIVE: 0.50,
        PatchManagementQuality.QUARTERLY: 0.18,
        PatchManagementQuality.MONTHLY: 0.02,
        PatchManagementQuality.WEEKLY: 0.0,
        PatchManagementQuality.AUTOMATED: 0.0,
    },
    "developing": {
        PatchManagementQuality.NONE: 0.15,
        PatchManagementQuality.REACTIVE: 0.30,
        PatchManagementQuality.QUARTERLY: 0.35,
        PatchManagementQuality.MONTHLY: 0.18,
        PatchManagementQuality.WEEKLY: 0.02,
        PatchManagementQuality.AUTOMATED: 0.0,
    },
    "defined": {
        PatchManagementQuality.NONE: 0.05,
        PatchManagementQuality.REACTIVE: 0.15,
        PatchManagementQuality.QUARTERLY: 0.30,
        PatchManagementQuality.MONTHLY: 0.40,
        PatchManagementQuality.WEEKLY: 0.08,
        PatchManagementQuality.AUTOMATED: 0.02,
    },
    "managed": {
        PatchManagementQuality.NONE: 0.02,
        PatchManagementQuality.REACTIVE: 0.08,
        PatchManagementQuality.QUARTERLY: 0.15,
        PatchManagementQuality.MONTHLY: 0.45,
        PatchManagementQuality.WEEKLY: 0.25,
        PatchManagementQuality.AUTOMATED: 0.05,
    },
    "optimizing": {
        PatchManagementQuality.NONE: 0.0,
        PatchManagementQuality.REACTIVE: 0.03,
        PatchManagementQuality.QUARTERLY: 0.07,
        PatchManagementQuality.MONTHLY: 0.30,
        PatchManagementQuality.WEEKLY: 0.40,
        PatchManagementQuality.AUTOMATED: 0.20,
    },
}

# Industry modifiers - multiply base probabilities by these factors
# Values > 1.0 increase likelihood, < 1.0 decrease likelihood

INDUSTRY_CONTROL_TYPE_MODIFIERS = {
    "financial-services": {
        "mfa": {
            MFAType.FIDO2: 1.8,
            MFAType.PUSH_NOTIFICATION: 1.3,
            MFAType.SMS: 0.6,
        },
        "firewall": {
            FirewallType.NGFW_ADVANCED: 1.6,
            FirewallType.NGFW: 1.3,
            FirewallType.BASIC: 0.5,
        },
        "segmentation": {
            SegmentationType.ZERO_TRUST: 1.6,
            SegmentationType.MICRO_SEGMENTATION: 1.4,
        },
        "endpoint": {
            EndpointProtectionType.XDR: 1.5,
            EndpointProtectionType.ADVANCED_EDR: 1.3,
        },
        "patch": {
            PatchManagementQuality.AUTOMATED: 1.5,
            PatchManagementQuality.WEEKLY: 1.3,
        },
    },
    "healthcare": {
        "mfa": {
            MFAType.SMS: 1.3,
            MFAType.FIDO2: 0.7,
        },
        "endpoint": {
            EndpointProtectionType.TRADITIONAL_AV: 1.3,
            EndpointProtectionType.XDR: 0.7,
        },
        "patch": {
            PatchManagementQuality.QUARTERLY: 1.4,
            PatchManagementQuality.AUTOMATED: 0.6,
        },
    },
    "technology": {
        "mfa": {
            MFAType.FIDO2: 2.0,
            MFAType.AUTHENTICATOR_APP: 1.4,
            MFAType.SMS: 0.4,
        },
        "firewall": {
            FirewallType.NGFW_ADVANCED: 1.7,
            FirewallType.BASIC: 0.4,
        },
        "segmentation": {
            SegmentationType.ZERO_TRUST: 1.8,
            SegmentationType.MICRO_SEGMENTATION: 1.5,
        },
        "endpoint": {
            EndpointProtectionType.XDR: 1.8,
            EndpointProtectionType.TRADITIONAL_AV: 0.3,
        },
        "patch": {
            PatchManagementQuality.AUTOMATED: 2.0,
            PatchManagementQuality.WEEKLY: 1.5,
        },
    },
    "government": {
        "mfa": {
            MFAType.FIDO2: 1.5,
            MFAType.SMS: 0.5,
        },
        "firewall": {
            FirewallType.NGFW_ADVANCED: 1.4,
        },
        "segmentation": {
            SegmentationType.MICRO_SEGMENTATION: 1.4,
        },
    },
    "small-business": {
        "mfa": {
            MFAType.SMS: 1.5,
            MFAType.FIDO2: 0.3,
        },
        "firewall": {
            FirewallType.BASIC: 1.5,
            FirewallType.STATEFUL: 1.2,
            FirewallType.NGFW_ADVANCED: 0.3,
        },
        "endpoint": {
            EndpointProtectionType.TRADITIONAL_AV: 1.4,
            EndpointProtectionType.XDR: 0.3,
        },
        "segmentation": {
            SegmentationType.NONE: 1.5,
            SegmentationType.ZERO_TRUST: 0.2,
        },
        "patch": {
            PatchManagementQuality.REACTIVE: 1.5,
            PatchManagementQuality.AUTOMATED: 0.3,
        },
    },
}

# Exposure modifiers - adjust based on service exposure
EXPOSURE_CONTROL_TYPE_MODIFIERS = {
    "internet-facing": {
        "mfa": {
            MFAType.FIDO2: 1.4,
            MFAType.PUSH_NOTIFICATION: 1.3,
            MFAType.SMS: 0.7,
        },
        "waf": {
            WAFType.CUSTOM_TUNED: 1.5,
            WAFType.OWASP_CRS: 1.3,
            WAFType.NONE: 0.5,
        },
        "firewall": {
            FirewallType.NGFW_ADVANCED: 1.3,
            FirewallType.BASIC: 0.7,
        },
    },
    "restricted": {
        "mfa": {
            MFAType.FIDO2: 1.6,
            MFAType.PUSH_NOTIFICATION: 1.2,
            MFAType.SMS: 0.5,
        },
        "segmentation": {
            SegmentationType.ZERO_TRUST: 1.5,
            SegmentationType.MICRO_SEGMENTATION: 1.3,
        },
    },
    "internal": {
        "mfa": {
            MFAType.SMS: 1.2,
            MFAType.AUTHENTICATOR_APP: 1.1,
        },
        "waf": {
            WAFType.NONE: 1.5,
        },
    },
}
