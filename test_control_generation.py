#!/usr/bin/env python3
"""Test script to verify control types generation."""

from src.core.control_lr_mapper import get_control_lr_from_security_controls
from src.simulation.security_controls import SecurityControlsGenerator

# Test configuration: Large financial services organization, optimizing maturity
generator = SecurityControlsGenerator()

print("=" * 80)
print("CONTROL TYPES GENERATION TEST")
print("=" * 80)
print("\nConfiguration:")
print("  Organization: Large, Global, Financial Services")
print("  Environment: Production")
print("  Maturity: Optimizing (Level 5)")
print("\n" + "=" * 80)

# Generate controls
controls = generator.generate(
    maturity="optimizing",
    industry="financial-services",
    size="large",
    environment="prod",
)

print("\nGenerated Control Types:")
print("-" * 80)

control_types = [
    ("MFA Type", "mfa_type"),
    ("Firewall Type", "firewall_type"),
    ("WAF Type", "waf_type"),
    ("Endpoint Protection", "endpoint_protection_type"),
    ("Network Segmentation", "segmentation_type"),
    ("IDS/IPS Type", "ids_ips_type"),
    ("SIEM Maturity", "siem_maturity"),
    ("Patch Management", "patch_management_quality"),
]

for display_name, attr_name in control_types:
    value = getattr(controls, attr_name, "N/A")
    print(f"  {display_name:25s}: {value}")

print("\nBoolean Controls:")
print("-" * 80)
boolean_controls = [
    ("Privileged Access Mgmt", "privileged_access_mgmt"),
    ("24x7 SOC", "soc_24x7"),
    ("Incident Response Plan", "incident_response_plan"),
    ("Security Training", "security_training"),
    ("Air Gapped", "air_gapped"),
]

for display_name, attr_name in boolean_controls:
    value = getattr(controls, attr_name, False)
    print(f"  {display_name:25s}: {value}")

print("\n" + "=" * 80)
print("EFFECTIVENESS VALUES (LR)")
print("=" * 80)

# Convert to dict for LR mapping
controls_dict = {
    "mfa_type": controls.mfa_type,
    "firewall_type": controls.firewall_type,
    "waf_type": controls.waf_type,
    "endpoint_protection_type": controls.endpoint_protection_type,
    "segmentation_type": controls.segmentation_type,
    "ids_ips_type": controls.ids_ips_type,
    "siem_maturity": controls.siem_maturity,
    "patch_management_quality": controls.patch_management_quality,
    "privileged_access_mgmt": controls.privileged_access_mgmt,
    "soc_24x7": controls.soc_24x7,
    "incident_response_plan": controls.incident_response_plan,
    "security_training": controls.security_training,
    "air_gapped": controls.air_gapped,
}

lr_values = get_control_lr_from_security_controls(controls_dict)

print("\nLikelihood Ratios (LR):")
print("-" * 80)
for control_name, lr in sorted(lr_values.items()):
    reduction = (1 - lr) * 100
    print(f"  {control_name:25s}: LR={lr:.2f} ({reduction:.0f}% reduction)")

print("\n" + "=" * 80)
print("MULTIPLE RUNS TEST (Variability Check)")
print("=" * 80)

# Generate 10 times to show variability
mfa_counts = {}
firewall_counts = {}
waf_counts = {}

for _i in range(10):
    c = generator.generate(
        maturity="optimizing",
        industry="financial-services",
        size="large",
        environment="prod",
    )

    mfa_counts[c.mfa_type] = mfa_counts.get(c.mfa_type, 0) + 1
    firewall_counts[c.firewall_type] = firewall_counts.get(c.firewall_type, 0) + 1
    waf_counts[c.waf_type] = waf_counts.get(c.waf_type, 0) + 1

print("\nMFA Type Distribution (10 runs):")
for mfa_type, count in sorted(mfa_counts.items(), key=lambda x: -x[1]):
    print(f"  {mfa_type:20s}: {count}/10 ({count * 10}%)")

print("\nFirewall Type Distribution (10 runs):")
for fw_type, count in sorted(firewall_counts.items(), key=lambda x: -x[1]):
    print(f"  {fw_type:20s}: {count}/10 ({count * 10}%)")

print("\nWAF Type Distribution (10 runs):")
for waf_type, count in sorted(waf_counts.items(), key=lambda x: -x[1]):
    print(f"  {waf_type:20s}: {count}/10 ({count * 10}%)")

print("\n" + "=" * 80)
