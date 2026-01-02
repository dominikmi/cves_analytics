#!/usr/bin/env python3
"""Extract key data from scenario comparison reports."""

import re
from pathlib import Path


def extract_report_data(report_path):
    """Extract key metrics from a report file."""
    with open(report_path) as f:
        content = f.read()

    data = {}

    # Extract organization details
    org_match = re.search(r"Organization Size: (\w+)", content)
    data["org_size"] = org_match.group(1) if org_match else "Unknown"

    industry_match = re.search(r"Industry: ([\w-]+)", content)
    data["industry"] = industry_match.group(1) if industry_match else "Unknown"

    maturity_match = re.search(r"Security Maturity: (\w+)", content)
    data["maturity"] = maturity_match.group(1) if maturity_match else "Unknown"

    # Extract vulnerability counts
    total_match = re.search(r"Total Vulnerabilities Scanned: (\d+)", content)
    data["total_vulns"] = int(total_match.group(1)) if total_match else 0

    # Extract Bayesian assessment
    bayesian_section = re.search(
        r"Bayesian Risk Assessment.*?Critical: (\d+).*?High: (\d+).*?"
        r"Medium: (\d+).*?Low: (\d+).*?Negligible: (\d+)",
        content,
        re.DOTALL,
    )
    if bayesian_section:
        data["bayesian_critical"] = int(bayesian_section.group(1))
        data["bayesian_high"] = int(bayesian_section.group(2))
        data["bayesian_medium"] = int(bayesian_section.group(3))
        data["bayesian_low"] = int(bayesian_section.group(4))
        data["bayesian_negligible"] = int(bayesian_section.group(5))

    # Extract average exploitation probability
    avg_prob_match = re.search(r"Average Exploitation Probability: ([\d.]+)%", content)
    data["avg_exploit_prob"] = float(avg_prob_match.group(1)) if avg_prob_match else 0.0

    # Extract actionable vulnerabilities
    actionable_match = re.search(r"Actionable Vulnerabilities.*?: (\d+)", content)
    data["actionable"] = int(actionable_match.group(1)) if actionable_match else 0

    # Extract kill-chain probability
    kc_prob_match = re.search(r"Overall Probability: ([\d.]+)%", content)
    data["killchain_prob"] = float(kc_prob_match.group(1)) if kc_prob_match else 0.0

    kc_threat_match = re.search(r"Threat Level: (\w+)", content)
    data["killchain_threat"] = (
        kc_threat_match.group(1) if kc_threat_match else "Unknown"
    )

    # Extract active controls
    controls_match = re.search(r"Active Security Controls: (\d+)", content)
    data["active_controls"] = int(controls_match.group(1)) if controls_match else 0

    return data


# Process all three scenarios
scenarios = {
    "Scenario 1 (Small/Initial)": (
        "output/scenario_comparison/scenario1_small_initial"
    ),
    "Scenario 2 (Mid/Managed)": ("output/scenario_comparison/scenario2_mid_managed"),
    "Scenario 3 (Large/Optimizing)": (
        "output/scenario_comparison/scenario3_large_optimizing"
    ),
}

print("=" * 100)
print("SCENARIO COMPARISON DATA EXTRACTION")
print("=" * 100)

for scenario_name, scenario_dir in scenarios.items():
    path = Path(scenario_dir)
    reports = list(path.glob("report_*.txt"))

    if reports:
        # Get the most recent report
        latest_report = max(reports, key=lambda p: p.stat().st_mtime)

        print(f"\n{scenario_name}")
        print("-" * 100)

        data = extract_report_data(latest_report)

        print(f"Organization:        {data['org_size']}, {data['industry']}")
        print(f"Maturity:            {data['maturity']}")
        print(f"Total Vulns:         {data['total_vulns']}")
        print(f"Active Controls:     {data['active_controls']}")
        print(f"Avg Exploit Prob:    {data['avg_exploit_prob']:.2f}%")
        print("\nBayesian Assessment:")
        crit = data.get("bayesian_critical", 0)
        high = data.get("bayesian_high", 0)
        med = data.get("bayesian_medium", 0)
        low = data.get("bayesian_low", 0)
        neg = data.get("bayesian_negligible", 0)
        total = data["total_vulns"]

        print(f"  Critical:          {crit} ({crit / total * 100:.1f}%)")
        print(f"  High:              {high} ({high / total * 100:.1f}%)")
        print(f"  Medium:            {med} ({med / total * 100:.1f}%)")
        print(f"  Low:               {low} ({low / total * 100:.1f}%)")
        print(f"  Negligible:        {neg} ({neg / total * 100:.1f}%)")
        print(f"\nActionable:          {data['actionable']}")
        print(f"Kill-Chain Prob:     {data['killchain_prob']:.1f}%")
        print(f"Threat Level:        {data['killchain_threat']}")

print("\n" + "=" * 100)
