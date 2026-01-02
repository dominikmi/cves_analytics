#!/usr/bin/env python3
"""Create mock cache for Monte Carlo testing.

This creates a simplified cache with sample vulnerability data
to test the Monte Carlo framework without full pipeline integration.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_mock_cache(
    scenario_config: dict, output_dir: str = "monte_carlo/output/cache"
):
    """Create mock cache with sample vulnerability data.

    Args:
        scenario_config: Scenario configuration
        output_dir: Output directory for cache
    """
    logger.info("Creating mock cache...")

    # Create output directory
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Generate mock vulnerability data
    n_vulns = 500  # 500 sample vulnerabilities

    # Mock CVE IDs
    cve_ids = [f"CVE-2023-{10000 + i}" for i in range(n_vulns)]

    # Mock CVSS scores (realistic distribution)
    cvss_scores = np.random.choice(
        [4.0, 5.0, 6.0, 7.0, 7.5, 8.0, 8.5, 9.0, 9.5],
        size=n_vulns,
        p=[0.15, 0.20, 0.20, 0.15, 0.10, 0.10, 0.05, 0.03, 0.02],
    )

    # Mock EPSS scores (realistic distribution - most low, some high)
    epss_scores = np.random.beta(2, 20, size=n_vulns)  # Skewed toward low values

    # Mock KEV status (5% are KEV)
    is_kev = np.random.choice([True, False], size=n_vulns, p=[0.05, 0.95])

    # Mock severity (based on CVSS)
    severity = []
    for cvss in cvss_scores:
        if cvss >= 9.0:
            severity.append("Critical")
        elif cvss >= 7.0:
            severity.append("High")
        elif cvss >= 4.0:
            severity.append("Medium")
        else:
            severity.append("Low")

    # Create enriched CVE dataset
    enriched_cves = {
        "cve_id": cve_ids,
        "cvss_score": cvss_scores.tolist(),
        "epss_score": epss_scores.tolist(),
        "is_kev": is_kev.tolist(),
        "severity_reassessed": severity,
    }

    # Mock Docker scan results
    docker_scans = {
        "nginx:latest": [
            {"cve_id": cve_ids[i], "severity": severity[i]} for i in range(0, 100)
        ],
        "postgres:14": [
            {"cve_id": cve_ids[i], "severity": severity[i]} for i in range(100, 200)
        ],
        "redis:7": [
            {"cve_id": cve_ids[i], "severity": severity[i]} for i in range(200, 300)
        ],
    }

    # Mock EPSS data
    epss_data = {cve_id: float(score) for cve_id, score in zip(cve_ids, epss_scores)}

    # Mock KEV data
    kev_data = {
        cve_id: {
            "date_added": "2023-06-15",
            "required_action": "Apply updates",
        }
        for cve_id, kev in zip(cve_ids, is_kev)
        if kev
    }

    # Mock architecture
    architecture = {
        "components": [
            {"name": "web", "type": "frontend", "exposure": "internet"},
            {"name": "api", "type": "backend", "exposure": "internal"},
            {"name": "database", "type": "data", "exposure": "internal"},
        ],
        "network_topology": {
            "zones": ["dmz", "internal", "data"],
            "segmentation": "vlan",
        },
    }

    # Create cache
    cache = {
        "version": "1.0",
        "timestamp": datetime.now().isoformat(),
        "scenario_config": scenario_config,
        "docker_scans": docker_scans,
        "enriched_cves": enriched_cves,
        "epss_data": epss_data,
        "kev_data": kev_data,
        "architecture": architecture,
    }

    # Save cache
    cache_key = f"cache_{scenario_config['org_size']}_{scenario_config['industry']}_{scenario_config['environment']}"
    cache_file = Path(output_dir) / f"{cache_key}.json"

    with open(cache_file, "w") as f:
        json.dump(cache, f, indent=2)

    logger.info(f"Mock cache created: {cache_file}")
    logger.info(f"  Vulnerabilities: {n_vulns}")
    logger.info(f"  Docker images: {len(docker_scans)}")
    logger.info(f"  KEV entries: {len(kev_data)}")

    return cache


if __name__ == "__main__":
    # Create mock cache for large/optimizing scenario
    scenario_config = {
        "org_size": "large",
        "industry": "financial-services",
        "maturity": "optimizing",
        "environment": "prod",
    }

    create_mock_cache(scenario_config)

    logger.info("Mock cache ready for Monte Carlo simulation!")
