"""Pytest configuration and shared fixtures."""

import pytest


@pytest.fixture
def sample_cve_data():
    """Sample CVE data for testing."""
    return {
        "cve_id": "CVE-2021-1234",
        "description": "Test vulnerability",
        "cwe_id": "CWE-79",
        "published_date": "2021-01-01",
        "last_modified_date": "2021-01-02",
        "base_score": 7.5,
        "base_severity": "High",
        "attack_vector": "NETWORK",
        "attack_complexity": "LOW",
    }


@pytest.fixture
def sample_impact_data():
    """Sample CVSS impact data for testing."""
    return {
        "baseMetricV3": {
            "cvssV3": {
                "version": "3.1",
                "baseScore": 7.5,
                "baseSeverity": "High",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "NONE",
                "availabilityImpact": "NONE",
            },
            "exploitabilityScore": 3.9,
            "impactScore": 3.6,
        }
    }


@pytest.fixture
def sample_scenario_params():
    """Sample scenario generation parameters."""
    return {
        "size": "mid",
        "reach": "global",
        "industry": "financial-services",
        "environment_type": "prod",
        "output_format": "json",
    }
