"""CVSS parsing utilities to eliminate duplication."""

import re
from typing import Any


class CVSSParser:
    """Parses CVSS v2 and v3 metrics from CVE data."""

    @staticmethod
    def _safe_get(data: dict[str, Any], *keys: str) -> Any | None:
        """Safely navigate nested dictionaries.

        Args:
            data: Dictionary to navigate
            *keys: Keys to traverse in order

        Returns:
            Value at the end of the key path, or None if not found

        """
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
                if current is None:
                    return None
            else:
                return None
        return current

    @staticmethod
    def parse_cvss_v3(impact_data: dict[str, Any]) -> dict[str, Any]:
        """Parse CVSS v3 metrics from impact data.

        Args:
            impact_data: Impact data from CVE JSON

        Returns:
            Dictionary containing parsed CVSS v3 metrics

        """
        base_metric = CVSSParser._safe_get(impact_data, "baseMetricV3")
        if not base_metric:
            return {}

        cvss_v3 = base_metric.get("cvssV3", {})

        return {
            "cvss_version": cvss_v3.get("version"),
            "base_score": cvss_v3.get("baseScore"),
            "base_severity": cvss_v3.get("baseSeverity"),
            "exploitability_score": base_metric.get("exploitabilityScore"),
            "impact_score": base_metric.get("impactScore"),
            "vector_string": cvss_v3.get("vectorString"),
            "attack_vector": cvss_v3.get("attackVector"),
            "attack_complexity": cvss_v3.get("attackComplexity"),
            "privileges_required": cvss_v3.get("privilegesRequired"),
            "user_interaction": cvss_v3.get("userInteraction"),
            "scope": cvss_v3.get("scope"),
            "confidentiality_impact": cvss_v3.get("confidentialityImpact"),
            "integrity_impact": cvss_v3.get("integrityImpact"),
            "availability_impact": cvss_v3.get("availabilityImpact"),
        }

    @staticmethod
    def parse_cvss_v2(impact_data: dict[str, Any]) -> dict[str, Any]:
        """Parse CVSS v2 metrics from impact data.

        Args:
            impact_data: Impact data from CVE JSON

        Returns:
            Dictionary containing parsed CVSS v2 metrics

        """
        base_metric = CVSSParser._safe_get(impact_data, "baseMetricV2")
        if not base_metric:
            return {}

        cvss_v2 = base_metric.get("cvssV2", {})

        return {
            "cvss_version": cvss_v2.get("version"),
            "base_score": cvss_v2.get("baseScore"),
            "base_severity": base_metric.get("severity"),
            "exploitability_score": base_metric.get("exploitabilityScore"),
            "impact_score": base_metric.get("impactScore"),
            "vector_string": cvss_v2.get("vectorString"),
            "access_vector": cvss_v2.get("accessVector"),
            "access_complexity": cvss_v2.get("accessComplexity"),
            "authentication": cvss_v2.get("authentication"),
            "user_interaction_required": base_metric.get("userInteractionRequired"),
            "confidentiality_impact": cvss_v2.get("confidentialityImpact"),
            "integrity_impact": cvss_v2.get("integrityImpact"),
            "availability_impact": cvss_v2.get("availabilityImpact"),
        }

    @staticmethod
    def parse_cvss(impact_data: dict[str, Any]) -> dict[str, Any]:
        """Parse CVSS metrics, preferring v3 over v2.

        Args:
            impact_data: Impact data from CVE JSON

        Returns:
            Dictionary containing parsed CVSS metrics

        """
        # Try v3 first, fall back to v2
        if "baseMetricV3" in impact_data:
            return CVSSParser.parse_cvss_v3(impact_data)
        if "baseMetricV2" in impact_data:
            return CVSSParser.parse_cvss_v2(impact_data)
        return {}

    @staticmethod
    def parse_cvss_vector(vector: str | None) -> dict[str, str]:
        """Parse CVSS vector string into components.

        Args:
            vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        Returns:
            Dictionary with CVSS components

        """
        if not vector or not isinstance(vector, str):
            return {}

        components = {}

        # Clean up the vector string
        vector = str(vector).strip()

        # Extract version from CVSS:X.X format
        version_match = re.search(r"CVSS:(\d+\.\d+)", vector)
        if version_match:
            components["version"] = version_match.group(1)

        # Extract all metrics - handle both formats:
        # Format 1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        # Format 2: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (without CVSS prefix)

        # Split by / and process each component
        parts = vector.split("/")
        for part in parts:
            part = part.strip()
            if ":" in part:
                # Skip CVSS:X.X part
                if part.startswith("CVSS:"):
                    continue
                # Extract metric and value
                metric, value = part.split(":", 1)
                metric = metric.strip().upper()  # Standardize to uppercase
                value = value.strip().upper()  # Standardize to uppercase
                if metric and value:
                    components[metric] = value

        return components

    @staticmethod
    def get_attack_vector(components: dict[str, str]) -> str:
        """Get Attack Vector (AV) from components."""
        return components.get("AV", "")

    @staticmethod
    def get_attack_complexity(components: dict[str, str]) -> str:
        """Get Attack Complexity (AC) from components."""
        return components.get("AC", "")

    @staticmethod
    def get_privileges_required(components: dict[str, str]) -> str:
        """Get Privileges Required (PR) from components."""
        return components.get("PR", "")

    @staticmethod
    def get_user_interaction(components: dict[str, str]) -> str:
        """Get User Interaction (UI) from components."""
        return components.get("UI", "")

    @staticmethod
    def get_scope(components: dict[str, str]) -> str:
        """Get Scope (S) from components."""
        return components.get("S", "")

    @staticmethod
    def get_confidentiality(components: dict[str, str]) -> str:
        """Get Confidentiality Impact (C) from components."""
        return components.get("C", "")

    @staticmethod
    def get_integrity(components: dict[str, str]) -> str:
        """Get Integrity Impact (I) from components."""
        return components.get("I", "")

    @staticmethod
    def get_availability(components: dict[str, str]) -> str:
        """Get Availability Impact (A) from components."""
        return components.get("A", "")
