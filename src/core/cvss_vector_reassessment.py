#!/usr/bin/env python3
"""
CVSS Vector and EPSS Score-based Vulnerability Reassessment Module.

This module provides comprehensive criteria for reassessing vulnerability severity
based on CVSS vectors and EPSS scores, moving beyond simple score thresholds to
consider attack complexity, exploitability, and real-world threat data.

Criteria Justification:
- CVSS vectors provide detailed attack characteristics (AV, AC, PR, UI, S, C, I, A)
- EPSS scores represent real-world exploitation probability based on threat intelligence
- Combined assessment provides more accurate risk evaluation than CVSS score alone
"""

from __future__ import annotations

from enum import Enum

import pandas as pd

from src.core.cvss_parser import CVSSParser
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


# CVSS v3 valid metric values
class CVSSMetric(str, Enum):
    """Valid CVSS metric names."""

    AV = "AV"  # Attack Vector
    AC = "AC"  # Attack Complexity
    PR = "PR"  # Privileges Required
    UI = "UI"  # User Interaction
    S = "S"  # Scope
    C = "C"  # Confidentiality Impact
    INTEGRITY = "I"  # Integrity Impact  # noqa: E741
    A = "A"  # Availability Impact


class CVSSValue(str, Enum):
    """Valid CVSS metric values."""

    # Attack Vector
    N = "N"  # Network
    A = "A"  # Adjacent
    L = "L"  # Local
    P = "P"  # Physical
    # Attack Complexity, Privileges Required, User Interaction
    H = "H"  # High
    # Scope, Confidentiality/Integrity/Availability Impact
    U = "U"  # Unchanged
    C = "C"  # Changed


def validate_risk_factor(factor: float | None, name: str = "risk_factor") -> float:
    """
    Validate and normalize risk factor.

    Args:
        factor: Risk factor value
        name: Name of factor for logging

    Returns:
        Validated factor in range [0.5, 3.0], or 1.0 if invalid
    """
    if factor is None or pd.isna(factor):
        return 1.0

    try:
        factor = float(factor)
    except (ValueError, TypeError):
        logger.warning(f"{name} is not a number: {factor}, using default 1.0")
        return 1.0

    if not (0.5 <= factor <= 3.0):
        logger.warning(
            f"{name} out of valid range [0.5, 3.0]: {factor}, clamping to 1.0"
        )
        return 1.0

    return factor


def normalize_epss(epss: float | None) -> float:
    """
    Validate and normalize EPSS score.

    Args:
        epss: EPSS score (should be 0-1, but may be 0-100 percentage)

    Returns:
        Normalized EPSS in range [0, 1], or 0.0 if invalid
    """
    if epss is None or pd.isna(epss):
        return 0.0

    try:
        epss = float(epss)
    except (ValueError, TypeError):
        logger.warning(f"EPSS is not a number: {epss}, using default 0.0")
        return 0.0

    # If EPSS > 1, assume it's a percentage and normalize
    if epss > 1.0:
        logger.debug(
            f"EPSS appears to be percentage: {epss}, normalizing to {epss / 100.0}"
        )
        epss = epss / 100.0

    if not (0.0 <= epss <= 1.0):
        logger.warning(f"EPSS out of valid range [0, 1]: {epss}, using default 0.0")
        return 0.0

    return epss


def validate_cvss_vector(vector: str | None) -> bool:
    """
    Validate CVSS vector string format and components.

    Args:
        vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/...")

    Returns:
        True if vector is valid, False otherwise
    """
    if not vector or not isinstance(vector, str):
        return False

    vector = str(vector).strip()
    if not vector or vector.lower() == "nan":
        return False

    # Extract components
    parts = vector.split("/")
    for part in parts:
        part = part.strip()
        if not part or ":" not in part:
            continue

        # Skip CVSS version part
        if part.startswith("CVSS:"):
            continue

        try:
            metric, value = part.split(":", 1)
            metric = metric.strip().upper()
            value = value.strip().upper()

            # Validate metric name
            if metric not in [m.value for m in CVSSMetric]:
                logger.debug(f"Invalid CVSS metric: {metric}")
                return False

            # Validate metric value
            if value not in [v.value for v in CVSSValue]:
                logger.debug(f"Invalid CVSS value: {value}")
                return False
        except ValueError:
            logger.debug(f"Malformed CVSS component: {part}")
            return False

    return True


class CVSSEPSSReassessment:
    """
    Reassess vulnerability severity using CVSS vectors and EPSS scores.

    Criteria for Critical Classification:
    =====================================

    A vulnerability is classified as CRITICAL based on the following criteria:

    1. **High CVSS Score + High Exploitability (EPSS >= 0.5)**
       - CVSS >= 9.0 AND EPSS >= 0.5
       - Justification: Extremely severe vulnerability with high real-world exploitation
       - Example: Remote code execution with no authentication required

    2. **Network-Accessible RCE with Low Complexity**
       - AV:N (Network) AND AC:L (Low) AND (I:H OR A:H) AND EPSS >= 0.3
       - Justification: Remotely exploitable without special conditions
       - Impact: Can compromise system integrity or availability

    3. **Privilege Escalation to Root/Admin**
       - PR:L/PR:N (Low/None) AND (I:H OR A:H) AND S:C (Changed Scope)
       - AND EPSS >= 0.4
       - Justification: Can escalate from limited user to full system control
       - Impact: Complete system compromise

    4. **Authentication Bypass with Data Access**
       - AV:N AND AC:L AND PR:N AND C:H AND EPSS >= 0.4
       - Justification: Unauthenticated remote access to sensitive data
       - Impact: Confidentiality breach without authentication

    5. **Known Exploited Vulnerability (KEV)**
       - Any CVSS >= 7.0 AND in KEV catalog AND EPSS >= 0.2
       - Justification: Active exploitation in the wild significantly increases risk
       - Impact: Immediate threat to systems

    6. **High EPSS + Moderate CVSS**
       - CVSS >= 7.0 AND EPSS >= 0.7
       - Justification: Even moderate vulnerabilities with high exploitation probability
       - Impact: Likely to be exploited despite moderate severity

    7. **Scope Change + High Impact**
       - S:C (Scope Changed) AND (C:H OR I:H OR A:H) AND CVSS >= 8.0
       - Justification: Can affect resources beyond the vulnerable component
       - Impact: Lateral movement and privilege escalation potential
    """

    def __init__(self):
        """Initialize the reassessment engine."""
        self.parser = CVSSParser()

    def reassess_severity(
        self,
        cvss_score: float | None,
        cvss_vector: str | None,
        epss_score: float | None,
        is_kev: bool = False,
        exposure_risk_factor: float = 1.0,
        asset_value_risk_factor: float = 1.0,
    ) -> tuple[str, str]:
        """
        Reassess vulnerability severity based on CVSS, EPSS, and environment context criteria.

        Args:
            cvss_score: CVSS base score (0-10)
            cvss_vector: CVSS vector string
            epss_score: EPSS score (0-1)
            is_kev: Whether vulnerability is in KEV catalog
            exposure_risk_factor: Risk factor based on service exposure (default: 1.0)
            asset_value_risk_factor: Risk factor based on asset value (default: 1.0)

        Returns:
            Tuple of (severity_level, justification)
        """
        # Handle missing data
        if cvss_score is None or pd.isna(cvss_score):
            return "Unknown", "Missing CVSS score"

        # Validate CVSS score is in valid range
        try:
            cvss_score = float(cvss_score)
            if not (0.0 <= cvss_score <= 10.0):
                logger.warning(f"CVSS score out of range [0, 10]: {cvss_score}")
                return "Unknown", f"Invalid CVSS score: {cvss_score}"
        except (ValueError, TypeError):
            logger.warning(f"CVSS score is not a number: {cvss_score}")
            return "Unknown", f"Invalid CVSS score: {cvss_score}"

        # Parse CVSS vector and validate
        components = {}
        if validate_cvss_vector(cvss_vector):
            components = self.parser.parse_cvss_vector(cvss_vector)
        elif cvss_vector:
            logger.debug(f"Invalid CVSS vector: {cvss_vector}")

        # Normalize and validate EPSS
        epss = normalize_epss(epss_score)

        # Validate and normalize risk factors
        exposure_risk_factor = validate_risk_factor(
            exposure_risk_factor, "exposure_risk_factor"
        )
        asset_value_risk_factor = validate_risk_factor(
            asset_value_risk_factor, "asset_value_risk_factor"
        )

        # Apply environment context factors to adjust the effective CVSS score
        adjusted_cvss_score = min(
            10.0, cvss_score * exposure_risk_factor * asset_value_risk_factor
        )

        # Add justification for environment factors if they're significant
        environment_justification = ""
        if exposure_risk_factor != 1.0 or asset_value_risk_factor != 1.0:
            environment_justification = f" (adjusted from {cvss_score:.1f} due to exposure factor {exposure_risk_factor:.1f} and asset value factor {asset_value_risk_factor:.1f})"

        # Apply reassessment criteria with adjusted score
        severity, justification = self._apply_critical_criteria(
            adjusted_cvss_score, components, epss, is_kev
        )

        if severity == "Critical":
            return severity, justification + environment_justification

        # Apply high severity criteria
        severity, justification = self._apply_high_criteria(
            adjusted_cvss_score, components, epss, is_kev
        )

        if severity == "High":
            return severity, justification + environment_justification

        # Apply medium severity criteria
        severity, justification = self._apply_medium_criteria(
            adjusted_cvss_score, components, epss
        )

        if severity == "Medium":
            return severity, justification + environment_justification

        # Apply low severity criteria
        severity, justification = self._apply_low_criteria(
            adjusted_cvss_score, components, epss
        )

        return severity, justification + environment_justification

    def _apply_critical_criteria(
        self,
        cvss_score: float,
        components: dict[str, str],
        epss_score: float,
        is_kev: bool,
    ) -> tuple[str, str]:
        """Apply CRITICAL severity criteria."""

        # Criterion 1: High CVSS + High EPSS
        if cvss_score >= 9.0 and epss_score >= 0.5:
            return (
                "Critical",
                "High CVSS (>=9.0) + High EPSS (>=0.5): Extremely severe with active exploitation",
            )

        # Criterion 2: Network RCE with low complexity
        av = self.parser.get_attack_vector(components)
        ac = self.parser.get_attack_complexity(components)
        integrity = self.parser.get_integrity(components)
        availability = self.parser.get_availability(components)

        if (
            av == "N"
            and ac == "L"
            and (integrity == "H" or availability == "H")
            and epss_score >= 0.3
        ):
            return (
                "Critical",
                "Network RCE (AV:N/AC:L) with high impact + EPSS>=0.3: Remote code execution",
            )

        # Criterion 3: Privilege escalation with scope change
        pr = self.parser.get_privileges_required(components)
        scope = self.parser.get_scope(components)

        if (
            pr in ["L", "N"]
            and (integrity == "H" or availability == "H")
            and scope == "C"
            and epss_score >= 0.4
        ):
            return (
                "Critical",
                "Privilege escalation (PR:L/N) with scope change (S:C) + EPSS>=0.4: System compromise",
            )

        # Criterion 4: Authentication bypass with data access
        confidentiality = self.parser.get_confidentiality(components)

        if (
            av == "N"
            and ac == "L"
            and pr == "N"
            and confidentiality == "H"
            and epss_score >= 0.4
        ):
            return (
                "Critical",
                "Authentication bypass (AV:N/AC:L/PR:N) with data access (C:H) + EPSS>=0.4: Unauthenticated data access",
            )

        # Criterion 5: Known exploited vulnerability
        if is_kev and cvss_score >= 7.0 and epss_score >= 0.25:
            return (
                "Critical",
                "Known Exploited Vulnerability (KEV) with high CVSS + EPSS>=0.25: Actively exploited",
            )

        # Criterion 6: High EPSS with moderate CVSS
        if cvss_score >= 7.0 and epss_score >= 0.7:
            return (
                "Critical",
                "High exploitation probability (EPSS>=0.7) with moderate-high CVSS: Real-world threat",
            )

        # Criterion 7: Scope change with high impact
        if (
            scope == "C"
            and (confidentiality == "H" or integrity == "H" or availability == "H")
            and cvss_score >= 8.0
        ):
            return (
                "Critical",
                "Scope change (S:C) with high impact (CVSS>=8.0): Lateral movement risk",
            )

        return "NotCritical", ""

    def _apply_high_criteria(
        self,
        cvss_score: float,
        components: dict[str, str],
        epss_score: float,
        is_kev: bool,
    ) -> tuple[str, str]:
        """Apply HIGH severity criteria."""

        # High CVSS score (standard CVSS-based assessment)
        if cvss_score >= 7.0:
            if epss_score >= 0.5:
                return (
                    "High",
                    f"High CVSS ({cvss_score}) + Moderate-High EPSS ({epss_score}): Enhanced confidence in high severity",
                )
            return (
                "High",
                f"High CVSS score ({cvss_score}): Standard CVSS-based assessment",
            )

        # Known Exploited Vulnerability
        if is_kev and cvss_score >= 5.0:
            return (
                "High",
                f"Known Exploited Vulnerability (KEV) with CVSS {cvss_score}: Active exploitation despite moderate severity",
            )

        # High EPSS with moderate CVSS
        if cvss_score >= 5.0 and epss_score >= 0.6:
            return (
                "High",
                f"Moderate CVSS ({cvss_score}) with high exploitation probability (EPSS {epss_score}): Likely to be exploited",
            )

        # Network-accessible High Impact
        av = self.parser.get_attack_vector(components)
        ac = self.parser.get_attack_complexity(components)
        integrity = self.parser.get_integrity(components)
        availability = self.parser.get_availability(components)

        if (
            av == "N"
            and ac == "L"
            and (integrity == "H" or availability == "H")
            and cvss_score >= 6.0
        ):
            return (
                "High",
                "Network-accessible with high impact (AV:N/AC:L + high I/A) with CVSS>=6.0: Easy exploitation with serious consequences",
            )

        return "NotHigh", ""

    def _apply_medium_criteria(
        self,
        cvss_score: float,
        components: dict[str, str],
        epss_score: float,
    ) -> tuple[str, str]:
        """Apply MEDIUM severity criteria."""

        # Moderate CVSS (standard CVSS-based assessment)
        if cvss_score >= 4.0:
            if epss_score >= 0.4:
                return (
                    "Medium",
                    f"Moderate CVSS ({cvss_score}) with notable exploitation probability (EPSS {epss_score}): Should be prioritized for patching",
                )
            return (
                "Medium",
                f"Moderate CVSS score ({cvss_score}): Standard CVSS-based assessment",
            )

        # Low CVSS but high EPSS
        if cvss_score >= 2.0 and epss_score >= 0.5:
            return (
                "Medium",
                f"Low CVSS ({cvss_score}) but high exploitation probability (EPSS {epss_score}): Likely to be exploited despite low severity",
            )

        return "NotMedium", ""

    def _apply_low_criteria(
        self,
        cvss_score: float,
        components: dict[str, str],
        epss_score: float,
    ) -> tuple[str, str]:
        """Apply LOW severity criteria."""

        # Low CVSS with Low EPSS
        if cvss_score < 4.0 and epss_score < 0.3:
            return (
                "Low",
                f"Low CVSS ({cvss_score}) with low exploitation probability (EPSS {epss_score}): Minimal immediate threat",
            )

        # Physical/Local Access Required
        av = self.parser.get_attack_vector(components)
        pr = self.parser.get_privileges_required(components)

        if av == "P" or (av == "L" and pr == "H"):
            return (
                "Low",
                f"Physical/Local access required (AV:{av}/PR:{pr}): Limited attack surface",
            )

        # Low CVSS (fallback)
        if cvss_score >= 0.1:
            if epss_score >= 0.3:
                return (
                    "Low",
                    f"Low CVSS ({cvss_score}) with some exploitation probability (EPSS {epss_score})",
                )
            return "Low", f"Low CVSS score ({cvss_score})"

        return "NotLow", ""

    def _default_severity(self, cvss_score: float) -> str:
        """Get default severity based on CVSS score."""
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        elif cvss_score >= 0.1:
            return "Low"
        else:
            return "Negligible"


def reassess_vulnerabilities(
    df: pd.DataFrame,
    cvss_score_col: str = "cvss_score",
    cvss_vector_col: str = "cvss_vector",
    epss_score_col: str = "epss_score",
    kev_col: str | None = None,
    exposure_risk_factor_col: str | None = None,
    asset_value_risk_factor_col: str | None = None,
    original_severity_col: str | None = None,
) -> pd.DataFrame:
    """
    Reassess all vulnerabilities in a DataFrame.

    Args:
        df: DataFrame with vulnerability data
        cvss_score_col: Column name for CVSS score
        cvss_vector_col: Column name for CVSS vector
        epss_score_col: Column name for EPSS score
        kev_col: Column name for KEV indicator
        exposure_risk_factor_col: Column name for exposure risk factor
        asset_value_risk_factor_col: Column name for asset value risk factor

    Returns:
        DataFrame with added 'severity_reassessed' and 'reassessment_reason' columns
    """
    reassessor = CVSSEPSSReassessment()

    def reassess_row(row: pd.Series) -> tuple[str, str]:
        """Reassess a single vulnerability."""
        # Use .get() for Series, which returns NaN if column doesn't exist
        cvss_score = row.get(cvss_score_col, None)
        cvss_vector = row.get(cvss_vector_col, None)
        epss_score = row.get(epss_score_col, None)
        is_kev = bool(row.get(kev_col, False)) if kev_col else False

        # Get environment context factors
        exposure_risk_factor = (
            row.get(exposure_risk_factor_col, 1.0) if exposure_risk_factor_col else 1.0
        )
        asset_value_risk_factor = (
            row.get(asset_value_risk_factor_col, 1.0)
            if asset_value_risk_factor_col
            else 1.0
        )

        # Get original severity for fallback
        original_severity = (
            row.get(original_severity_col, None) if original_severity_col else None
        )

        # If CVSS score is missing, fallback to original severity
        if (
            cvss_score is None or pd.isna(cvss_score)
        ) and original_severity is not None:
            return (
                original_severity,
                f"Fallback to original severity ({original_severity}) due to missing CVSS data",
            )

        return reassessor.reassess_severity(
            cvss_score,
            cvss_vector,
            epss_score,
            is_kev,
            exposure_risk_factor,
            asset_value_risk_factor,
        )

    # Apply reassessment
    logger.info("Reassessing vulnerabilities based on CVSS vectors and EPSS scores...")
    logger.info(f"  Available columns: {list(df.columns)}")
    logger.info(
        f"  CVSS score column: {cvss_score_col} (exists: {cvss_score_col in df.columns})"
    )
    logger.info(
        f"  CVSS vector column: {cvss_vector_col} (exists: {cvss_vector_col in df.columns})"
    )
    logger.info(
        f"  EPSS score column: {epss_score_col} (exists: {epss_score_col in df.columns})"
    )

    results = df.apply(reassess_row, axis=1, result_type="expand")
    df["severity_reassessed"] = results[0]
    df["reassessment_reason"] = results[1]

    critical_count = (df["severity_reassessed"] == "Critical").sum()
    high_count = (df["severity_reassessed"] == "High").sum()
    medium_count = (df["severity_reassessed"] == "Medium").sum()
    unknown_count = (df["severity_reassessed"] == "Unknown").sum()

    logger.info(
        f"Reassessment complete. Critical: {critical_count}, High: {high_count}, "
        f"Medium: {medium_count}, Unknown: {unknown_count}"
    )

    return df
