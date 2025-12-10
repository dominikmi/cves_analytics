"""Remediation planning module for phased vulnerability fixes."""

import logging
from math import ceil
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


class RemediationPlanner:
    """Plan phased remediation of vulnerabilities."""

    # Effort estimates (hours per vulnerability)
    EFFORT_ESTIMATES = {
        "Critical": 4.0,
        "High": 2.0,
        "Medium": 1.0,
        "Low": 0.5,
        "Unknown": 1.0,
    }

    # Work week hours
    WORK_WEEK_HOURS = 40

    def __init__(self):
        """Initialize remediation planner."""
        self.logger = logger

    def create_remediation_roadmap(
        self,
        enriched_results: pd.DataFrame,
        severity_column: str = "severity_reassessed",
    ) -> dict[str, Any]:
        """
        Create phased remediation plan.

        Args:
            enriched_results: DataFrame with vulnerability data
            severity_column: Column name for severity assessment

        Returns:
            Dictionary with phases and effort estimates
        """
        if enriched_results.empty:
            return {
                "phase1": {
                    "vulns": pd.DataFrame(),
                    "effort_hours": 0,
                    "timeline": "Week 1",
                },
                "phase2": {
                    "vulns": pd.DataFrame(),
                    "effort_hours": 0,
                    "timeline": "Weeks 2-3",
                },
                "phase3": {
                    "vulns": pd.DataFrame(),
                    "effort_hours": 0,
                    "timeline": "Weeks 4-6",
                },
            }

        # Ensure severity column exists
        if severity_column not in enriched_results.columns:
            severity_column = "severity"

        # Phase 1: Critical vulnerabilities (Week 1)
        phase1 = enriched_results[
            enriched_results[severity_column] == "Critical"
        ].nlargest(
            20,
            "risk_score"
            if "risk_score" in enriched_results.columns
            else severity_column,
        )

        phase1_effort = len(phase1) * self.EFFORT_ESTIMATES["Critical"]
        phase1_weeks = ceil(phase1_effort / self.WORK_WEEK_HOURS)

        # Phase 2: High vulnerabilities (Weeks 2-3)
        phase2 = enriched_results[enriched_results[severity_column] == "High"].nlargest(
            50,
            "risk_score"
            if "risk_score" in enriched_results.columns
            else severity_column,
        )

        phase2_effort = len(phase2) * self.EFFORT_ESTIMATES["High"]
        phase2_weeks = ceil(phase2_effort / self.WORK_WEEK_HOURS)

        # Phase 3: Medium vulnerabilities (Weeks 4-6)
        phase3 = enriched_results[
            enriched_results[severity_column] == "Medium"
        ].nlargest(
            100,
            "risk_score"
            if "risk_score" in enriched_results.columns
            else severity_column,
        )

        phase3_effort = len(phase3) * self.EFFORT_ESTIMATES["Medium"]
        phase3_weeks = ceil(phase3_effort / self.WORK_WEEK_HOURS)

        roadmap = {
            "phase1": {
                "vulns": phase1,
                "count": len(phase1),
                "effort_hours": phase1_effort,
                "timeline_weeks": phase1_weeks,
                "timeline": "Week 1 (ASAP)",
                "severity": "Critical",
            },
            "phase2": {
                "vulns": phase2,
                "count": len(phase2),
                "effort_hours": phase2_effort,
                "timeline_weeks": phase2_weeks,
                "timeline": f"Weeks 2-{1 + phase2_weeks}",
                "severity": "High",
            },
            "phase3": {
                "vulns": phase3,
                "count": len(phase3),
                "effort_hours": phase3_effort,
                "timeline_weeks": phase3_weeks,
                "timeline": f"Weeks {2 + phase2_weeks}-{1 + phase2_weeks + phase3_weeks}",
                "severity": "Medium",
            },
        }

        total_effort = phase1_effort + phase2_effort + phase3_effort
        total_weeks = phase1_weeks + phase2_weeks + phase3_weeks

        self.logger.info(
            f"Remediation roadmap: {len(phase1)} critical, {len(phase2)} high, {len(phase3)} medium"
        )
        self.logger.info(
            f"Total effort: {total_effort:.1f} hours ({total_weeks} weeks)"
        )

        return roadmap

    def identify_quick_wins(
        self, enriched_results: pd.DataFrame, max_effort_hours: float = 4.0
    ) -> pd.DataFrame:
        """
        Identify vulnerabilities that can be fixed quickly.

        Quick wins are high-impact vulnerabilities with low complexity.

        Args:
            enriched_results: DataFrame with vulnerability data
            max_effort_hours: Maximum effort threshold for quick wins

        Returns:
            DataFrame with quick win vulnerabilities
        """
        if enriched_results.empty:
            return pd.DataFrame()

        # Quick wins: high risk but low complexity
        # Criteria: Risk score >= 6 AND effort <= max_effort_hours
        quick_wins = enriched_results[
            (enriched_results.get("risk_score", 5.0) >= 6.0)
            & (
                enriched_results.get("severity_reassessed", "Unknown").isin(
                    ["Critical", "High"]
                )
            )
        ].copy()

        # Estimate effort if not available
        if "estimated_effort_hours" not in quick_wins.columns:
            quick_wins["estimated_effort_hours"] = quick_wins[
                "severity_reassessed"
            ].map(self.EFFORT_ESTIMATES)

        # Filter by effort threshold
        quick_wins = quick_wins[
            quick_wins["estimated_effort_hours"] <= max_effort_hours
        ]

        # Sort by risk score
        if "risk_score" in quick_wins.columns:
            quick_wins = quick_wins.sort_values("risk_score", ascending=False)

        self.logger.info(
            f"Identified {len(quick_wins)} quick wins (effort <= {max_effort_hours}h)"
        )

        return quick_wins

    def estimate_total_effort(self, enriched_results: pd.DataFrame) -> dict[str, Any]:
        """
        Estimate total remediation effort.

        Args:
            enriched_results: DataFrame with vulnerability data

        Returns:
            Dictionary with effort estimates
        """
        if enriched_results.empty:
            return {
                "total_hours": 0,
                "total_weeks": 0,
                "total_people_weeks": 0,
                "breakdown": {},
            }

        severity_column = (
            "severity_reassessed"
            if "severity_reassessed" in enriched_results.columns
            else "severity"
        )

        breakdown = {}
        total_hours = 0

        for severity, effort in self.EFFORT_ESTIMATES.items():
            count = (enriched_results[severity_column] == severity).sum()
            hours = count * effort
            total_hours += hours
            breakdown[severity] = {"count": count, "effort_hours": hours}

        total_weeks = ceil(total_hours / self.WORK_WEEK_HOURS)
        total_people_weeks = ceil(total_hours / self.WORK_WEEK_HOURS)

        return {
            "total_hours": total_hours,
            "total_weeks": total_weeks,
            "total_people_weeks": total_people_weeks,
            "breakdown": breakdown,
        }
