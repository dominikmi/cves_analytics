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
        use_bayesian: bool = True,
    ) -> dict[str, Any]:
        """
        Create phased remediation plan based on Bayesian risk assessment.

        Args:
            enriched_results: DataFrame with vulnerability data
            severity_column: Column name for severity assessment (fallback)
            use_bayesian: If True, use risk_category from Bayesian assessment

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

        # Prefer Bayesian risk_category over severity_reassessed
        if use_bayesian and "risk_category" in enriched_results.columns:
            category_column = "risk_category"
            sort_column = (
                "bayesian_risk_score"
                if "bayesian_risk_score" in enriched_results.columns
                else "risk_score"
            )
            self.logger.info("Using Bayesian risk_category for remediation planning")
        else:
            # Fallback to severity_reassessed
            if severity_column not in enriched_results.columns:
                category_column = "severity"
            else:
                category_column = severity_column
            sort_column = (
                "risk_score"
                if "risk_score" in enriched_results.columns
                else category_column
            )

        # Phase 1: Bayesian Critical vulnerabilities ONLY (Week 1)
        phase1_vulns = enriched_results[enriched_results[category_column] == "Critical"]
        if sort_column in enriched_results.columns:
            phase1 = phase1_vulns.nlargest(20, sort_column)
        else:
            phase1 = phase1_vulns.head(20)

        phase1_effort = len(phase1) * self.EFFORT_ESTIMATES["Critical"]
        phase1_weeks = (
            ceil(phase1_effort / self.WORK_WEEK_HOURS) if phase1_effort > 0 else 1
        )

        # Phase 2: Bayesian High vulnerabilities (Weeks 2-3)
        phase2_vulns = enriched_results[enriched_results[category_column] == "High"]
        if sort_column in enriched_results.columns:
            phase2 = phase2_vulns.nlargest(50, sort_column)
        else:
            phase2 = phase2_vulns.head(50)

        phase2_effort = len(phase2) * self.EFFORT_ESTIMATES["High"]
        phase2_weeks = (
            ceil(phase2_effort / self.WORK_WEEK_HOURS) if phase2_effort > 0 else 1
        )

        # Phase 3: Bayesian Medium vulnerabilities (Weeks 4-6)
        phase3_vulns = enriched_results[enriched_results[category_column] == "Medium"]
        if sort_column in enriched_results.columns:
            phase3 = phase3_vulns.nlargest(100, sort_column)
        else:
            phase3 = phase3_vulns.head(100)

        phase3_effort = len(phase3) * self.EFFORT_ESTIMATES["Medium"]
        phase3_weeks = (
            ceil(phase3_effort / self.WORK_WEEK_HOURS) if phase3_effort > 0 else 1
        )

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

    def estimate_total_effort(
        self, enriched_results: pd.DataFrame, use_bayesian: bool = True
    ) -> dict[str, Any]:
        """
        Estimate total remediation effort based on Bayesian risk categories.

        Args:
            enriched_results: DataFrame with vulnerability data
            use_bayesian: If True, use risk_category from Bayesian assessment

        Returns:
            Dictionary with effort estimates (only for Bayesian Critical/High/Medium)
        """
        if enriched_results.empty:
            return {
                "total_hours": 0,
                "total_weeks": 0,
                "total_people_weeks": 0,
                "breakdown": {},
            }

        # Prefer Bayesian risk_category over severity_reassessed
        if use_bayesian and "risk_category" in enriched_results.columns:
            category_column = "risk_category"
        elif "severity_reassessed" in enriched_results.columns:
            category_column = "severity_reassessed"
        else:
            category_column = "severity"

        breakdown = {}
        total_hours = 0

        # Only count Critical, High, Medium for remediation effort
        # Low and Negligible are not prioritized for remediation
        for severity in ["Critical", "High", "Medium"]:
            effort = self.EFFORT_ESTIMATES.get(severity, 1.0)
            count = (enriched_results[category_column] == severity).sum()
            hours = count * effort
            total_hours += hours
            breakdown[severity] = {"count": int(count), "effort_hours": hours}

        total_weeks = ceil(total_hours / self.WORK_WEEK_HOURS) if total_hours > 0 else 0
        total_people_weeks = (
            ceil(total_hours / self.WORK_WEEK_HOURS) if total_hours > 0 else 0
        )

        return {
            "total_hours": total_hours,
            "total_weeks": total_weeks,
            "total_people_weeks": total_people_weeks,
            "breakdown": breakdown,
        }
