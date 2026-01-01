"""Control Correlation Engine for Realistic Security Control Generation.

Models organizational behavior where security controls are implemented in suites
based on security maturity, budget, and organizational culture.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from src.utils.security_controls_config import get_security_controls_config

logger = logging.getLogger(__name__)


class ControlCorrelationEngine:
    """Applies control correlations to generate realistic security postures.

    This engine models realistic organizational behavior where:
    - Controls are implemented in suites (defense in depth)
    - Some controls are prerequisites for others (e.g., SIEM needed for SOAR)
    - Security maturity affects control presence
    - Budget constraints create gaps in related controls
    """

    def __init__(self) -> None:
        """Initialize the correlation engine."""
        self.config = get_security_controls_config()
        self.correlations = self.config.metadata.get("control_correlations", {})

        # Load correlation data from config
        if hasattr(self.config, "control_correlations"):
            self.correlations = self.config.control_correlations
        else:
            self.correlations = {}
            logger.warning("No control correlations found in config")

    def apply_correlations(
        self,
        initial_controls: dict[str, bool],
        maturity_level: int = 3,
        randomness: float = 0.2,
    ) -> dict[str, bool]:
        """Apply control correlations to generate realistic control set.

        Args:
            initial_controls: Initial control presence (seed controls)
            maturity_level: Organization security maturity (1-5)
            randomness: Amount of randomness (0.0-1.0). Higher = more variation

        Returns:
            Enhanced control set with correlations applied

        Example:
            >>> engine = ControlCorrelationEngine()
            >>> initial = {"mfa": True, "firewall": True}
            >>> enhanced = engine.apply_correlations(initial, maturity_level=3)
            >>> # enhanced likely has sso_with_mfa, iam_platform, etc.
        """
        # Start with initial controls
        controls = initial_controls.copy()

        # Apply maturity-based controls first
        controls = self._apply_maturity_level(controls, maturity_level, randomness)

        # Apply positive correlations (if control exists, add related)
        controls = self._apply_positive_correlations(controls, randomness)

        # Apply negative correlations (if control missing, remove related)
        controls = self._apply_negative_correlations(controls, randomness)

        return controls

    def _apply_maturity_level(
        self, controls: dict[str, bool], maturity_level: int, randomness: float
    ) -> dict[str, bool]:
        """Apply maturity-level based control presence.

        Organizations at higher maturity levels have more controls.
        """
        if not hasattr(self.config, "control_maturity_levels"):
            return controls

        maturity_levels = self.config.control_maturity_levels

        # Apply controls for this maturity level and below
        for level in range(1, maturity_level + 1):
            level_key = (
                f"level_{level}_initial"
                if level == 1
                else f"level_{level}_managed"
                if level == 2
                else f"level_{level}_defined"
                if level == 3
                else f"level_{level}_quantitatively_managed"
                if level == 4
                else f"level_{level}_optimizing"
            )

            if level_key not in maturity_levels:
                continue

            level_data = maturity_levels[level_key]
            typical_controls = level_data.get("typical_controls", [])
            base_probability = level_data.get("probability", 0.7)

            for control in typical_controls:
                # Adjust probability with randomness
                prob = base_probability * (1.0 - randomness * random.uniform(-0.5, 0.5))
                prob = max(0.0, min(1.0, prob))  # Clamp to [0, 1]

                # Only set if not already decided
                if control not in controls:
                    controls[control] = random.random() < prob

        return controls

    def _apply_positive_correlations(
        self, controls: dict[str, bool], randomness: float
    ) -> dict[str, bool]:
        """Apply positive correlations.

        If a control exists, related controls are more likely to exist.
        """
        # Multiple passes to propagate correlations
        for _ in range(3):  # 3 passes to propagate through chains
            for control_name, is_present in list(controls.items()):
                if not is_present:
                    continue

                # Get correlations for this control
                if control_name not in self.correlations:
                    continue

                control_corr = self.correlations[control_name]
                positive_corrs = control_corr.get("positive_correlations", [])

                for corr in positive_corrs:
                    related_control = corr.get("control")
                    base_prob = corr.get("probability", 0.7)

                    # Skip if already decided
                    if related_control in controls:
                        continue

                    # Adjust probability with randomness
                    prob = base_prob * (1.0 - randomness * random.uniform(-0.5, 0.5))
                    prob = max(0.0, min(1.0, prob))

                    # Add correlated control
                    controls[related_control] = random.random() < prob

                    if controls[related_control]:
                        logger.debug(
                            f"Positive correlation: {control_name} -> {related_control} "
                            f"(prob={prob:.2f})"
                        )

        return controls

    def _apply_negative_correlations(
        self, controls: dict[str, bool], randomness: float
    ) -> dict[str, bool]:
        """Apply negative correlations.

        If a control is missing, related controls are less likely to exist.
        """
        for control_name, is_present in list(controls.items()):
            if is_present:
                continue  # Only process missing controls

            # Get correlations for this control
            if control_name not in self.correlations:
                continue

            control_corr = self.correlations[control_name]
            negative_corrs = control_corr.get("negative_correlations", [])

            for corr in negative_corrs:
                related_control = corr.get("control")
                base_prob = corr.get("probability", 0.3)

                # Skip if already decided as present
                if related_control in controls and controls[related_control]:
                    continue

                # Adjust probability with randomness
                prob = base_prob * (1.0 - randomness * random.uniform(-0.5, 0.5))
                prob = max(0.0, min(1.0, prob))

                # Reduce likelihood of correlated control
                if related_control not in controls:
                    controls[related_control] = random.random() < prob

                    if not controls[related_control]:
                        logger.debug(
                            f"Negative correlation: !{control_name} -> !{related_control} "
                            f"(prob={prob:.2f})"
                        )

        return controls

    def generate_realistic_controls(
        self,
        maturity_level: int = 3,
        seed_controls: dict[str, bool] | None = None,
        randomness: float = 0.2,
        sector: str | None = None,
    ) -> dict[str, bool]:
        """Generate a realistic set of security controls.

        Args:
            maturity_level: Organization security maturity (1-5)
            seed_controls: Optional seed controls to start with
            randomness: Amount of variation (0.0-1.0)
            sector: Optional sector (e.g., 'financial_services', 'education')

        Returns:
            Dictionary of control names to presence (True/False)

        Example:
            >>> engine = ControlCorrelationEngine()
            >>> controls = engine.generate_realistic_controls(
            ...     maturity_level=4, sector='financial_services'
            ... )
            >>> # Returns realistic control set for financial sector
        """
        if seed_controls is None:
            seed_controls = {}

        # Apply sector adjustment to maturity level
        effective_maturity = maturity_level
        if sector and hasattr(self.config, "sector_maturity_adjustments"):
            sector_data = self.config.sector_maturity_adjustments.get(sector, {})
            if isinstance(sector_data, dict):
                multiplier = sector_data.get("multiplier", 1.0)
                # Adjust randomness based on sector (well-invested = less random)
                randomness = randomness * (2.0 - multiplier)
                randomness = max(0.1, min(0.5, randomness))
                logger.info(
                    f"Sector '{sector}' adjustment: multiplier={multiplier:.2f}, "
                    f"adjusted_randomness={randomness:.2f}"
                )

        # Apply correlations
        controls = self.apply_correlations(
            seed_controls, effective_maturity, randomness
        )

        # Log summary
        present_controls = [k for k, v in controls.items() if v]
        sector_info = f" (sector: {sector})" if sector else ""
        logger.info(
            f"Generated {len(present_controls)} controls for maturity level "
            f"{maturity_level}{sector_info}"
        )

        return controls

    def explain_control_presence(
        self, control_name: str, controls: dict[str, bool]
    ) -> dict[str, Any]:
        """Explain why a control is present or absent.

        Args:
            control_name: Name of control to explain
            controls: Current control set

        Returns:
            Explanation dictionary with reasons
        """
        is_present = controls.get(control_name, False)

        explanation = {
            "control": control_name,
            "present": is_present,
            "reasons": [],
            "related_controls": {
                "supporting": [],  # Controls that support this one
                "dependent": [],  # Controls that depend on this one
            },
        }

        if control_name not in self.correlations:
            explanation["reasons"].append("No correlations defined")
            return explanation

        control_corr = self.correlations[control_name]

        # Check positive correlations
        positive_corrs = control_corr.get("positive_correlations", [])
        for corr in positive_corrs:
            related = corr["control"]
            if related in controls and controls[related]:
                explanation["related_controls"]["supporting"].append(
                    {"control": related, "probability": corr["probability"]}
                )
                if is_present:
                    explanation["reasons"].append(
                        f"Correlated with {related} (prob={corr['probability']:.0%})"
                    )

        # Check negative correlations
        negative_corrs = control_corr.get("negative_correlations", [])
        for corr in negative_corrs:
            related = corr["control"]
            if related in controls and not controls[related]:
                explanation["related_controls"]["dependent"].append(
                    {"control": related, "probability": corr["probability"]}
                )
                if not is_present:
                    explanation["reasons"].append(
                        f"Missing prerequisite: {related} (prob={corr['probability']:.0%})"
                    )

        return explanation


def generate_correlated_controls(
    maturity_level: int = 3,
    seed_controls: dict[str, bool] | None = None,
    randomness: float = 0.2,
    sector: str | None = None,
) -> dict[str, bool]:
    """Convenience function to generate correlated controls.

    Args:
        maturity_level: Organization security maturity (1-5)
        seed_controls: Optional seed controls
        randomness: Amount of variation (0.0-1.0)
        sector: Optional sector (e.g., 'financial_services', 'education')

    Returns:
        Dictionary of control names to presence
    """
    engine = ControlCorrelationEngine()
    return engine.generate_realistic_controls(
        maturity_level, seed_controls, randomness, sector
    )
