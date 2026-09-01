"""Attack path analysis service."""

import polars as pl

from src.core.attack.kill_chain import KillChainCalculator
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class AttackPathService:
    """Analyze attack paths through kill chain stages.

    Identifies chained vulnerabilities that form complete attack paths.
    """

    @staticmethod
    def analyze(df: pl.DataFrame) -> pl.DataFrame:
        """Analyze attack paths in findings DataFrame.

        Args:
            df: Enriched vulnerability DataFrame.

        Returns:
            DataFrame with kill chain probability annotations.
        """
        if df.is_empty():
            return df

        calculator = KillChainCalculator()

        # Require kill chain data to proceed
        if "kill_chain_phase" not in df.columns:
            logger.warning("No kill_chain_phase column, skipping analysis")
            return df

        # Convert DataFrame rows to list of dicts
        vulns = df.to_dicts()

        # Default security controls (all enabled)
        security_controls: dict[str, bool] = {
            "waf": True,
            "ids": True,
            "rbac": True,
            "network_segmentation": True,
        }

        # Calculate kill chain probability
        result = calculator.calculate_kill_chain_probability(
            application={},
            vulnerabilities=vulns,
            security_controls=security_controls,
            docker_security_good=True,
        )

        # Add kill chain probability column
        df = df.with_columns(
            pl.lit(result.overall_probability).alias("kill_chain_probability")
        )

        return df
