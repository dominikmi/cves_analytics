"""EPSS trajectory analysis for temporal risk assessment.

This module provides functionality to analyze EPSS score changes over time
to better assess vulnerability risk based on exploitation trends rather than
static patch availability assumptions.

Theoretical Foundation:
Based on the Work-Averse Cyberattacker Model (Allodi et al., 2021), which
analyzed 2 million attack signatures and found:
- Attackers face high initial costs for exploit development
- Selective exploitation: not all vulnerabilities are weaponized
- Weaponization lag: significant delay between disclosure and mass exploitation

Key Insight:
EPSS naturally captures patch adoption through observed exploitation patterns.
- Declining EPSS after patch = widespread adoption reducing risk
- Persistent high EPSS despite patch = sustained threat (many unpatched systems)
- Rising EPSS = active exploitation increasing

References:
- Allodi, L., Massacci, F., & Williams, J. (2021). "The Work-Averse
  Cyberattacker Model: Theory and Evidence from Two Million Attack Signatures".
  Risk Analysis, 42(8), 1623-1642. https://doi.org/10.1111/risa.13732
- FIRST.org EPSS Model: https://www.first.org/epss/model
- EPSS API Documentation: https://www.first.org/epss/api
"""

import gzip
from datetime import datetime, timedelta
from pathlib import Path

import polars as pl
import requests

from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class EPSSTrajectory:
    """Manages EPSS historical data and trajectory analysis."""

    def __init__(self, data_directory: str = "data/download"):
        """Initialize EPSS trajectory analyzer.

        Args:
            data_directory: Base directory for EPSS data storage
        """
        self.data_dir = Path(data_directory) / "EPSS"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @error_handler()
    def download_historical_epss(
        self,
        target_date: str,
        days_back: int = 90,
    ) -> dict[str, str]:
        """Download historical EPSS scores for trajectory analysis.

        Args:
            target_date: Target date in YYYY-MM-DD format
            days_back: Number of days of historical data to fetch (default 90)

        Returns:
            Dictionary mapping date strings to file paths
        """
        target_dt = datetime.strptime(target_date, "%Y-%m-%d")
        downloaded_files = {}

        # Download current, -30d, -90d snapshots
        for days_offset in [0, 30, days_back]:
            date = target_dt - timedelta(days=days_offset)
            # EPSS publishes with 1-day delay
            epss_date = (date - timedelta(days=1)).strftime("%Y-%m-%d")
            date_str = date.strftime("%Y-%m-%d")

            file_path = self._download_epss_for_date(epss_date)
            if file_path:
                downloaded_files[date_str] = file_path
                logger.info(f"Downloaded EPSS for {date_str}: {file_path}")
            else:
                logger.warning(f"Failed to download EPSS for {date_str}")

        return downloaded_files

    def _download_epss_for_date(self, date: str) -> str | None:
        """Download EPSS scores for a specific date.

        Args:
            date: Date in YYYY-MM-DD format

        Returns:
            Path to unzipped CSV file or None if failed
        """
        file_path = self.data_dir / f"epss_scores-{date}.csv.gz"
        unzipped_path = file_path.with_suffix("")

        try:
            # Check if unzipped file already exists
            if unzipped_path.exists():
                logger.debug(f"EPSS file already exists: {unzipped_path}")
                return str(unzipped_path)

            # Check if gzipped file exists
            if file_path.exists():
                logger.debug(f"Unzipping existing file: {file_path}")
            else:
                # Download from EPSS API
                url = f"https://epss.cyentia.com/epss_scores-{date}.csv.gz"
                logger.info(f"Downloading EPSS from {url}")
                response = requests.get(url, timeout=60)
                response.raise_for_status()

                with open(file_path, "wb") as f:
                    f.write(response.content)
                logger.info(f"Downloaded {file_path}")

            # Ungzip the file
            with gzip.open(file_path, "rb") as f_in:
                with open(unzipped_path, "wb") as f_out:
                    f_out.write(f_in.read())

            return str(unzipped_path)

        except requests.RequestException as e:
            logger.error(f"Failed to download EPSS for {date}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error processing EPSS file for {date}: {e}")
            return None

    @error_handler()
    def load_epss_snapshot(self, file_path: str) -> pl.DataFrame:
        """Load EPSS snapshot from CSV file.

        Args:
            file_path: Path to EPSS CSV file

        Returns:
            Polars DataFrame with cve and epss columns
        """
        try:
            df = pl.read_csv(
                file_path,
                skip_rows=1,  # Skip header comment
                has_header=True,
                columns=["cve", "epss"],
            )
            return df
        except Exception as e:
            logger.error(f"Failed to load EPSS snapshot from {file_path}: {e}")
            return pl.DataFrame({"cve": [], "epss": []})

    def calculate_trajectory_factor(
        self,
        epss_current: float,
        epss_30d_ago: float | None,
        epss_90d_ago: float | None,
    ) -> float:
        """Calculate risk adjustment based on EPSS trajectory.

        Trajectory Analysis:
        - Declining EPSS: Patch adoption reducing risk → use current EPSS (1.0x)
        - Rising EPSS: Active exploitation increasing → amplify risk (1.2x)
        - Stable EPSS: Sustained threat → use current EPSS (1.0x)

        Args:
            epss_current: Current EPSS score
            epss_30d_ago: EPSS score 30 days ago (None if unavailable)
            epss_90d_ago: EPSS score 90 days ago (None if unavailable)

        Returns:
            Trajectory factor (1.0 = baseline, 1.2 = rising threat)
        """
        # Convert to float if needed (handle string types)
        try:
            epss_current = float(epss_current) if epss_current is not None else 0.0
            epss_30d_ago = float(epss_30d_ago) if epss_30d_ago is not None else None
            epss_90d_ago = float(epss_90d_ago) if epss_90d_ago is not None else None
        except (ValueError, TypeError):
            return 1.0  # Baseline if conversion fails

        # If no historical data, use baseline
        if epss_30d_ago is None or epss_90d_ago is None:
            return 1.0

        # Calculate 90-day trend (change per day)
        trend_90d = (epss_current - epss_90d_ago) / 90

        # Thresholds for significant change (0.1% per day = 9% over 90 days)
        DECLINE_THRESHOLD = -0.001
        RISE_THRESHOLD = 0.001

        if trend_90d < DECLINE_THRESHOLD:
            # Declining EPSS indicates patch adoption or waning interest
            return 1.0  # Risk naturally declining
        elif trend_90d > RISE_THRESHOLD:
            # Rising EPSS indicates active exploitation or new exploits
            return 1.2  # Amplify risk by 20%
        else:
            # Stable EPSS indicates sustained threat level
            return 1.0  # Use current EPSS as-is

    def enrich_with_trajectory(
        self,
        df: pl.DataFrame,
        current_date: str,
        cve_col: str = "cve_id",
        epss_col: str = "epss_score",
    ) -> pl.DataFrame:
        """Enrich vulnerability DataFrame with EPSS trajectory analysis.

        Args:
            df: DataFrame with vulnerabilities
            current_date: Current date in YYYY-MM-DD format
            cve_col: Column name for CVE ID
            epss_col: Column name for current EPSS score

        Returns:
            DataFrame with additional columns:
            - epss_30d_ago: EPSS score 30 days ago
            - epss_90d_ago: EPSS score 90 days ago
            - epss_trajectory_factor: Risk adjustment factor
        """
        # Download historical EPSS data
        historical_files = self.download_historical_epss(current_date, days_back=90)

        if not historical_files:
            logger.warning("No historical EPSS data available, using baseline factors")
            return df.with_columns(
                [
                    pl.lit(None).alias("epss_30d_ago"),
                    pl.lit(None).alias("epss_90d_ago"),
                    pl.lit(1.0).alias("epss_trajectory_factor"),
                ]
            )

        # Load historical snapshots
        target_dt = datetime.strptime(current_date, "%Y-%m-%d")
        date_30d = (target_dt - timedelta(days=30)).strftime("%Y-%m-%d")
        date_90d = (target_dt - timedelta(days=90)).strftime("%Y-%m-%d")

        epss_30d = None
        epss_90d = None

        if date_30d in historical_files:
            epss_30d = self.load_epss_snapshot(historical_files[date_30d])
            epss_30d = epss_30d.rename({"epss": "epss_30d_ago"})

        if date_90d in historical_files:
            epss_90d = self.load_epss_snapshot(historical_files[date_90d])
            epss_90d = epss_90d.rename({"epss": "epss_90d_ago"})

        # Join historical data
        result = df
        if epss_30d is not None:
            result = result.join(
                epss_30d,
                left_on=cve_col,
                right_on="cve",
                how="left",
            )
        else:
            result = result.with_columns([pl.lit(None).alias("epss_30d_ago")])

        if epss_90d is not None:
            result = result.join(
                epss_90d,
                left_on=cve_col,
                right_on="cve",
                how="left",
            )
        else:
            result = result.with_columns([pl.lit(None).alias("epss_90d_ago")])

        # Calculate trajectory factors
        result = result.with_columns(
            [
                pl.struct([epss_col, "epss_30d_ago", "epss_90d_ago"])
                .map_elements(
                    lambda x: self.calculate_trajectory_factor(
                        x[epss_col],
                        x["epss_30d_ago"],
                        x["epss_90d_ago"],
                    ),
                    return_dtype=pl.Float64,
                )
                .alias("epss_trajectory_factor")
            ]
        )

        return result
