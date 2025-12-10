"""Optimized CVE v5 data loader with parallel processing and caching."""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)


class CVEv5Loader:
    """Optimized CVE v5 data loader with caching and progress tracking."""

    def __init__(self, cache_dir: str = "./data/.cache"):
        """Initialize the loader with optional caching."""
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, start_year: int, end_year: int) -> Path:
        """Get cache file path for year range."""
        return self.cache_dir / f"cve_v5_{start_year}_{end_year}.parquet"

    def _load_from_cache(self, start_year: int, end_year: int) -> pd.DataFrame | None:
        """Load CVE data from cache if available."""
        cache_path = self._get_cache_path(start_year, end_year)
        if cache_path.exists():
            try:
                logger.info(f"Loading CVE data from cache: {cache_path}")
                return pd.read_parquet(cache_path)
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
                return None
        return None

    def _save_to_cache(self, df: pd.DataFrame, start_year: int, end_year: int) -> None:
        """Save CVE data to cache."""
        try:
            cache_path = self._get_cache_path(start_year, end_year)
            df.to_parquet(cache_path, index=False)
            logger.info(f"Cached CVE data to: {cache_path}")
        except Exception as e:
            logger.warning(f"Failed to cache data: {e}")

    def _parse_cve_file(
        self, json_file: Path, cve_ids: set[str] | None = None
    ) -> dict[str, Any] | None:
        """Parse a single CVE JSON file efficiently."""
        try:
            with open(json_file) as f:
                record = json.load(f)

            # Extract CVE ID
            cve_id = record.get("cveMetadata", {}).get("cveId", "")
            if not cve_id:
                return None

            # Skip if filtering by CVE IDs
            if cve_ids and cve_id not in cve_ids:
                return None

            # Extract CVSS metrics
            metrics = record.get("containers", {}).get("cna", {}).get("metrics", [])
            cvss_data = {}

            # Use first match for each CVSS version (priority order)
            for metric in metrics:
                if "cvssV4_0" in metric and "cvss_v4_0_score" not in cvss_data:
                    cvss_data["cvss_v4_0_score"] = metric["cvssV4_0"].get("baseScore")
                    cvss_data["cvss_v4_0_vector"] = metric["cvssV4_0"].get(
                        "vectorString"
                    )
                elif "cvssV3_1" in metric and "cvss_v3_1_score" not in cvss_data:
                    cvss_data["cvss_v3_1_score"] = metric["cvssV3_1"].get("baseScore")
                    cvss_data["cvss_v3_1_vector"] = metric["cvssV3_1"].get(
                        "vectorString"
                    )
                elif "cvssV3_0" in metric and "cvss_v3_0_score" not in cvss_data:
                    cvss_data["cvss_v3_0_score"] = metric["cvssV3_0"].get("baseScore")
                    cvss_data["cvss_v3_0_vector"] = metric["cvssV3_0"].get(
                        "vectorString"
                    )
                elif "cvssV2_0" in metric and "cvss_v2_0_score" not in cvss_data:
                    cvss_data["cvss_v2_0_score"] = metric["cvssV2_0"].get("baseScore")
                    cvss_data["cvss_v2_0_vector"] = metric["cvssV2_0"].get(
                        "vectorString"
                    )

            # Extract description
            descriptions = (
                record.get("containers", {}).get("cna", {}).get("descriptions", [])
            )
            description = descriptions[0].get("value", "") if descriptions else ""

            # Extract CWE
            problem_types = (
                record.get("containers", {}).get("cna", {}).get("problemTypes", [])
            )
            cwe_id = ""
            if problem_types:
                cwe_list = problem_types[0].get("descriptions", [])
                if cwe_list:
                    cwe_id = cwe_list[0].get("cweId", "")

            # Build record
            return {
                "cve_id": cve_id,
                "description": description,
                "cwe_id": cwe_id,
                **cvss_data,
            }

        except Exception as e:
            logger.debug(f"Error processing {json_file}: {e}")
            return None

    def load_cvev5_cve_data(
        self,
        start_year: int,
        end_year: int,
        directory: str,
        cve_ids: list[str] | None = None,
        use_cache: bool = True,
        max_workers: int = 8,
    ) -> pd.DataFrame:
        """
        Load CVE v5 data with parallel processing and caching.

        Args:
            start_year: Start year for CVE data
            end_year: End year for CVE data
            directory: Directory containing CVE data
            cve_ids: Optional list of specific CVE IDs to load
            use_cache: Whether to use caching
            max_workers: Number of parallel workers

        Returns:
            DataFrame with CVE data
        """
        # Try cache first
        if use_cache:
            cached_data = self._load_from_cache(start_year, end_year)
            if cached_data is not None:
                if cve_ids:
                    return cached_data[cached_data["cve_id"].isin(cve_ids)]
                return cached_data

        # Find all CVE JSON files
        cve_dir = Path(directory) / "CVEV5" / "cves"
        if not cve_dir.exists():
            logger.warning(f"CVE directory not found: {cve_dir}")
            return pd.DataFrame()

        logger.info(f"Loading CVE v5 data from {cve_dir}")

        # Find all JSON files for the year range
        json_files = []
        for year in range(start_year, end_year + 1):
            year_dir = cve_dir / str(year)
            if year_dir.exists():
                json_files.extend(year_dir.rglob("CVE-*.json"))

        logger.info(f"Found {len(json_files)} CVE v5 JSON files")

        if not json_files:
            return pd.DataFrame()

        # Convert cve_ids to set for O(1) lookup
        cve_ids_set = set(cve_ids) if cve_ids else None

        # Load and parse CVE data in parallel
        cve_records = []
        processed = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self._parse_cve_file, json_file, cve_ids_set): json_file
                for json_file in json_files
            }

            for future in as_completed(futures):
                processed += 1
                if processed % 1000 == 0:
                    logger.info(f"  Processed {processed}/{len(json_files)} files...")

                result = future.result()
                if result:
                    cve_records.append(result)

        if not cve_records:
            logger.warning("No CVE records loaded")
            return pd.DataFrame()

        # Create DataFrame from records
        df = pd.DataFrame(cve_records)
        logger.info(f"Loaded {len(df)} CVE v5 records")

        # Log statistics
        cvss_cols = [c for c in df.columns if "cvss_" in c and "score" in c]
        for col in cvss_cols:
            with_data = df[col].notna().sum()
            logger.info(f"  {col}: {with_data} records have data")

        # Cache the results
        if use_cache:
            self._save_to_cache(df, start_year, end_year)

        return df
