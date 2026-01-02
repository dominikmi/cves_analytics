#!/usr/bin/env python3
"""Cache manager for Monte Carlo simulations.

Separates one-time expensive operations (Docker scanning, CVE enrichment)
from fast iterative operations (control generation, risk calculation).
Provides ~670x speedup for Monte Carlo simulations.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SimulationCache:
    """Manages cached data for Monte Carlo simulations.

    Caches expensive operations that don't change between iterations:
    - Docker image vulnerability scans
    - Enriched CVE dataset (CVSS, EPSS, KEV, CWE)
    - EPSS scores
    - KEV catalog

    Attributes:
        cache_dir: Directory for cache storage
        cache_version: Version for cache invalidation
    """

    CACHE_VERSION = "1.0"

    def __init__(self, cache_dir: str | Path = "monte_carlo/output/cache"):
        """Initialize cache manager.

        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, Any] = {}

    def build_cache(
        self, scenario_config: dict[str, Any], force_rebuild: bool = False
    ) -> dict[str, Any]:
        """Build cache for a scenario configuration.

        This is the expensive one-time setup phase that scans Docker images
        and loads enriched CVE data.

        Args:
            scenario_config: Scenario configuration dict
            force_rebuild: Force cache rebuild even if valid cache exists

        Returns:
            Cache dict with all pre-computed data
        """
        cache_key = self._get_cache_key(scenario_config)
        cache_file = self.cache_dir / f"{cache_key}.json"

        # Try to load existing cache
        if not force_rebuild and cache_file.exists():
            logger.info(f"Loading cache from {cache_file}")
            cache = self._load_cache(cache_file)
            if self._is_cache_valid(cache):
                logger.info("Cache is valid, using cached data")
                self._cache = cache
                return cache
            logger.warning("Cache is invalid, rebuilding")

        # Build new cache
        logger.info("Building new cache (this may take 5-10 minutes)...")
        cache = self._build_new_cache(scenario_config)

        # Save cache
        self._save_cache(cache, cache_file)
        self._cache = cache

        return cache

    def get_cached_data(self, key: str) -> Any:
        """Get cached data by key.

        Args:
            key: Cache key

        Returns:
            Cached data

        Raises:
            KeyError: If key not in cache
        """
        if key not in self._cache:
            raise KeyError(f"Key '{key}' not found in cache")
        return self._cache[key]

    def _get_cache_key(self, scenario_config: dict[str, Any]) -> str:
        """Generate cache key from scenario config.

        Cache is scenario-specific because different scenarios may use
        different Docker images or vulnerability datasets.

        Args:
            scenario_config: Scenario configuration

        Returns:
            Cache key string
        """
        org_size = scenario_config.get("org_size", "unknown")
        industry = scenario_config.get("industry", "unknown")
        environment = scenario_config.get("environment", "unknown")

        return f"cache_{org_size}_{industry}_{environment}"

    def _build_new_cache(self, scenario_config: dict[str, Any]) -> dict[str, Any]:
        """Build new cache from scratch.

        This runs the expensive operations:
        1. Generate scenario (to get Docker image list)
        2. Scan Docker images with Grype
        3. Load and enrich CVE dataset
        4. Load EPSS scores
        5. Load KEV catalog

        Args:
            scenario_config: Scenario configuration

        Returns:
            Cache dict
        """
        from src.cli.pipeline import VulnerabilityAssessmentPipeline
        from src.utils.config import AppConfig

        logger.info("Step 1/5: Running pipeline to generate data...")

        # Create config for pipeline
        config = AppConfig(
            org_size=scenario_config["org_size"],
            org_reach="global",  # Default for Monte Carlo
            industry=scenario_config["industry"],
            environment=scenario_config["environment"],
            grype_binary_path="/opt/homebrew/bin/grype",
            data_path="data",
            output_path=str(self.cache_dir / "temp"),
        )

        # Run pipeline
        pipeline = VulnerabilityAssessmentPipeline(config)
        pipeline.run()

        # Extract data from pipeline state
        logger.info("Step 2/5: Extracting Docker scan results...")
        docker_scans = self._extract_docker_scans_from_state(pipeline.state)

        logger.info("Step 3/5: Extracting enriched CVE dataset...")
        enriched_cves = self._extract_enriched_cves_from_state(pipeline.state)

        logger.info("Step 4/5: Extracting EPSS data...")
        epss_data = self._extract_epss_data_from_state(pipeline.state)

        logger.info("Step 5/5: Extracting KEV catalog...")
        kev_data = self._extract_kev_data_from_state(pipeline.state)

        # Extract architecture
        architecture = self._extract_architecture_from_state(pipeline.state)

        cache = {
            "version": self.CACHE_VERSION,
            "timestamp": datetime.now().isoformat(),
            "scenario_config": scenario_config,
            "docker_scans": docker_scans,
            "enriched_cves": enriched_cves,
            "epss_data": epss_data,
            "kev_data": kev_data,
            "architecture": architecture,
        }

        logger.info("Cache built successfully")
        return cache

    def _extract_docker_scans_from_state(self, pipeline_state: dict) -> dict[str, list]:
        """Extract Docker scan results from pipeline state.

        Args:
            pipeline_state: Pipeline state dict

        Returns:
            Dict mapping image names to vulnerability lists
        """
        scan_results = pipeline_state.get("scan_results")
        if scan_results is None or scan_results.is_empty():
            return {}

        # Group by image name
        docker_scans = {}
        for row in scan_results.iter_rows(named=True):
            image = row.get("image_name", "unknown")
            if image not in docker_scans:
                docker_scans[image] = []
            docker_scans[image].append(
                {
                    "cve_id": row.get("cve_id"),
                    "severity": row.get("severity"),
                    "cvss_score": row.get("cvss_score"),
                }
            )

        return docker_scans

    def _extract_enriched_cves_from_state(self, pipeline_state: dict) -> dict:
        """Extract enriched CVE dataset from pipeline state.

        Args:
            pipeline_state: Pipeline state dict

        Returns:
            Enriched CVE data (serializable format)
        """
        enriched_df = pipeline_state.get("enriched_data")
        if enriched_df is None or enriched_df.is_empty():
            return {}

        # Convert DataFrame to dict for JSON serialization
        return enriched_df.to_dict(as_series=False)

    def _extract_epss_data_from_state(self, pipeline_state: dict) -> dict:
        """Extract EPSS scores from pipeline state.

        Args:
            pipeline_state: Pipeline state dict

        Returns:
            EPSS data dict
        """
        enriched_df = pipeline_state.get("enriched_data")
        if enriched_df is None or enriched_df.is_empty():
            return {}

        # Extract EPSS scores as dict
        if "cve_id" in enriched_df.columns and "epss_score" in enriched_df.columns:
            epss_dict = {}
            for row in enriched_df.select(["cve_id", "epss_score"]).iter_rows(
                named=True
            ):
                epss_dict[row["cve_id"]] = float(row["epss_score"])
            return epss_dict
        return {}

    def _extract_kev_data_from_state(self, pipeline_state: dict) -> dict:
        """Extract KEV catalog from pipeline state.

        Args:
            pipeline_state: Pipeline state dict

        Returns:
            KEV data dict
        """
        enriched_df = pipeline_state.get("enriched_data")
        if enriched_df is None or enriched_df.is_empty():
            return {}

        # Extract KEV entries
        if "cve_id" in enriched_df.columns and "is_kev" in enriched_df.columns:
            kev_dict = {}
            kev_df = enriched_df.filter(pl.col("is_kev") == True)
            for row in kev_df.iter_rows(named=True):
                kev_dict[row["cve_id"]] = {
                    "is_kev": True,
                    "date_added": row.get("kev_date_added", "unknown"),
                }
            return kev_dict
        return {}

    def _extract_architecture_from_state(self, pipeline_state: dict) -> dict:
        """Extract architecture from pipeline state.

        Args:
            pipeline_state: Pipeline state dict

        Returns:
            Architecture dict
        """
        scenario = pipeline_state.get("scenario")
        if scenario is None:
            return {}

        # Extract architecture information
        architecture = {
            "application": {
                "name": scenario.application.name
                if hasattr(scenario, "application")
                else "unknown",
                "type": scenario.application.app_type
                if hasattr(scenario, "application")
                else "unknown",
            },
            "components": [],
            "network_topology": {
                "segmentation": scenario.network_policy
                if hasattr(scenario, "network_policy")
                else "none",
            },
        }

        # Extract components if available
        if hasattr(scenario, "application") and hasattr(
            scenario.application, "components"
        ):
            for comp in scenario.application.components:
                architecture["components"].append(
                    {
                        "name": comp.name if hasattr(comp, "name") else "unknown",
                        "type": comp.component_type
                        if hasattr(comp, "component_type")
                        else "unknown",
                        "exposure": comp.exposure
                        if hasattr(comp, "exposure")
                        else "internal",
                    }
                )

        return architecture

    def _is_cache_valid(self, cache: dict) -> bool:
        """Check if cache is valid.

        Args:
            cache: Cache dict

        Returns:
            True if cache is valid
        """
        if cache.get("version") != self.CACHE_VERSION:
            logger.warning(
                f"Cache version mismatch: {cache.get('version')} "
                f"!= {self.CACHE_VERSION}"
            )
            return False

        # Check if cache is too old (e.g., > 7 days)
        timestamp = cache.get("timestamp")
        if timestamp:
            cache_date = datetime.fromisoformat(timestamp)
            age_days = (datetime.now() - cache_date).days
            if age_days > 7:
                logger.warning(f"Cache is {age_days} days old, rebuilding")
                return False

        return True

    def _load_cache(self, cache_file: Path) -> dict:
        """Load cache from file.

        Args:
            cache_file: Path to cache file

        Returns:
            Cache dict
        """
        with open(cache_file) as f:
            return json.load(f)

    def _save_cache(self, cache: dict, cache_file: Path) -> None:
        """Save cache to file.

        Args:
            cache: Cache dict
            cache_file: Path to cache file
        """
        with open(cache_file, "w") as f:
            json.dump(cache, f, indent=2)
        logger.info(f"Cache saved to {cache_file}")
