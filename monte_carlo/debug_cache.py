#!/usr/bin/env python3
"""Debug cache creation to identify the issue."""

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from monte_carlo.src.cache_manager import SimulationCache

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    """Debug cache creation."""
    logger.info("Starting cache debug...")
    
    scenario_config = {
        "org_size": "large",
        "industry": "financial-services",
        "maturity": "optimizing",
        "environment": "prod",
    }
    
    cache_manager = SimulationCache("monte_carlo/output/cache")
    
    try:
        logger.info("Attempting to build cache...")
        cache = cache_manager.build_cache(scenario_config, force_rebuild=True)
        
        logger.info("Cache built successfully!")
        logger.info(f"Cache keys: {cache.keys()}")
        logger.info(f"Enriched CVEs count: {len(cache.get('enriched_cves', {}).get('cve_id', []))}")
        logger.info(f"Docker scans: {list(cache.get('docker_scans', {}).keys())}")
        
    except Exception as e:
        logger.error(f"Cache build failed: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
