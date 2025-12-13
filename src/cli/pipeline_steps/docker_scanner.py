import asyncio
import logging
import time
from typing import Any

import pandas as pd

from src.core.docker_scanner import DockerImageScanner


class DockerScanner:
    """Scans Docker images for vulnerabilities using Grype."""

    def __init__(self, logger: logging.Logger):
        """Initialize the Docker scanner."""
        self.logger = logger

    def scan(self, scenario: dict[str, Any], grype_path: str) -> pd.DataFrame:
        """Scan Docker images from the scenario for vulnerabilities."""
        start_time = time.time()

        try:
            # Extract image names from scenario
            images = []
            for service in scenario.get("services", []):
                image = service.get("image") or service.get("docker_image")
                if image:
                    images.append(image)

            if not images:
                self.logger.warning("No Docker images found in scenario")
                return pd.DataFrame()

            self.logger.info(
                f"Found {len(images)} Docker images to scan: {', '.join(images[:5])}{'...' if len(images) > 5 else ''}",
            )

            # Initialize scanner with Grype
            scanner = DockerImageScanner(grype_binary_path=grype_path)

            # Ensure the grype path is set correctly
            if not scanner.grype_binary_path:
                scanner.grype_binary_path = grype_path

            # Use concurrent scanning
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                scan_results = loop.run_until_complete(
                    scanner.scan_images_concurrently(images),
                )
                loop.close()
            except Exception as e:
                self.logger.warning(
                    f"Concurrent scanning failed, falling back to sequential: {e!s}",
                )
                # Fallback to sequential scanning
                results = []
                for idx, image in enumerate(images, 1):
                    self.logger.info(f"[{idx}/{len(images)}] Scanning: {image}")
                    try:
                        result = scanner.scan_image_with_grype(image)
                        if not result.empty:
                            results.append(result)
                            self.logger.info(f"  Found {len(result)} vulnerabilities")
                        else:
                            self.logger.info("  No vulnerabilities found")
                    except Exception as e:
                        self.logger.warning(f"  Could not scan {image}: {e!s}")

                if results:
                    scan_results = pd.concat(results, ignore_index=True)
                else:
                    scan_results = pd.DataFrame()

            duration = time.time() - start_time
            self.logger.info(f"Image scanning completed in {duration:.2f}s")
            self.logger.info(f"Total vulnerabilities found: {len(scan_results)}")

            return scan_results

        except Exception as e:
            self.logger.error(f"Failed to scan Docker images: {e!s}", exc_info=True)
            raise
