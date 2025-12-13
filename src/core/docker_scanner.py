"""Docker image vulnerability scanner using Grype."""

import asyncio
import json
import logging
import subprocess

import pandas as pd

from src.utils.config import get_config
from src.utils.error_handling import error_handler
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


class DockerImageScanner:
    """Scanner for Docker images in private registries using Grype."""

    def __init__(
        self,
        registry_url: str | None = None,
        grype_binary_path: str | None = None,
    ):
        """Initialize the Docker image scanner.

        Args:
            registry_url: URL of the Docker registry
            grype_binary_path: Path to Grype binary

        """
        self.registry_url = registry_url
        self.grype_binary_path = grype_binary_path
        try:
            if self.registry_url:
                logger.info(
                    f"Initialized DockerImageScanner with registry URL: {self.registry_url}",
                )
            else:
                logger.info(
                    f"Initialized DockerImageScanner for local images with Grype path: {self.grype_binary_path}",
                )
        except Exception as e:
            logger.error(f"Failed to initialize DockerImageScanner: {e}")

    @error_handler()
    def list_images_and_tags(self, tls_verify: bool = False) -> dict[str, list[str]]:
        """Get images and tags from a Docker registry.

        Args:
            tls_verify: Whether to verify TLS certificates

        Returns:
            Dictionary mapping repository names to tag lists

        """
        if not self.registry_url:
            logger.error("Registry URL not provided")
            return {}

        try:
            import requests

            repos_url = f"{self.registry_url}/v2/_catalog"
            repos_response = requests.get(repos_url, timeout=10, verify=tls_verify)
            repos_response.raise_for_status()

            logger.info(f"Fetched data from registry: {repos_response.json()}")
            repositories = repos_response.json().get("repositories", [])

            images = {}
            for repo in repositories:
                tags_url = f"{self.registry_url}/v2/{repo}/tags/list"
                tags_response = requests.get(tags_url, timeout=10, verify=tls_verify)
                tags_response.raise_for_status()
                tags = tags_response.json().get("tags", [])

                if tags:
                    images[repo] = tags

            return images
        except requests.RequestException as e:
            logger.error(f"Error fetching data from registry: {e}")
            return {}

    def scan_image_with_grype(self, image_name: str) -> pd.DataFrame:
        """Scan a Docker image with Grype and return results as DataFrame.

        Args:
            image_name: Name of the Docker image to scan

        Returns:
            DataFrame with vulnerability scan results

        """
        try:
            cmd = [self.grype_binary_path, image_name, "--output", "json"]
            logging.debug(f"Running: {cmd}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )  # 5 minute timeout

            if result.returncode != 0:
                logging.warning(
                    f"Grype returned non-zero exit code {result.returncode} "
                    f"for {image_name}: {result.stderr}",
                )
                return pd.DataFrame()

            if not result.stdout.strip():
                logging.warning(f"Grype returned empty output for {image_name}")
                return pd.DataFrame()

            try:
                scan_data = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logging.error(f"Error parsing Grype JSON output for {image_name}: {e}")
                return pd.DataFrame()

            matches = scan_data.get("matches", [])
            if not matches:
                return pd.DataFrame()

            vulnerabilities = []
            for match in matches:
                vuln = {
                    "image_name": image_name,
                    "vuln_id": match.get("vulnerability", {}).get("id", ""),
                    "severity": match.get("vulnerability", {}).get("severity", ""),
                    "vuln_desc": match.get("vulnerability", {}).get("description", ""),
                    "data_src": match.get("vulnerability", {}).get("dataSource", ""),
                    "package_name": match.get("artifact", {}).get("name", ""),
                    "package_ver": match.get("artifact", {}).get("version", ""),
                    "package_url": match.get("artifact", {}).get("purl", ""),
                    "fixed_ver": "",
                }

                # Safely extract fixed version
                try:
                    fix_info = match.get("vulnerability", {}).get("fix", {})
                    versions = fix_info.get("versions", [])
                    if versions and isinstance(versions, list) and len(versions) > 0:
                        vuln["fixed_ver"] = versions[0]
                except (IndexError, TypeError, AttributeError):
                    # If we can't extract fixed version, leave it as empty string
                    pass

                vulnerabilities.append(vuln)

            return pd.DataFrame(vulnerabilities)

        except subprocess.TimeoutExpired:
            logging.error(f"Grype scan timed out for {image_name}")
            return pd.DataFrame()
        except Exception as e:
            logging.error(f"Error scanning image {image_name}: {e}")
            return pd.DataFrame()

    async def scan_images_concurrently(self, image_names: list[str]) -> pd.DataFrame:
        """Scan multiple Docker images concurrently with rate limiting.

        Args:
            image_names: List of Docker image names to scan

        Returns:
            DataFrame with all vulnerability scan results

        """
        try:
            config = get_config()
            max_concurrent = config.max_concurrent_scans
        except Exception:
            max_concurrent = 5  # Default fallback

        semaphore = asyncio.Semaphore(max_concurrent)

        async def scan_with_semaphore(image_name: str) -> pd.DataFrame:
            async with semaphore:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None,
                    self.scan_image_with_grype,
                    image_name,
                )

        # Create tasks for all images
        tasks = [scan_with_semaphore(image_name) for image_name in image_names]

        # Run all scans concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and combine DataFrames
        dataframes = []
        for result in results:
            if isinstance(result, pd.DataFrame) and not result.empty:
                dataframes.append(result)
            elif isinstance(result, Exception):
                logging.error(f"Scan failed with exception: {result}")

        if dataframes:
            return pd.concat(dataframes, ignore_index=True)
        return pd.DataFrame()
