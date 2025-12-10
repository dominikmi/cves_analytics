#!/usr/bin/env python3
"""Scan Docker images for vulnerabilities using Grype."""

import argparse
import os
import sys
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

from src.core.docker_scanner import DockerImageScanner
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

# Load environment variables
env_path = Path(".") / ".env"
load_dotenv(dotenv_path=env_path)


def main() -> None:
    """Main entry point for Docker image scanning."""
    parser = argparse.ArgumentParser(
        description="Scan Docker images for vulnerabilities with Grype"
    )
    parser.add_argument("-r", "--registry", required=False, help="Docker registry URL")
    parser.add_argument("-i", "--image", required=False, help="Docker image name")
    parser.add_argument(
        "-l",
        "--list_of_images",
        required=False,
        help="Docker image list in CSV format",
    )
    parser.add_argument(
        "-t",
        "--tls",
        required=False,
        action="store_true",
        help="Enable TLS verification for registry",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        help="Output file for scan results (CSV)",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Get Grype binary path from environment
    grype_binary_path = os.getenv("GRYPE_BINARY_PATH")

    # Initialize scanner
    scanner = DockerImageScanner(
        registry_url=args.registry, grype_binary_path=grype_binary_path
    )

    results = []

    # Scan single image
    if args.image:
        logger.info(f"Scanning image: {args.image}")
        result = scanner.scan_image_with_grype(args.image)
        if not result.empty:
            results.append(result)

    # Scan images from registry
    elif args.registry:
        logger.info(f"Listing images from registry: {args.registry}")
        images = scanner.list_images_and_tags(tls_verify=args.tls)

        for repo, tags in images.items():
            for tag in tags:
                image_ref = f"{repo}:{tag}"
                logger.info(f"Scanning image: {image_ref}")
                result = scanner.scan_image_with_grype(image_ref)
                if not result.empty:
                    results.append(result)

    # Scan images from CSV list
    elif args.list_of_images:
        logger.info(f"Reading image list from: {args.list_of_images}")
        try:
            images_df = pd.read_csv(args.list_of_images)
            image_column = images_df.columns[0]

            for image in images_df[image_column]:
                logger.info(f"Scanning image: {image}")
                result = scanner.scan_image_with_grype(image)
                if not result.empty:
                    results.append(result)
        except Exception as e:
            logger.error(f"Error reading image list: {e}")
            sys.exit(1)

    else:
        logger.error("Please provide either --image, --registry, or --list_of_images")
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Combine results
    if results:
        combined_results = pd.concat(results, ignore_index=True)

        # Save to file if specified
        if args.output:
            combined_results.to_csv(args.output, index=False)
            logger.info(f"Results saved to {args.output}")
        else:
            print(combined_results.to_csv(index=False))
    else:
        logger.warning("No vulnerabilities found")


if __name__ == "__main__":
    main()
