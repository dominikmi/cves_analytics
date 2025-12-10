#!/usr/bin/env python3
"""Generate vulnerability scanning simulation scenarios."""

import argparse
import json
import sys
from typing import Any

from src.simulation.scenario_generator import ScenarioGenerator
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


def main() -> None:
    """Main entry point for scenario generation."""
    parser = argparse.ArgumentParser(
        description="Generate vulnerability scanning simulation scenarios"
    )
    parser.add_argument(
        "--size",
        choices=["small", "mid"],
        required=True,
        help="Size of the organization",
    )
    parser.add_argument(
        "--reach",
        choices=["local", "global"],
        required=True,
        help="Geographic reach of the organization",
    )
    parser.add_argument(
        "--industry",
        choices=["on-line-store", "consulting", "financial-services"],
        required=True,
        help="Industry type",
    )
    parser.add_argument(
        "--environment",
        choices=["dev", "test", "qa", "stage", "prod"],
        default="prod",
        help="Target environment (default: prod)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    logger.info(
        f"Generating scenario: size={args.size}, reach={args.reach}, "
        f"industry={args.industry}, environment={args.environment}"
    )

    # Create scenario generator
    generator = ScenarioGenerator()

    # Generate scenario
    result: Any = generator.generate_scenario(
        args.size,
        args.reach,
        args.industry,
        args.environment,
        output_format=args.format,
    )

    # Output result
    if args.format == "csv":
        print(result)
    else:
        print(json.dumps(result, indent=4))

    logger.info("Scenario generation complete")


if __name__ == "__main__":
    main()
