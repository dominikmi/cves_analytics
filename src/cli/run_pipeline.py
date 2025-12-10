#!/usr/bin/env python3
"""Main entry point for the vulnerability assessment pipeline."""

import argparse
import sys

from src.cli.pipeline import VulnerabilityAssessmentPipeline
from src.utils.config import AppConfig


def main():
    """Main entry point for the pipeline."""
    parser = argparse.ArgumentParser(
        description="Run full vulnerability assessment pipeline"
    )
    parser.add_argument(
        "--org-size",
        choices=["small", "mid", "large"],
        required=True,
        help="Organization size",
    )
    parser.add_argument(
        "--org-reach",
        choices=["local", "regional", "global"],
        required=True,
        help="Organization geographic reach",
    )
    parser.add_argument(
        "--industry",
        choices=[
            "on-line-store",
            "financial-services",
            "consulting",
        ],
        required=True,
        help="Organization industry",
    )
    parser.add_argument(
        "--environment",
        choices=["dev", "test", "qa", "stage", "prod"],
        required=True,
        help="Environment type",
    )
    parser.add_argument(
        "--grype-path",
        default="/opt/homebrew/bin/grype",
        help="Path to Grype binary",
    )
    parser.add_argument(
        "--data-path",
        default="./data",
        help="Path to CVE v5 data directory",
    )
    parser.add_argument(
        "--cve-dataset",
        help="Path to CVE dataset CSV (deprecated, use --data-path)",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--log-file",
        default="./logs/pipeline.log",
        help="Log file path",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )

    args = parser.parse_args()

    try:
        # Create configuration using AppConfig
        config = AppConfig(
            grype_binary_path=args.grype_path,
            data_path=args.data_path,
            output_path=args.output_dir,
            log_level=args.log_level,
        )

        # Store additional pipeline-specific parameters
        config.org_size = args.org_size
        config.org_reach = args.org_reach
        config.industry = args.industry
        config.environment = args.environment
        config.cve_dataset = args.cve_dataset
        config.log_file = args.log_file

        # Create and run pipeline
        pipeline = VulnerabilityAssessmentPipeline(config)
        report_path = pipeline.run()

        print("\nPipeline completed successfully!")
        print(f"Report saved to: {report_path}")

    except Exception as e:
        print(f"Pipeline failed: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
