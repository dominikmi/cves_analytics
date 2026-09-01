"""CLI entry point for pipeline orchestration."""

import argparse
import sys

from sqlmodel import Session

from src.data.stores.duckdb_store import DuckDBStore
from src.db.sqlite_models import Profile, get_engine
from src.services.pipeline import VulnerabilityAssessmentPipeline
from src.simulation.scenario_generator import ScenarioGenerator
from src.utils.config import settings
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="CVEs Analytics Pipeline")
    parser.add_argument("--data-dir", default=settings.data_dir, help="Data directory")
    parser.add_argument(
        "--upload-dir", default=settings.upload_dir, help="Upload directory"
    )
    parser.add_argument("--profile", default=1, type=int, help="Profile ID to scan")
    parser.add_argument(
        "--images", nargs="+", default=None, help="Docker images to scan"
    )
    parser.add_argument(
        "--generate-scenario",
        action="store_true",
        help="Generate a simulated environment scenario",
    )
    parser.add_argument(
        "--size", default="small", help="Organization size (small, mid)"
    )
    parser.add_argument(
        "--reach", default="local", help="Geographic reach (local, global)"
    )
    parser.add_argument("--industry", default="technology", help="Industry type")
    parser.add_argument(
        "--env-type",
        default="prod",
        help="Environment type (dev, test, qa, stage, prod)",
    )
    args = parser.parse_args()

    engine = get_engine()
    duckdb_store = DuckDBStore(":memory:")

    with Session(engine) as session:
        profile = session.get(Profile, args.profile)
        if not profile:
            logger.warning("Profile %d not found, creating default", args.profile)
            images = args.images or ["nginx:latest"]
            profile = Profile(
                id=args.profile,
                name="default",
                org_size=args.size,
                org_reach=args.reach,
                industry=args.industry,
                environment=args.env_type,
                security_maturity=0.5,
                image_inventory=images,
            )
            session.add(profile)
            session.commit()
            session.refresh(profile)

        if args.images:
            profile.image_inventory = args.images
            session.commit()

        # Generate scenario if requested
        if args.generate_scenario:
            generator = ScenarioGenerator()
            scenario = generator.generate_scenario(
                size=args.size,
                reach=args.reach,
                industry=args.industry,
                environment_type=args.env_type,
            )
            print("\nGenerated scenario:")
            print(f"  Company: {scenario['company_name']}")  # type: ignore[index]
            print(f"  Topology: {scenario['metadata']['topology']}")  # type: ignore[index]
            print(f"  Services: {len(scenario['services'])}")  # type: ignore[index]
            print(f"  Maturity: {scenario['security_maturity']}")  # type: ignore[index]

        pipeline = VulnerabilityAssessmentPipeline(
            profile=profile,
            duckdb_store=duckdb_store,
            data_dir=args.data_dir,
        )

        try:
            result = pipeline.run()
            print("\nPipeline complete:")
            print(f"  Findings: {len(result.findings_df)}")
            print(f"  Severities: {result.severity_counts}")
            risk_val = (
                result.avg_bayesian_risk
                if result.avg_bayesian_risk is not None
                else 0.0
            )
            print(f"  Avg Bayesian Risk: {risk_val:.4f}")
            sys.exit(0)
        except Exception as exc:
            logger.error("Pipeline failed: %s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
