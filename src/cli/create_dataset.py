#!/usr/bin/env python3
"""Create CVE dataset by downloading and merging CVE v5, EPSS, and KEV data."""

import argparse
import sys
import time
from datetime import datetime

import pandas as pd

from src.core.cvev5_processor import (
    download_cvev5_cve_data,
    load_cvev5_cve_data,
    unzip_files,
)
from src.core.cwe_processor import get_cwe_name_and_description
from src.core.epss_processor import download_epss_scores
from src.core.kev_processor import download_known_exploited_vulnerabilities
from src.core.vulnrichment_processor import (
    update_row_with_vulnrichment_details,
)
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


def main() -> None:
    """Main entry point for dataset creation."""
    parser = argparse.ArgumentParser(description="CVE data analyser")
    parser.add_argument(
        "-s", "--start_year", type=int, required=True, help="Start year"
    )
    parser.add_argument("-e", "--end_year", type=int, required=True, help="End year")
    parser.add_argument(
        "-d",
        "--data_path",
        type=str,
        required=True,
        help="Download/Process the CVE data path",
    )
    parser.add_argument(
        "-o", "--output_path", type=str, required=True, help="Output the CVE data path"
    )

    # Enforce help message if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    logger.info(
        f"Starting the process for the years {args.start_year} to {args.end_year}"
    )

    # Download CVE v5 data
    start_time = time.time()
    logger.info("Step 1: Downloading CVE v5 data...")
    download_cvev5_cve_data(args.start_year, args.end_year, args.data_path)
    logger.info(f"Download complete in {time.time() - start_time:.2f}s")

    # Unzip downloaded files
    start_time = time.time()
    logger.info("Step 2: Unzipping files...")
    unzip_files(args.data_path)
    logger.info(f"Unzip complete in {time.time() - start_time:.2f}s")

    # Load CVE data to DataFrame
    start_time = time.time()
    logger.info("Step 3: Loading CVE data into DataFrame...")
    cves = load_cvev5_cve_data(args.start_year, args.end_year, args.data_path)
    logger.info(
        f"CVE data loaded in {time.time() - start_time:.2f}s - {len(cves)} records"
    )

    # Check if data was loaded
    if cves.empty:
        logger.error(
            "No CVE data loaded. Please check if downloads were successful "
            "and JSON files exist in the data directory."
        )
        sys.exit(1)

    # Sort by CVE ID
    start_time = time.time()
    logger.info("Step 4: Sorting CVE data...")
    cves = cves.sort_values(by="cve_id")
    logger.info(f"Sort complete in {time.time() - start_time:.2f}s")

    today_date = datetime.now().strftime("%Y-%m-%d")

    # Save raw CVE data
    start_time = time.time()
    logger.info("Step 5: Saving raw CVE data...")
    cves.to_csv(
        f"{args.output_path}/cves_{args.start_year}-{args.end_year}_{today_date}.csv",
        index=False,
    )
    logger.info(f"Raw data saved in {time.time() - start_time:.2f}s")

    # Download EPSS scores
    start_time = time.time()
    logger.info("Step 6: Downloading EPSS scores...")
    epss_file = download_epss_scores(today_date, args.data_path)
    logger.info(f"EPSS download complete in {time.time() - start_time:.2f}s")

    # Merge EPSS scores with CVE data
    start_time = time.time()
    logger.info("Step 7: Merging EPSS scores...")
    if epss_file:
        epss_scores = pd.read_csv(epss_file, skiprows=1)
        cves_with_epss = pd.merge(
            cves, epss_scores, left_on="cve_id", right_on="cve", how="left"
        )
    else:
        cves_with_epss = cves
        logger.warning("Failed to download EPSS scores")
    logger.info(f"EPSS merge complete in {time.time() - start_time:.2f}s")

    # Download KEV data
    start_time = time.time()
    logger.info("Step 8: Downloading known exploited vulnerabilities...")
    kev_data = download_known_exploited_vulnerabilities(args.data_path)
    logger.info(f"KEV download complete in {time.time() - start_time:.2f}s")

    # Merge KEV data
    start_time = time.time()
    logger.info("Step 9: Merging KEV data...")
    if kev_data is not None:
        cves_with_kev = pd.merge(
            cves_with_epss,
            kev_data,
            left_on="cve_id",
            right_on="cveID",
            how="left",
        )
    else:
        cves_with_kev = cves_with_epss
        logger.warning("Failed to download KEV data")
    logger.info(f"KEV merge complete in {time.time() - start_time:.2f}s")

    # Enrich with CWE details
    start_time = time.time()
    logger.info("Step 10: Enriching with CWE details...")
    cves_with_kev["cwe_details"] = cves_with_kev["cwe_id"].apply(
        get_cwe_name_and_description
    )
    logger.info(f"CWE enrichment complete in {time.time() - start_time:.2f}s")

    # Expand CWE details
    start_time = time.time()
    logger.info("Step 11: Expanding CWE details...")
    cwe_details_df = pd.json_normalize(cves_with_kev["cwe_details"])
    cves_enriched = pd.concat([cves_with_kev, cwe_details_df], axis=1)
    logger.info(f"CWE expansion complete in {time.time() - start_time:.2f}s")

    # Enrich with vulnrichment data
    start_time = time.time()
    logger.info("Step 12: Enriching with vulnerability enrichment data...")
    cves_enriched = cves_enriched.apply(update_row_with_vulnrichment_details, axis=1)
    logger.info(f"Vulnrichment enrichment complete in {time.time() - start_time:.2f}s")

    # Save final enriched dataset
    start_time = time.time()
    logger.info("Step 13: Saving final enriched dataset...")
    output_file = (
        f"{args.output_path}/cves_enriched_{args.start_year}-{args.end_year}"
        f"_{today_date}.csv"
    )
    cves_enriched.to_csv(output_file, index=False)
    logger.info(f"Final data saved in {time.time() - start_time:.2f}s")

    logger.info(f"Dataset creation complete. Output saved to {output_file}")


if __name__ == "__main__":
    main()
