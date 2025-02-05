#!/usr/bin/env python3

# Dominik Miklaszewski
# v0.0.1, 2025-02-02 - just getting started, grab the baseline files and start working on them.

import argparse
import os, sys
from localutils import cveutils

# set up the argument parser
parser = argparse.ArgumentParser(description="CVE data analyser")
parser.add_argument("-s","--start_year", required=True, help="Start year")
parser.add_argument("-e","--end_year", required=True, help="End year")
parser.add_argument("-d","--download_path", required=True, help="Download the CVE data path")
parser.add_argument("-x","--extract_path", required=True, help="Extract the CVE data path")
parser.add_argument("-o","--output_path", required=True, help="Output the CVE data path")

# enforce help message if no arguments are provided
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

def main():
    args = parser.parse_args()

    # download the NVD CVE data
    download_nvd_cve_data(args.start_year, args.end_year, args.download_path)
    # unzip the downloaded files
    unzip_files(args.extract_path)

    # load the CVE data to a dataframe
    cves = load_nvd_cve_data(args.extract_path)
    # Sort the data by CVE ID
    cves = cves.sort_values(by="cve_id")

    today_date = datetime.datetime.now().strftime("%Y-%m-%d")

    # save the data to a CSV file
    cves.to_csv(f"{args.output_path}/cves_{args.start_year}-{args.end_year}-{today_date}.csv", index=False)
    
    # download the EPSS scores
    epss_file = download_epss_scores(today_date, args.download_path)
    
    # merge the EPSS scores with the CVE data
    epss_scores = pd.read_csv(epss_file, skiprows=1)
    cves_with_epss = pd.merge(cves,epss_scores, left_on="cve_id", right_on="cve", how="left")
    cves_with_epss.drop(columns=["cve"], inplace=True)

    # save the data to a CSV file
    cves_with_epss.to_csv(f"{args.output_path}/cves_with_epss_{args.start_year}-{args.end_year}-{today_date}.csv", index=False)
    
    # download the known exploited vulnerabilities
    kevs = download_known_exploited_vulnerabilities()

    # simulate identified vulns outcome
    outcome_cves = cves_with_epss.sample(1000)
    outcome_cves.drop(columns=["scope", "confidentiality_impact", "integrity_impact", "availability_impact"], inplace=True)
    outcome_cves = outcome_cves.apply(update_row_with_details, axis=1)
    outcome_cves.to_csv(f"{args.output_path}/outcome_cves_epss_enriched-{today_date}.csv", index=False)


if __name__ == "__main__":
    main()