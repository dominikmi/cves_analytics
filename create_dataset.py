#!/usr/bin/env python3

# Dominik Miklaszewski
# v0.0.2, 2025-02-24 - For a given year range, data from NVD, EPSS, KEVS merged and saved to CSV file.
# v0.0.1, 2025-02-02 - just getting started, grab the baseline files and start working on them.

import pandas as pd
import argparse
import sys
from localutils import metricshelper
from datetime import datetime

# set up the argument parser
parser = argparse.ArgumentParser(description="CVE data analyser")
parser.add_argument("-s","--start_year", type=int, required=True, help="Start year")
parser.add_argument("-e","--end_year", type=int, required=True, help="End year")
parser.add_argument("-d","--download_path", type=str, required=True, help="Download the CVE data path")
parser.add_argument("-x","--extract_path", type=str, required=True, help="Extract the CVE data path")
parser.add_argument("-o","--output_path", type=str, required=True, help="Output the CVE data path")

# enforce help message if no arguments are provided
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

def main():
    args = parser.parse_args()

    # download the NVD CVE data
    metricshelper.download_nvd_cve_data(args.start_year, args.end_year, args.download_path)
    # unzip the downloaded files
    metricshelper.unzip_files(args.extract_path)

    # load the CVE data to a dataframe
    cves = metricshelper.load_nvd_cve_data(args.start_year, args.end_year,args.extract_path)
    # Sort the data by CVE ID
    cves = cves.sort_values(by="cve_id")

    today_date = datetime.now().strftime("%Y-%m-%d")

    # save the data to a CSV file
    cves.to_csv(f"{args.output_path}/cves_{args.start_year}-{args.end_year}_{today_date}.csv", index=False)
    
    # download the EPSS scores
    epss_file = metricshelper.download_epss_scores(today_date, args.download_path)
    
    # merge the EPSS scores with the CVE data
    epss_scores = pd.read_csv(epss_file, skiprows=1)
    cves_with_epss = pd.merge(cves,epss_scores, left_on="cve_id", right_on="cve", how="left")
    cves_with_epss.drop(columns=["cve"], inplace=True)

    # save the data to a CSV file
    cves_with_epss.to_csv(f"{args.output_path}/cves_with_epss_{args.start_year}-{args.end_year}_{today_date}.csv", index=False)
    
    # download the known exploited vulnerabilities
    kevs = metricshelper.download_known_exploited_vulnerabilities()

    # merge the known exploited vulnerabilities with the CVE data
    cves_with_kevs = pd.merge(cves_with_epss, kevs, on="cve_id", how="left")

    cves_with_kevs = cves_with_kevs.apply(metricshelper.update_row_with_details, axis=1)

    # normalize description data, some are with "" some not
    cves_with_kevs["description"] = cves_with_kevs["description"].apply(lambda x: x if x else "")

    # filter out all with Rejected CVEs in description
    cves_with_kevs = cves_with_kevs[~cves_with_kevs["description"].str.contains("Rejected reason:")]
    cves_with_kevs.to_csv(f"output/cves_epss_kevs_enriched-{today_date}.csv", index=False)

if __name__ == "__main__":
    main()