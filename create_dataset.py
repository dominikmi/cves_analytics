#!/usr/bin/env python3

# Dominik Miklaszewski
# v0.0.2, 2025-02-24 - For a given year range, data from NVD, EPSS, KEVS merged and saved to CSV file.
# v0.0.1, 2025-02-02 - just getting started, grab the baseline files and start working on them.

import pandas as pd
import argparse
import sys
from localutils.metricshelper import download_nvd_cve_data, unzip_files, load_nvd_cve_data, download_epss_scores, download_known_exploited_vulnerabilities, update_row_with_details, get_cwe_name_and_description, logger
from datetime import datetime

# set up the argument parser
parser = argparse.ArgumentParser(description="CVE data analyser")
parser.add_argument("-s","--start_year", type=int, required=True, help="Start year")
parser.add_argument("-e","--end_year", type=int, required=True, help="End year")
parser.add_argument("-d","--data_path", type=str, required=True, help="Download/Process the CVE data path")
parser.add_argument("-o","--output_path", type=str, required=True, help="Output the CVE data path")

# enforce help message if no arguments are provided
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

def main():
    args = parser.parse_args()

    logger.info(f"Starting the process for the years {args.start_year} to {args.end_year}")
    # download the NVD CVE data
    download_nvd_cve_data(args.start_year, args.end_year, args.data_path)
    # unzip the downloaded files
    unzip_files(args.data_path)

    logger.info("Processing the data")
    # load the CVE data to a dataframe
    cves = load_nvd_cve_data(args.start_year, args.end_year,args.data_path)
    # Sort the data by CVE ID
    cves = cves.sort_values(by="cve_id")

    today_date = datetime.now().strftime("%Y-%m-%d")

    # save the data to a CSV file
    cves.to_csv(f"{args.output_path}/cves_{args.start_year}-{args.end_year}_{today_date}.csv", index=False)
    
    logger.info("Downloading the EPSS scores")
    # download the EPSS scores
    epss_file = download_epss_scores(today_date, args.data_path)
    
    # merge the EPSS scores with the CVE data
    epss_scores = pd.read_csv(epss_file, skiprows=1)
    cves_with_epss = pd.merge(cves,epss_scores, left_on="cve_id", right_on="cve", how="left")
    cves_with_epss.drop(columns=["cve"], inplace=True)

    # save the data to a CSV file
    cves_with_epss.to_csv(f"{args.output_path}/cves_with_epss_{args.start_year}-{args.end_year}_{today_date}.csv", index=False)
    
    logger.info("Downloading the known exploited vulnerabilities")
    # download the known exploited vulnerabilities
    kevs = download_known_exploited_vulnerabilities(args.data_path)

    # merge the known exploited vulnerabilities with the CVE data
    cves_with_kevs = pd.merge(cves_with_epss, kevs, left_on="cve_id", right_on="cveID", how="left")

    logger.info("Processing the data for KEVs")
    cves_with_kevs = cves_with_kevs.apply(lambda row: update_row_with_details(row) if isinstance(row["cve_id"], str) else None, axis=1)

    # normalize description data, some are with "" some not
    cves_with_kevs["description"] = cves_with_kevs["description"].apply(lambda x: x if x else "")

    # filter out all with Rejected CVEs in description
    cves_with_kevs = cves_with_kevs[~cves_with_kevs["description"].str.contains("Rejected reason:")]
    
    logger.info("Enriching the data with CWE data")
    # enrich cwe data
    list_of_cwes = list(set(cves_with_kevs[~cves_with_kevs['cwe_id'].isin(['not_found', 'NVD-CWE-noinfo', 'NVD-CWE-Other'])]["cwe_id"].to_list()))
    cwes_df = pd.DataFrame([get_cwe_name_and_description(cwe_id) for cwe_id in list_of_cwes])
    cve_final = cves_with_kevs.merge(cwes_df, on='cwe_id', how='left')
    cve_final = cve_final.fillna("not_found")

    # organizing the columns
    cve_final = cve_final.rename(columns={"vendorProject":"kev_vendor_proj", "product": "kev_product","vulnerabilityName": "kev_vuln_name", "dateAdded":"kev_date_added","shortDescription":"kev_desc","requiredAction":"kev_req_action"})
    cve_final = cve_final.rename(columns={"dueDate":"kev_due_date", "knownRansomwareCampaignUse": "kev_known_ransom_camp_use","cwes": "kev_cwes", "Exploitation":"cve_exploitable","Automatable":"cve_automatable","Technical Impact":"cve_tech_impact"})
    
    cve_final = cve_final[['cve_id', 'description', 'published_date', 'last_modified_date',
       'cvss_version', 'cwe_id', 'cwe_name', 'cwe_desc', 'cwe_cc_scope', 'cwe_cc_impact', 'cvss_vector', 'attack_vector',
       'attack_complexity', 'privileges_required', 'user_interaction',
       'base_score', 'base_severity', 'exploitability_score',
       'confidentiality_impact', 'integrity_impact', 'availability_impact',
       'cve_exploitable', 'cve_automatable', 'cve_tech_impact',
       'epss', 'percentile', 'kev_vendor_proj', 'kev_product',
       'kev_vuln_name', 'kev_date_added', 'kev_desc', 'kev_req_action',
       'kev_due_date', 'kev_known_ransom_camp_use', 'notes', 'kev_cwes']]
    
    cve_final.to_csv(f"{args.output_path}/cves_epss_kevs_cwe_enriched-{today_date}.csv", index=False)
    logger.info("Process completed")
if __name__ == "__main__":
    main()