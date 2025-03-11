#!/usr/bin/env python3

# v0.1 by Dominik Miklaszewski, 03.2025
# 
# What it does:
# - This script is used to scan Docker images either pulled in from public registries or private one
# - It uses grype to scan the images and returns the vulnerabilities found in a DataFrame
# - It then can enrich the data with additional information such as CVE details, severity, etc. from CVEs enriched dataframe

import pandas as pd
from localutils.dockerscanhelper import DockerImageScanner
import argparse
import os
import sys
import logging
from dotenv import load_dotenv
from pathlib import Path

# Set up logging
log_directory = 'logs'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(filename=os.path.join(log_directory, 'scan_images.log'), level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

# load .env file
env_path = Path(".") / ".env"
load_dotenv(dotenv_path=env_path)

# Parse command line arguments

parser = argparse.ArgumentParser(description='Scan Docker images for vulnerabilities with grype')
parser.add_argument('-r', '--registry', required=False, help='Docker registry URL')
parser.add_argument('-i', '--image', required=False, help='Docker image name')
parser.add_argument('-l', '--list_of_images', required=False, help='Docker image list in CSV format')
parser.add_argument('-t', '--tls', required=False, action='store_true', help='Enable TLS verification for registry')
parser.add_argument('-o', '--output', required=True, help='Output CSV file path for scan results')
parser.add_argument('-e', '--enrich_with_data', required=False, help='Enrich with CVE data, path to CSV file')

# enforce help message if no arguments are provided
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

# supress pandas warning
pd.options.mode.chained_assignment = None

def main():
    args = parser.parse_args()

    # Ensure that at least one image parameter is provided
    if not args.image and not args.list_of_images:
        parser.error("Either --image or --list_of_images must be provided.")

    # Initialize the DockerImageScanner
    scanner = DockerImageScanner(args.registry)

    # Scan a single image
    if args.image:
        try:
            logging.info(f'Scanning image: {args.image}')
            results = scanner.scan_image_with_grype(args.image)
        except Exception as e:
            logging.error(f'Error scanning image: {args.image}, error: {e}')
            return

    # Scan a list of images
    if args.list_of_images:
        try:
            logging.info(f'Scanning images from list: {args.list_of_images}')
            images = pd.read_csv(args.list_of_images)
            dfs = []
            dfs = [scanner.scan_image_with_grype(image) for image in images["image"]]
            valid_dfs = [d for d in dfs if isinstance(d, pd.DataFrame)]
            results = pd.concat(valid_dfs)
        except Exception as e:
            logging.error(f'Error scanning images from list: {args.list_of_images}, error: {e}')
            return
    
    # Save the scan results to a CSV file
    if not args.enrich_with_data:
        results.to_csv(args.output, index=False)
        logging.info(f'Scan results saved to {args.output}')
        return
    else:
    # Enrich the scan results with CVE data
        if len(results):
            try:
                logging.info(f'Enriching scan results with CVE data from: {args.enrich_with_data}')
                cve_data = pd.read_csv(args.enrich_with_data)
                enriched_results =  pd.merge(results, cve_data, left_on="vuln_id", right_on="cve_id", how="left")

                # make all colunm name lowercase
                enriched_results.columns = enriched_results.columns.str.lower()
                enriched_results = enriched_results.drop(columns=["cve_id", "description"])
                # fill all NaN values with "not_found"
                enriched_results = enriched_results.fillna("not_found")

                # dump to a CSV file
                enriched_results.to_csv(args.output, index=False)
                logging.info(f'Enriched scan results saved to {args.output}')
                return
            except Exception as e:
                logging.error(f'Error enriching scan results with CVE data: {e}')
        else:
            logging.error('No scan results to enrich with CVE data')
            return

if __name__ == '__main__':
    main()


