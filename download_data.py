!#/usr/bin/env python3

# Dominik Miklaszewski
# v0.0.1, 2025-02-02

import argparse
import os, sys
from localutils import cveutils

# set up the argument parser
parser = argparse.ArgumentParser(description="CVE data analyser")
parser.add_argument("-d","--download_cves", action="store_true", help="Download the CVE data")
parser.add_argument("-e","--extract", action="store_true", help="Extract the CVE data")
parser.add_argument("-t","--transform", action="store_true", help="Transform the CVE data")
parser.add_argument("-l","--load", action="store_true", help="Load the CVE data")
parser.add_argument("-a","--all", action="store_true", help="Run all the steps")

# enforce help message if no arguments are provided
if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

def main():
    pass


if __name__ == "__main__":
    main()