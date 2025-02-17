import gzip
import pandas as pd
import numpy as np
import requests
import logging
import os 
import re
import json
from datetime import datetime, timedelta
from dateutil import parser, relativedelta

from dotenv import load_dotenv
load_dotenv()

# set up the current date and time
current_date = datetime.now().strftime('%Y-%m-%d')
current_time = datetime.now().strftime('%H:%M:%S')


#Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(f"logs/app-{current_date+current_time}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# Download and unzip NVD CVE data
def download_nvd_cve_data(start_year: int, end_year: int, directory: str):
    
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    end_year_plus = end_year + 1
    for year in range(start_year, end_year_plus):
        file_path = os.path.join(directory, f"nvdcve-1.1-{year}.json.zip")
        if os.path.exists(file_path):
            logger.info(f"File {file_path} already exists, skipping download.")
            continue
        
        url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip"
        response = requests.get(url)
        if response.status_code == 200:
            with open(file_path, 'wb') as file:
                file.write(response.content)
            logger.info(f"Downloaded {file_path}")
        else:
            logger.error(f"Failed to download data for year {year}")

# unzip all found files in the directory
def unzip_files(directory):
    import zipfile
    import os
    
    for file in os.listdir(directory):
        if file.endswith(".zip"):
            file_path = os.path.join(directory, file)
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(directory)
                logger.info(f"Unzipped {file_path}")
                os.remove(file_path)

# Load NVD CVE data into a DataFrame
def load_nvd_cve_data(directory):
    data = []
    cves_list = []
    for file in os.listdir(directory):
        if file.endswith(".json"):
            file_path = os.path.join(directory, file)
            with open(file_path, 'r') as file:
                data = json.load(file)
                logger.info(f"Loaded {file_path}")
                for index, item in enumerate(data.get("CVE_Items", [])):
                    cve = (
                        item.get("cve", {}).get("CVE_data_meta", {}).get("ID", ""), 
                        item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", ""),
                        item.get("publishedDate", ""),
                        item.get("lastModifiedDate", ""),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("version", item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("version", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("vectorString", item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("vectorString", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("attackVector", item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("accessVector", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("attackComplexity", item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("accessComplexity", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("privilegesRequired", item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("authentication", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("userInteraction", item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("userInteraction", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", item.get("impact", {}).get("baseMetricV2", {}).get("severity", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("exploitabilityScore", item.get("impact", {}).get("baseMetricV2", {}).get("exploitabilityScore", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("impactScore", item.get("impact", {}).get("baseMetricV2", {}).get("impactScore", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("scope", item.get("impact", {}).get("baseMetricV2", {}).get("scope", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("confidentialityImpact", item.get("impact", {}).get("baseMetricV2", {}).get("confidentialityImpact", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("integrityImpact", item.get("impact", {}).get("baseMetricV2", {}).get("integrityImpact", "")),
                        item.get("impact", {}).get("baseMetricV3", {}).get("availabilityImpact", item.get("impact", {}).get("baseMetricV2", {}).get("availabilityImpact", "")),
                    )
                    cves_list.append(cve)

    cves_df = pd.DataFrame(cves_list, columns=["cve_id", "description", "published_date", "last_modified_date", "cvss_version", "cvss_vector", "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "base_score", "base_severity", "exploitability_score", "impact_score", "scope", "confidentiality_impact", "integrity_impact", "availability_impact"])
    return cves_df

# Download EPSS scores for a given day -1 and ungzip it
def download_epss_scores(date, directory):
    yesterday = datetime.strptime(date, "%Y-%m-%d") - timedelta(days=1)
    yesterday = yesterday.strftime("%Y-%m-%d")
    file_path = os.path.join(directory, f"epss_scores-{yesterday}.csv.gz")
    try:
        if not os.path.exists(file_path):
            logger.info(f"Downloading EPSS scores for date {yesterday}")
            url = f"https://epss.cyentia.com/epss_scores-{yesterday}.csv.gz"
            response = requests.get(url)
            if response.status_code == 200:
                with open(file_path, 'wb') as file:
                    file.write(response.content)
                logger.info(f"Downloaded {file_path}")
        else:
            logger.info(f"File {file_path} already exists, skipping download.")

        logger.info(f"Unzipping {file_path}")
        with gzip.open(file_path, 'rb') as file_in:
            with open(file_path.replace(".gz", ""), 'wb') as file_out:
                file_out.write(file_in.read())
            return file_path.replace(".gz", "")
    except Exception as e:
        logger.error(f"Failed to download EPSS scores for date {date}: {e}")
        return None

# for the today date find the last given months of EPSS scores and download them
def download_epss_scores_for_months(months, directory):
    """ Download EPSS scores for a given number of months back from today. """
    today_date = datetime.now().strftime("%Y-%m-%d")
    
    for i in range(months):
        date = (datetime.strptime(today_date, "%Y-%m-%d").replace(day=1) - timedelta(days=1)).replace(day=1)
        date = (date - relativedelta.relativedelta(months=i)).strftime("%Y-%m-%d")
        file_path = download_epss_scores(date, directory)
        if file_path:
            epss_scores = pd.read_csv(file_path,skiprows=1)
            epss_scores["date"] = date
            epss_scores.to_csv(f"{directory}/epss_scores-{date}.csv", index=False)
        else:
            logger.error(f"Failed to download EPSS scores for date {date}")
            # download for previous date
            date = (datetime.strptime(date, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
            file_path = download_epss_scores(date, directory)
            if file_path:
                epss_scores = pd.read_csv(file_path, skiprows=1)
                epss_scores["date"] = date
                epss_scores.to_csv(f"{directory}/epss_scores-{date}.csv", index=False)
            else:
                logger.error(f"Failed to download EPSS scores for date {date}")


# Check on exploitability against exploitdb data
def get_exploitdb_data(cve_id):
    """
    Get the ExploitDB data for a given CVE ID.
    """
    try:
        logger.info(f"Searching ExploitDB data for {cve_id}")
        exploitdb_data = pEdb.searchCve(cve_id)
        if exploitdb_data:
            return pd.Series({
                "exploitdb_id": exploitdb_data.get("id", ""),
                "description": exploitdb_data.get("description", ""),
                "date": exploitdb_data.get("date", ""),
                "date_updated": exploitdb_data.get("date_updated", ""),
                "author": exploitdb_data.get("author", ""),
                "type": exploitdb_data.get("type", ""),
                "platform": exploitdb_data.get("platform", ""),
                "port": exploitdb_data.get("port", ""),
                "url": exploitdb_data.get("url", "")
            })
    except Exception as e:
        print(f"Error getting ExploitDB data for {cve_id}: {e}")
        return pd.Series({
            "exploitdb_id": None,
            "description": None,
            "date": None,
            "author": None,
            "type": None,
            "platform": None,
            "port": None,
            "url": None
        })

# Download KEV data  
def download_known_exploited_vulnerabilities():
    """ Download the known exploited vulnerabilities data from CISA. """
    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    
    # Download the file and return a DataFrame
    try:
        response = requests.get(url)
        response.raise_for_status()
        file_path = os.path.join("data/download", "known_exploited_vulnerabilities.csv")
        with open(file_path, 'wb') as file:
            file.write(response.content)
        logger.info(f"Downloaded known exploited vulnerabilities to {file_path}")
        return pd.read_csv(file_path)
    except Exception as e:
        print(f"Error loading known exploited vulnerabilities: {e}")
        return None
    
# Enrichment with CISAGOV data
token = os.getenv('GH_TOKEN')
header = {'Authorization': f'token {token}'}
url = f"https://api.github.com/repos/cisagov/vulnrichment"
output = requests.get(url,headers=header)
download_dir = "data/download/CISAGOV"

# function which returns a position in the "metrics" list where the "name" key matches the given value
def get_metric_position_of_other(metrics_list):
    for i, metric in enumerate(metrics_list):
        if "other" in metric:
            return i
    return None

# make output flattened
def flatten_vulnrichment_output(vulnrichment_output):
    """ Flatten the output from the CISAGOV vulnrichment repository. """
    flattened_output = {}
    for keyval in vulnrichment_output:
        if isinstance(keyval, dict):
            for k, v in keyval.items():
                flattened_output[k] = v
        else:
            return None
    return flattened_output

# function for downloading given JSON file for a given CVE ID from the CISAGOV vulnrichment repository
def cve_vulnrichment(cve_id):
    """ Download the JSON file for a given CVE ID from the CISAGOV vulnrichment repository. """
    parts = cve_id.split("-")
    year = parts[1]  # Example: "2021"
    number = int(parts[2])  # Example: "3493" → 3493
    thousands_group = f"{(number // 1000)}xxx"  # Calculate folder name, e.g., 3xxx

    # Construct URL for the JSON file
    file_path = f"{year}/{thousands_group}/{cve_id}.json"
    file_url = f"{url}/contents/{file_path}"

    try:
        # Get the metadata for the file
        metadata_output = requests.get(file_url,headers=header)
        metadata_output.raise_for_status()
        metadata = metadata_output.json()
        download_url = metadata["download_url"]

        # check if the file already exists
        downloaded_file = os.path.join(download_dir, f"{cve_id}.json")
        if os.path.exists(downloaded_file):
            logger.info(f"File {downloaded_file} already exists, skipping download.")
            # read the file and return the options
            with open(downloaded_file, "r") as file:
                cve = json.load(file)
                if cve.get("cveMetadata", {}).get("state") != "REJECTED":
                    adp_list = cve.get("containers", []).get("adp", [])
                    for i, item in enumerate(adp_list):
                        if "CISA ADP Vulnrichment" in item.get("title"):
                            adp_position = i
                    other = adp_list[adp_position].get("metrics", {})
                    position = get_metric_position_of_other(adp_list[adp_position].get("metrics", {}))
                    logger.info(f"Found positions: {adp_position}, {position}")
                    return other[position].get("other").get("content").get("options")
                else:
                    return [{"Exploitation": None}, {"Automatable": None}, {"Technical Impact": None}]

        # Downloading the JSON file
        logger.info(f"Download URL found, downloading: {download_url}")
        json_response = requests.get(download_url)
        json_response.raise_for_status()
        json_data = json_response.json()

        # Create the download folder if it doesn't exist
        os.makedirs(download_dir, exist_ok=True)

        # Save the file locally
        local_file_path = os.path.join(download_dir, f"{cve_id}.json")
        with open(local_file_path, "w") as f:
            json.dump(json_data, f, indent=4)

        logger.info(f"Downloaded and saved {cve_id} to {local_file_path}")
        if json_data.get("cveMetadata", {}).get("state") != "REJECTED":
            adp_list = json_data.get("containers", []).get("adp", [])
            for i, item in enumerate(adp_list):
                if "CISA ADP Vulnrichment" in item.get("title"):
                    adp_position = i
            other = adp_list[adp_position].get("metrics", {})
            position = get_metric_position_of_other(adp_list[adp_position].get("metrics", {}))
            logger.info(f"Found positions: {adp_position}, {position}")
            return other[position].get("other").get("content").get("options")
        else:
            return [{"Exploitation": None}, {"Automatable": None}, {"Technical Impact": None}]
    
    except requests.exceptions.HTTPError as e:
        logger.error(f"Error downloading {cve_id}: {e}")
        return [{"Exploitation": None}, {"Automatable": None}, {"Technical Impact": None}]

# Update the row with the details from the vulnrichment output
def update_row_with_details(row):
    details = flatten_vulnrichment_output(cve_vulnrichment(row['cve_id']))  # Fetch details for the current row's cve_id
    if not details:
        return 
    for key, value in details.items():
        row[key] = value  # Add each detail as a new column to the row
    return row


def epss_time_machine(number: int, directory: str, unit='months') -> list[str]:
    """
    Download EPSS scores for a given number of months or days back from today.
    
    Args:
        number (int): Number of time units to go back (months or days)
        directory (str): Directory to save the files
        unit (str): Time unit to use ('months' or 'days')
    
    Returns:
        list: List of downloaded file paths
    """
    today_date = datetime.now().strftime("%Y-%m-%d")
    files = []
    
    for i in range(number):
        # Start with today's date, set it to 1st of current month, then go back
        date = datetime.strptime(today_date, "%Y-%m-%d")
        if unit == 'months':
            # For months, always set to 1st of the month and subtract months
            date = date.replace(day=1)
            date = date - relativedelta.relativedelta(months=i)
        else:
            # For days, just subtract days
            date = date - timedelta(days=i)
            
        date_str = date.strftime("%Y-%m-%d")
        file_path = download_epss_scores(date_str, directory)
        if file_path:
            files.append(file_path)
            
    return files


# add cwe descriptions to cwe_id in cves_cwes_df by matching CWE-ID with the cwes dataframe
# https://cwe-api.mitre.org/api/v1/cwe/weakness/<number>

def get_cwe_name_and_description(cwe_id):
    """ Get the CWE name and description for a given CWE ID. """
	try:
		logger.info(f"Getting CWE data for {cwe_id}")
		url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id.split('-')[1]}"
		response = requests.get(url)
		cwe_data = response.json()
		cwe_name =  cwe_data.get("Weaknesses")[0].get("Name")
		cwe_description = cwe_data.get("Weaknesses")[0].get("Description")
		return {"cwe_id": cwe_id, "cwe_name": cwe_name, "cwe_desc": cwe_description}
	except Exception as e:
		logger.error(f"Error getting CWE data for {cwe_id}, error: {e}")
		return {"cwe_id": cwe_id, "cwe_name": "not_found", "cwe_desc": "not_found"}