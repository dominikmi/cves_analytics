import gzip
import pandas as pd
import requests
import logging
import os 
import json
from datetime import datetime, timedelta
from dateutil import relativedelta
from localutils.errorhandler import error_handler
from functools import lru_cache as LRU

from dotenv import load_dotenv
load_dotenv()

# set up the current date and time
current_date = datetime.now().strftime('%Y-%m-%d')
current_time = datetime.now().strftime('%H:%M:%S')

# Set up logging
log_directory = "logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(filename=f"{log_directory}/app_{current_date}_{current_time}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ExploitDB
from pyExploitDb import PyExploitDb
pEdb = PyExploitDb()
pEdb.debug = False
pEdb.openFile()

# download NVD CVE data for a given range of years
@error_handler(logger)
def download_nvd_cve_data(start_year, end_year, directory):
    base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.zip"
    directory = f"{directory}/NVDCVE"

    if not os.path.exists(directory):
        os.makedirs(directory)
    
    for year in range(start_year, end_year + 1):
        file_path = os.path.join(directory, f"nvdcve-1.1-{year}.json.zip")
        if os.path.exists(file_path) or os.path.exists(file_path.replace(".zip", "")):
            logger.info(f"File {file_path} already exists, skipping download.")
            continue
        
        url = base_url.format(year)
        response = requests.get(url)
        if response.status_code == 200:
            with open(file_path, 'wb') as file:
                file.write(response.content)
            logger.info(f"Downloaded {file_path}")
        else:
            logger.error(f"Failed to download data for year {year}")

# unzip all found files in the directory
@error_handler(logger)
def unzip_files(directory):
    import zipfile
    import os
    
    directory = f"{directory}/NVDCVE"
    for file in os.listdir(directory):
        if file.endswith(".zip"):
            file_path = os.path.join(directory, file)
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(directory)
                logger.info(f"Unzipped {file_path}")
                os.remove(file_path)

# Load NVD CVE data into a DataFrame
@error_handler(logger)
def load_nvd_cve_data(start_year: int, end_year: int, directory: str) -> pd.DataFrame:
    directory = f"{directory}/NVDCVE"
    data = []
    cves_list = []
    for file in os.listdir(directory):
        # check if file is .json and is within the range of years
        if file.endswith(".json") and int(file.split("-")[2].split(".")[0]) in range(start_year, end_year + 1):
            file_path = os.path.join(directory, file)
            with open(file_path, 'r') as file:
                data = json.load(file)
                logger.info(f"Loaded {file_path}")
                for _, cve_data in enumerate(data.get("CVE_Items", [])):
                    if cve_data.get("impact"):
                        for key in cve_data.get("impact"):
                            if key == "baseMetricV3":
                                cve_id = cve_data.get("cve").get("CVE_data_meta").get("ID", "") if cve_data.get("cve") else ""
                                description = cve_data.get("cve").get("description").get("description_data")[0].get("value", "")
                                published_date = cve_data.get("publishedDate", "")
                                last_modified_date = cve_data.get("lastModifiedDate", "")
                                problemtype_data = cve_data.get("cve", {}).get("problemtype", {}).get("problemtype_data", [{}])[0].get("description", [])
                                cwe_id = problemtype_data[0].get("value", "") if problemtype_data else ""
                                cvss_version = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("version") 
                                severity = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("baseSeverity")
                                base_score = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("baseScore")
                                exploitability_score = cve_data.get("impact").get("baseMetricV3").get("exploitabilityScore")
                                vector_string = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("vectorString")
                                attack_vector = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("attackVector")
                                attack_complexity = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("attackComplexity")
                                authentication = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("privilegesRequired")
                                user_interaction = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("userInteraction")
                                confidentiality_impact = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("confidentialityImpact")
                                integrity_impact = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("integrityImpact")
                                availability_impact = cve_data.get("impact").get("baseMetricV3").get("cvssV3").get("availabilityImpact")
                                break
                            elif key == "baseMetricV2":
                                cve_id = cve_data.get("cve").get("CVE_data_meta").get("ID", "") if cve_data.get("cve") else ""
                                description = cve_data.get("cve").get("description").get("description_data")[0].get("value", "")
                                published_date = cve_data.get("publishedDate", "")
                                last_modified_date = cve_data.get("lastModifiedDate", "")
                                problemtype_data = cve_data.get("cve", {}).get("problemtype", {}).get("problemtype_data", [{}])[0].get("description", [])
                                cwe_id = problemtype_data[0].get("value", "") if problemtype_data else ""
                                cvss_version = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("version") 
                                severity = cve_data.get("impact").get("baseMetricV2").get("severity")
                                base_score = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("baseScore")
                                exploitability_score = cve_data.get("impact").get("baseMetricV2").get("exploitabilityScore")
                                vector_string = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("vectorString")
                                attack_vector = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("accessVector")
                                attack_complexity = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("accessComplexity")
                                authentication = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("authentication")
                                user_interaction = cve_data.get("impact").get("baseMetricV2").get("userInteractionRequired")
                                confidentiality_impact = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("confidentialityImpact")
                                integrity_impact = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("integrityImpact")
                                availability_impact = cve_data.get("impact").get("baseMetricV2").get("cvssV2").get("availabilityImpact")
                                break
                    cves_list.append((cve_id, description, published_date, last_modified_date, cvss_version, cwe_id, vector_string, attack_vector, attack_complexity, authentication, user_interaction, base_score, severity, exploitability_score, confidentiality_impact, integrity_impact, availability_impact))

    cves_df = pd.DataFrame(cves_list, columns=["cve_id", "description", "published_date", "last_modified_date", "cvss_version", "cwe_id", "cvss_vector", "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "base_score", "base_severity", "exploitability_score", "confidentiality_impact", "integrity_impact", "availability_impact"])
    return cves_df

# Download EPSS scores for a given day -1 and ungzip it
@error_handler(logger)
def download_epss_scores(date, directory):
    directory = f"{directory}/EPSS"
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
@error_handler(logger)
def download_epss_scores_for_months(months, directory):
    """ Download EPSS scores for a given number of months back from today. """
    today_date = datetime.now().strftime("%Y-%m-%d")
    directory = f"{directory}/EPSS"
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
@error_handler(logger)
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
@error_handler()
def download_known_exploited_vulnerabilities(directory: str):
    """ Download the known exploited vulnerabilities data from CISA. """
    url = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    
    directory = f"{directory}/KEV"
    # Download the file and return a DataFrame
    try:
        response = requests.get(url)
        response.raise_for_status()
        file_path = os.path.join(directory, "known_exploited_vulnerabilities.csv")
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
    if vulnrichment_output is None:
        return None
    flattened_output = {}
    for keyval in vulnrichment_output:
        if isinstance(keyval, dict):
            for k, v in keyval.items():
                flattened_output[k] = v
        else:
            return None
    return flattened_output

# function for downloading given JSON file for a given CVE ID from the CISAGOV vulnrichment repository
@error_handler()
def cve_vulnrichment(cve_id):
    logger.info(f"Processing cve_id -> {cve_id}")
    directory = "data/download/vulnrichment"
    year = cve_id.split("-")[1]  # Example: "2021"
    number = int(cve_id.split("-")[2])  # Example: "1891" → 1891
    thousands_group = f"{(number // 1000)}xxx"  # Calculate folder name, e.g., 1xxx
    cve_dir = f"{directory}/{year}/{thousands_group}"  # Example: "data/download/vulnrichment/2021/1xxx"

    # Construct file_path for the JSON file
    file_path = f"{cve_dir}/{cve_id}.json"
    logger.info(f"File path: {file_path}")

    # check if the file already exists
    if os.path.exists(file_path):
        logger.info(f"Processing data in {file_path}")
        # read the file and return the options
        with open(file_path, "r") as file:
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
        
    # check if the file does not exist and return None
    else: 
            return [{"Exploitation": None}, {"Automatable": None}, {"Technical Impact": None}]


# Update the row with the details from the vulnrichment output
@error_handler()
def update_row_with_details(row):
    details = flatten_vulnrichment_output(cve_vulnrichment(row['cve_id']))  # Fetch details for the current row's cve_id
    if not details:
        return 
    for key, value in details.items():
        row[key] = value  # Add each detail as a new column to the row
    return row

@error_handler()
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
    directory = f"{directory}/EPSS"
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

@error_handler(logger)
def list_to_csv(lst: list) -> str:
    """Converts a list of strings to a comma-separated string."""
    return ", ".join(str(item).strip() for item in lst if item is not None)

@error_handler(logger)
@LRU(maxsize=128)
def get_cwe_name_and_description(cwe_id):
    try:
        logger.info(f"Getting CWE data for {cwe_id}")
        if cwe_id in ["not_found", "NVD-CWE-noinfo", "NVD-CWE-Other"] or not cwe_id or cwe_id == "":
            return {"cwe_id": cwe_id, "cwe_name": "not_found", "cwe_desc": "not_found", "cwe_cc_scope": "not_found", "cwe_cc_impact": "not_found"}
        url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id.split('-')[1]}"
        response = requests.get(url)
        cwe_data = response.json()
        if cwe_data == f"for weakness: cwe ({cwe_id.split('-')[1]}) not found, use the category endpoint":
            return {"cwe_id": cwe_id, "cwe_name": "not_found", "cwe_desc": "not_found", "cwe_cc_scope": "not_found", "cwe_cc_impact": "not_found"}
        cwe_name = cwe_data.get("Weaknesses")[0].get("Name") if cwe_data.get("Weaknesses")[0].get("Name") else "not_found"
        cwe_description = cwe_data.get("Weaknesses")[0].get("Description") if cwe_data.get("Weaknesses")[0].get("Description") else "not_found"
        cwe_cc_impact = list_to_csv(cwe_data.get("Weaknesses")[0].get("CommonConsequences")[0].get("Impact")) if cwe_data.get("Weaknesses")[0].get("CommonConsequences") else "not_found"
        cwe_cc_scope = list_to_csv(cwe_data.get("Weaknesses")[0].get("CommonConsequences")[0].get("Scope")) if cwe_data.get("Weaknesses")[0].get("CommonConsequences") else "not_found"
        return {"cwe_id": cwe_id, "cwe_name": cwe_name, "cwe_desc": cwe_description, "cwe_cc_scope": cwe_cc_scope, "cwe_cc_impact": cwe_cc_impact}
    except Exception as e:
        logger.error(f"Error getting CWE data for {cwe_id}, error: {e}")
        return {"cwe_id": cwe_id, "cwe_name": "not_found", "cwe_desc": "not_found", "cwe_cc_scope": "not_found", "cwe_cc_impact": "not_found"}