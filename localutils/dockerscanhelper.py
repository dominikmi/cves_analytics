import logging
import subprocess
import json
import pandas as pd
import requests, os
from pygrype import Grype, GrypeBinaryBackend
from dotenv import load_dotenv
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/app_g.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# load .env file
env_path = Path(".") / ".env"
load_dotenv(dotenv_path=env_path)

class DockerImageScanner:
    """Class to scan Docker images in a private registry using Grype"""
    # Constructor to initialize the Docker registry URL and Grype scanner
    def __init__(self, registry_url: str=None):
        self.registry_url = registry_url
        binary_backend = GrypeBinaryBackend(os.getenv("GRYPE_BINARY_PATH"))
        self.grype = Grype(backend=binary_backend)
        self.grype_version = self.grype.version()
        logger.info("Initialized DockerRegistryScanner with registry URL: %s", self.registry_url)

    # Method to get images and tags from the Docker registry
    def list_images_and_tags(self, tls_verify: bool=False):
        """Method to get images and tags from a private Docker registry"""
        if not self.registry_url:
            logger.error("Registry URL not provided")
            return {}
        try:
            repos_url = f"{self.registry_url}/v2/_catalog"
            repos_response = requests.get(repos_url, timeout=10, verify=tls_verify)
            repos_response.raise_for_status()
            logger.info("Fetched data from registry: %s", repos_response.json())
            repositories = repos_response.json().get("repositories", [])
            
            images = {}
            for repo in repositories:
                tags_url = f"{self.registry_url}/v2/{repo}/tags/list"
                tags_response = requests.get(tags_url, timeout=10, verify=tls_verify)
                tags_response.raise_for_status()
                tags = tags_response.json().get("tags", [])
                if not tags:
                    continue
                else:
                    images[repo] = tags
            return images
        except requests.RequestException as e:
            logger.error("Error fetching data from registry: %s", e)
            return {}
        
    # Method to scan an image with Grype and return results in a dataframe
    def scan_image_with_grype(self, image: str) -> pd.DataFrame:
        """Method to scan a Docker image with Grype and return results in a DataFrame"""
        try:
            logger.info("Scanning image with Grype: %s ...", image)
            if not self.registry_url:
                grype_results = json.loads(self.grype.scan(image).to_json())
            else:
                grype_results = json.loads(self.grype.scan(self.registry_url.split("//")[1]+"/"+image).to_json())
            logger.info("Grype scan results: image: %s, found: %s vulnerabilities", image, len(grype_results.get("matches", [])))
            vulnerabilities = []
            if len(grype_results.get("matches", [])):
                logger.info("Parsing Grype scan results ...")
                [vulnerabilities.append({
                    "image_name": image,
                    "vuln_id": vuln.get("vulnerability").get("id"),
                    "severity": vuln.get("vulnerability").get("severity"),
                    "vuln_desc": vuln.get("vulnerability").get("description"),
                    "data_src": vuln.get("vulnerability").get("dataSource"),
                    "package_name": vuln.get("artifact").get("name"),
                    "package_ver": vuln.get("artifact").get("version"),
                    "package_url": vuln.get("artifact").get("purl"),
                    "fixed_ver": vuln.get("matchDetails")[0].get("found").get("versionConstraint")
                }) for vuln in grype_results.get("matches", [])]
                df = pd.DataFrame(vulnerabilities)
                return df.sort_values(by=["severity"], ascending=True).reset_index(drop=True)
            else:
                logger.info("No vulnerabilities found for image: %s", image)
                return pd.DataFrame()
        except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as e:
            logger.error("Error scanning image with Grype: %s", e)
            return pd.DataFrame()
 