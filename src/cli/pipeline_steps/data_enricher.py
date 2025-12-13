import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd

from src.core.cvev5_loader import CVEv5Loader
from src.core.cvss_bt_processor import CVSSBTProcessor
from src.core.cvss_vector_reassessment import reassess_vulnerabilities
from src.core.cwe_processor import get_cwe_name_and_description
from src.core.nlp_extractor import enrich_with_nlp_features
from src.simulation.security_controls import (
    ServiceSecurityControlsGenerator,
)


class DataEnricher:
    """Enriches vulnerability scan results with CVE data and environment context."""

    def __init__(self, logger: logging.Logger):
        """Initialize the data enricher."""
        self.logger = logger

    def enrich(
        self,
        scan_results: pd.DataFrame,
        scenario: dict[str, Any],
        data_path: str,
    ) -> pd.DataFrame:
        """Enrich scan results with CVE data and environment context."""
        start_time = time.time()

        try:
            if scan_results.empty:
                self.logger.warning("No scan results to enrich")
                return scan_results

            self.logger.info("Starting data enrichment process")

            # Rename vuln_id to cve_id for consistency
            if "vuln_id" in scan_results.columns:
                scan_results = scan_results.rename(columns={"vuln_id": "cve_id"})

            # Add environment context to scan results
            enriched = self._add_environment_context(scan_results.copy(), scenario)

            # PRIMARY SOURCE: CVSS-BT dataset (includes CVSS, EPSS, KEV, exploits)
            enriched = self._enrich_with_cvss_bt(enriched, data_path)

            # FALLBACK: CVE v5 data for records not in CVSS-BT
            enriched = self._enrich_with_cvev5_fallback(enriched, data_path)

            # FALLBACK: Load and merge EPSS data for any remaining gaps
            enriched = self._load_and_merge_epss_data(enriched, data_path)

            # Reassess severity using CVSS vectors, EPSS, and environment
            self.logger.info("Reassessing severity with CVSS/EPSS/environment...")
            enriched = reassess_vulnerabilities(
                enriched,
                cvss_score_col="cvss_score",
                cvss_vector_col="cvss_vector",
                epss_score_col="epss_score",
                kev_col="is_kev",
                exposure_risk_factor_col="exposure_risk_factor",
                asset_value_risk_factor_col="asset_value_risk_factor",
                original_severity_col="severity",
            )

            # Enrich with CWE data if available
            if "cwe_id" in enriched.columns:
                self.logger.info("Enriching with CWE data...")
                enriched["cwe_details"] = enriched["cwe_id"].apply(
                    get_cwe_name_and_description,
                )

            # Extract NLP features from descriptions
            if "description" in enriched.columns:
                self.logger.info("Extracting NLP features from descriptions...")
                enriched = enrich_with_nlp_features(enriched, "description")

            duration = time.time() - start_time
            self.logger.info(f"Data enrichment completed in {duration:.2f}s")

            return enriched

        except Exception as e:
            self.logger.error(f"Failed to enrich data: {e!s}", exc_info=True)
            raise

    def _add_environment_context(
        self,
        scan_results: pd.DataFrame,
        scenario: dict[str, Any],
    ) -> pd.DataFrame:
        """Add environment context to scan results."""
        if scan_results.empty or not scenario:
            return scan_results

        # Get scenario-level info
        security_maturity = scenario.get("security_maturity", "developing")
        industry = scenario.get("industry", "general")
        environment = scenario.get("environment", "prod")
        org_size = scenario.get("metadata", {}).get("size", "mid")

        # Initialize per-service security controls generator
        controls_generator = ServiceSecurityControlsGenerator(
            base_maturity=security_maturity,
        )

        # Create a mapping of images to their environment context
        image_context = {}
        services = scenario.get("services", [])

        for service in services:
            image_name = service.get("image")
            if image_name:
                exposure = service.get("exposure", "internal")
                service_role = service.get("role", "service")
                asset_value = service.get("asset_value", "medium")

                # Generate realistic security controls based on exposure
                service_controls = controls_generator.generate_for_service(
                    exposure=exposure,
                    service_role=service_role,
                    asset_value=asset_value,
                    industry=industry,
                    environment=environment,
                    size=org_size,
                )

                # Store context information for this image
                image_context[image_name] = {
                    "service_name": service.get("name", "unknown"),
                    "service_role": service_role,
                    "exposure": exposure,
                    "zone": service.get("zone", "internal"),
                    "asset_value": asset_value,
                    "ownership": service.get("ownership", "DEV"),
                    "environment_type": environment,
                    "industry": industry,
                    "is_segmented": scenario.get("is_segmented", False),
                    "security_posture": scenario.get("security_posture", {}),
                    "security_controls": service_controls,
                    "security_maturity": security_maturity,
                }

        # Log control distribution for debugging
        self._log_control_distribution(image_context)

        # Add context columns to scan results
        if "image_name" in scan_results.columns:
            # Add environment context columns
            scan_results["service_name"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("service_name", "unknown"),
            )
            scan_results["service_role"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("service_role", "service"),
            )
            scan_results["exposure"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("exposure", "internal"),
            )
            scan_results["zone"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("zone", "internal"),
            )
            scan_results["asset_value"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("asset_value", "medium"),
            )
            scan_results["ownership"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("ownership", "DEV"),
            )
            scan_results["environment_type"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("environment_type", "unknown"),
            )

            # Add security controls column for Bayesian risk assessment
            scan_results["security_controls"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get("security_controls", {}),
            )
            scan_results["security_maturity"] = scan_results["image_name"].map(
                lambda x: image_context.get(x, {}).get(
                    "security_maturity",
                    "developing",
                ),
            )

            # Add exposure risk factor (legacy - kept for backward compatibility)
            exposure_risk_map = {
                "internet-facing": 1.5,
                "dmz": 1.3,
                "internal": 1.0,
                "restricted": 0.8,
                "unknown": 1.0,
            }
            scan_results["exposure_risk_factor"] = scan_results["exposure"].map(
                exposure_risk_map,
            )

            # Add asset value risk factor (legacy - kept for backward compatibility)
            asset_value_risk_map = {
                "critical": 1.5,
                "high": 1.3,
                "medium": 1.0,
                "low": 0.8,
                "unknown": 1.0,
            }
            scan_results["asset_value_risk_factor"] = scan_results["asset_value"].map(
                asset_value_risk_map,
            )

            vuln_count = len(scan_results)
            self.logger.info(f"Added environment context for {vuln_count} vulns")
            self.logger.info(f"Security maturity: {security_maturity}")

        return scan_results

    def _log_control_distribution(self, image_context: dict[str, dict]) -> None:
        """Log security control distribution by exposure type."""
        exposure_controls: dict[str, list[str]] = {}

        for _image_name, context in image_context.items():
            exposure = context.get("exposure", "internal")
            controls = context.get("security_controls", {})
            active = [
                k for k, v in controls.items() if v and not k.startswith("patch_")
            ]

            if exposure not in exposure_controls:
                exposure_controls[exposure] = []
            exposure_controls[exposure].extend(active)

        self.logger.info("Security controls by exposure:")
        for exposure, controls in exposure_controls.items():
            # Count unique controls
            control_counts = {}
            for ctrl in controls:
                control_counts[ctrl] = control_counts.get(ctrl, 0) + 1

            active_list = list(control_counts.keys())
            self.logger.info(f"  {exposure}: {active_list}")

    def _convert_posture_to_controls(self, posture: dict[str, Any]) -> dict[str, bool]:
        """Convert legacy security_posture dict to security_controls format."""
        controls = {
            "network_segmentation": posture.get("network_segmentation", False),
            "mfa": posture.get("mfa_enforced", False),
            "firewall": True,  # Assume basic firewall is always present
            "antivirus": True,  # Assume basic AV is always present
            "incident_response_plan": posture.get("incident_response_plan", False),
            "security_training": posture.get("security_training", False),
        }

        # Map patch management cadence
        patch_mgmt = posture.get("patch_management", "monthly")
        controls["patch_daily"] = patch_mgmt == "daily"
        controls["patch_weekly"] = patch_mgmt == "weekly"
        controls["patch_monthly"] = patch_mgmt == "monthly"
        controls["patch_quarterly"] = patch_mgmt == "quarterly"

        return controls

    def _load_and_merge_epss_data(
        self,
        enriched: pd.DataFrame,
        data_path: str,
    ) -> pd.DataFrame:
        """Load EPSS data and merge it with enriched vulnerability data."""
        try:
            # Find the most recent EPSS CSV file
            epss_dir = Path(data_path) / "EPSS"
            if not epss_dir.exists():
                self.logger.warning(f"EPSS directory not found at {epss_dir}")
                return enriched

            # Look for CSV files (both compressed and uncompressed)
            csv_files = list(epss_dir.glob("epss_scores-*.csv"))
            if not csv_files:
                # Also check for gzipped files
                gz_files = list(epss_dir.glob("epss_scores-*.csv.gz"))
                if gz_files:
                    # For now, just log that we found gz files
                    self.logger.info(f"Found {len(gz_files)} gzipped EPSS files")

            if not csv_files:
                self.logger.warning("No EPSS CSV files found")
                return enriched

            # Get the most recent file (sort by date in filename)
            csv_files.sort(key=lambda x: x.name, reverse=True)
            latest_epss_file = csv_files[0]

            self.logger.info(f"Loading EPSS data from {latest_epss_file}")

            # Load EPSS data (skip comment lines)
            epss_data = pd.read_csv(latest_epss_file, comment="#")
            self.logger.info(f"Loaded {len(epss_data)} EPSS records")

            # Rename columns to match our expected format
            col_rename = {"cve": "cve_id", "epss": "epss_score"}
            epss_data = epss_data.rename(columns=col_rename)

            # Merge with enriched data
            if "cve_id" in enriched.columns:
                enriched = pd.merge(
                    enriched,
                    epss_data[["cve_id", "epss_score"]],
                    left_on="cve_id",
                    right_on="cve_id",
                    how="left",
                )
                merged_count = enriched["epss_score"].notna().sum()
                self.logger.info(f"Merged EPSS data with {merged_count} vulns")

                # Fill NaN EPSS scores with 0
                enriched["epss_score"] = enriched["epss_score"].fillna(0.0)
                filled = enriched["epss_score"].isna().sum()
                self.logger.info(f"Filled missing EPSS scores for {filled} records")
            else:
                self.logger.warning("No cve_id column found, skipping EPSS merge")

        except Exception as e:
            self.logger.warning(f"Failed to load EPSS data: {e!s}")

        return enriched

    def _fetch_missing_cve_data(self, enriched: pd.DataFrame) -> pd.DataFrame:
        """Fetch missing CVE data from NVD API for records without CVSS scores."""
        missing_mask = enriched["cvss_score"].isna()
        if not missing_mask.any():
            return enriched

        missing_cves = enriched[missing_mask]["cve_id"].unique()
        self.logger.info(
            f"Skipping NVD API for {len(missing_cves)} CVEs (rate limited)",
        )

        return enriched

    def _extract_cvss_data(self, enriched: pd.DataFrame) -> pd.DataFrame:
        """Extract CVSS vectors and scores from CVE v5 data."""
        # Find best CVSS score (prefer v4.0 > v3.1 > v3.0 > v2.0)
        enriched["cvss_vector"] = None
        enriched["cvss_score"] = None
        enriched["cvss_version"] = None

        cvss_priority = [
            ("cvss_v4_0_score", "cvss_v4_0_vector", "4.0"),
            ("cvss_v3_1_score", "cvss_v3_1_vector", "3.1"),
            ("cvss_v3_0_score", "cvss_v3_0_vector", "3.0"),
            ("cvss_v2_0_score", "cvss_v2_0_vector", "2.0"),
        ]

        for score_col, vector_col, version in cvss_priority:
            if score_col not in enriched.columns:
                continue

            mask = enriched["cvss_score"].isna() & enriched[score_col].notna()
            enriched.loc[mask, "cvss_score"] = enriched.loc[mask, score_col]
            enriched.loc[mask, "cvss_vector"] = enriched.loc[mask, vector_col]
            enriched.loc[mask, "cvss_version"] = version

        cvss_count = enriched["cvss_score"].notna().sum()
        self.logger.info(f"Extracted CVSS data for {cvss_count} vulns from CVE v5")

        return enriched

    def _enrich_with_cvss_bt(
        self,
        enriched: pd.DataFrame,
        data_path: str,
    ) -> pd.DataFrame:
        """Enrich scan results with CVSS-BT data as the primary source.

        CVSS-BT includes:
        - CVSS-BT adjusted scores (incorporates exploitability)
        - EPSS scores
        - KEV flags (CISA and VulnCheck)
        - Exploit availability (ExploitDB, Metasploit, Nuclei, GitHub PoC)
        """
        try:
            self.logger.info("Loading CVSS-BT data (primary source)...")
            processor = CVSSBTProcessor(data_path)
            enriched, enriched_count = processor.enrich_with_cvss_bt(enriched)

            if enriched_count > 0:
                # Map CVSS-BT columns to standard columns
                # Use CVSS-BT score as primary, base score as fallback
                if "cvss_bt_score" in enriched.columns:
                    enriched["cvss_score"] = enriched["cvss_bt_score"]
                    enriched["cvss_vector"] = enriched.get("cvss_bt_vector")

                # Use EPSS from CVSS-BT
                if "epss" in enriched.columns:
                    enriched["epss_score"] = enriched["epss"]

                self.logger.info(
                    f"CVSS-BT enrichment complete: {enriched_count} records",
                )
            else:
                self.logger.warning(
                    "No CVSS-BT data available, will use fallback sources",
                )

        except Exception as e:
            self.logger.warning(f"CVSS-BT enrichment failed: {e}, using fallback")

        return enriched

    def _enrich_with_cvev5_fallback(
        self,
        enriched: pd.DataFrame,
        data_path: str,
    ) -> pd.DataFrame:
        """Enrich scan results with CVE v5 data for records not covered by CVSS-BT.

        This is a fallback source for:
        - CVEs not in CVSS-BT dataset
        - Additional metadata (descriptions, CWE)
        """
        # Check how many records still need CVSS data
        needs_cvss = (
            enriched["cvss_score"].isna()
            if "cvss_score" in enriched.columns
            else pd.Series([True] * len(enriched))
        )
        missing_count = needs_cvss.sum()

        if missing_count == 0:
            self.logger.info(
                "All records have CVSS data from CVSS-BT, skipping CVE v5 fallback",
            )
            return enriched

        self.logger.info(f"{missing_count} records need CVE v5 fallback data")

        try:
            # Load CVE v5 data
            current_year = datetime.now().year
            loader = CVEv5Loader(cache_dir=f"{data_path}/.cache")
            self.logger.info("Loading CVE v5 data with caching...")
            cve_v5_data = loader.load_cvev5_cve_data(
                current_year - 5,
                current_year,
                data_path,
                use_cache=True,
            )

            if cve_v5_data.empty:
                self.logger.warning("No CVE v5 data available")
                return enriched

            # Merge with CVE v5 data
            scan_count = len(enriched)
            cve_count = len(cve_v5_data)
            self.logger.info(
                f"Merging {scan_count} scan results with {cve_count} CVE v5 records",
            )

            # Columns to merge from CVE v5
            cve_cols_to_merge = ["cve_id", "description", "cwe_id"]

            # Add CVSS columns if we need them
            cvss_cols = [
                "cvss_v4_0_score",
                "cvss_v4_0_vector",
                "cvss_v3_1_score",
                "cvss_v3_1_vector",
                "cvss_v3_0_score",
                "cvss_v3_0_vector",
                "cvss_v2_0_score",
                "cvss_v2_0_vector",
            ]
            for col in cvss_cols:
                if col in cve_v5_data.columns:
                    cve_cols_to_merge.append(col)

            available_cols = [c for c in cve_cols_to_merge if c in cve_v5_data.columns]
            cve_subset = cve_v5_data[available_cols].drop_duplicates(subset=["cve_id"])

            enriched = pd.merge(
                enriched,
                cve_subset,
                left_on="cve_id",
                right_on="cve_id",
                how="left",
                suffixes=("", "_v5"),
            )

            self.logger.info(
                f"Enriched {len(enriched)} vulnerabilities with CVE v5 data",
            )

            # Extract CVSS data for records that don't have it yet
            if (
                "cvss_score" not in enriched.columns
                or enriched["cvss_score"].isna().any()
            ):
                self.logger.info("Extracting CVSS vectors and scores from CVE v5...")
                enriched = self._extract_cvss_data(enriched)

                # Log missing CVSS data
                if "cvss_score" in enriched.columns:
                    missing_count = enriched["cvss_score"].isna().sum()
                    self.logger.info(
                        f"{missing_count} records still missing CVSS scores",
                    )

        except Exception as e:
            self.logger.warning(f"CVE v5 fallback enrichment failed: {e}")

        return enriched
