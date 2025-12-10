"""Tests for CVE v5 processor module."""

import json
import tempfile
import unittest
from pathlib import Path

from src.core.cvev5_processor import load_cvev5_cve_data


class TestCVEv5Processor(unittest.TestCase):
    """Test cases for CVE v5 data processing."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Clean up test fixtures."""
        self.temp_dir.cleanup()

    def test_load_cvev5_cve_data_empty_directory(self):
        """Test loading CVE data from empty directory."""
        result = load_cvev5_cve_data(2022, 2022, str(self.data_path))
        self.assertTrue(result.empty)

    def test_load_cvev5_cve_data_with_valid_cve(self):
        """Test loading CVE data with valid CVE record."""
        # Create test CVE directory structure
        cve_dir = self.data_path / "CVEV5" / "cves" / "2022" / "2xxx"
        cve_dir.mkdir(parents=True, exist_ok=True)

        # Create a sample CVE record
        cve_record = {
            "cveMetadata": {
                "cveId": "CVE-2022-1234",
                "datePublished": "2022-01-01T00:00:00Z",
                "dateUpdated": "2022-01-02T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"value": "Test vulnerability description"}],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 7.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        }
                    ],
                }
            },
        }

        # Write test CVE file
        cve_file = cve_dir / "CVE-2022-1234.json"
        with open(cve_file, "w") as f:
            json.dump(cve_record, f)

        # Load CVE data
        result = load_cvev5_cve_data(2022, 2022, str(self.data_path))

        # Verify results
        self.assertFalse(result.empty)
        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]["cve_id"], "CVE-2022-1234")
        self.assertEqual(result.iloc[0]["cwe_id"], "CWE-79")
        self.assertEqual(result.iloc[0]["cvss_v3_1_score"], 7.5)

    def test_load_cvev5_cve_data_multiple_cvss_versions(self):
        """Test loading CVE with multiple CVSS versions (precedence)."""
        cve_dir = self.data_path / "CVEV5" / "cves" / "2022" / "2xxx"
        cve_dir.mkdir(parents=True, exist_ok=True)

        cve_record = {
            "cveMetadata": {
                "cveId": "CVE-2022-5678",
                "datePublished": "2022-01-01T00:00:00Z",
                "dateUpdated": "2022-01-02T00:00:00Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"value": "Test"}],
                    "problemTypes": [{"descriptions": [{"cweId": "CWE-89"}]}],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 9.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        },
                        {
                            "cvssV3_0": {
                                "baseScore": 8.5,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        },
                    ],
                }
            },
        }

        cve_file = cve_dir / "CVE-2022-5678.json"
        with open(cve_file, "w") as f:
            json.dump(cve_record, f)

        result = load_cvev5_cve_data(2022, 2022, str(self.data_path))

        # Should prefer v3.1 over v3.0
        self.assertEqual(result.iloc[0]["cvss_v3_1_score"], 9.0)
        self.assertEqual(result.iloc[0]["cvss_v3_0_score"], 8.5)

    def test_load_cvev5_cve_data_malformed_json(self):
        """Test loading with malformed JSON file."""
        cve_dir = self.data_path / "CVEV5" / "cves" / "2022" / "2xxx"
        cve_dir.mkdir(parents=True, exist_ok=True)

        # Write malformed JSON
        cve_file = cve_dir / "CVE-2022-9999.json"
        with open(cve_file, "w") as f:
            f.write("{invalid json")

        # Should skip malformed file and return empty
        result = load_cvev5_cve_data(2022, 2022, str(self.data_path))
        self.assertTrue(result.empty)

    def test_load_cvev5_cve_data_missing_cve_id(self):
        """Test loading CVE record without cveId."""
        cve_dir = self.data_path / "CVEV5" / "cves" / "2022" / "2xxx"
        cve_dir.mkdir(parents=True, exist_ok=True)

        cve_record = {
            "cveMetadata": {
                "datePublished": "2022-01-01T00:00:00Z",
            },
            "containers": {"cna": {"descriptions": [{"value": "Test"}]}},
        }

        cve_file = cve_dir / "CVE-2022-0000.json"
        with open(cve_file, "w") as f:
            json.dump(cve_record, f)

        result = load_cvev5_cve_data(2022, 2022, str(self.data_path))
        # Should skip records without cveId
        self.assertTrue(result.empty)


if __name__ == "__main__":
    unittest.main()
