"""Unit tests for data processor modules.

Tests cover:
- EPSS processor (download, load)
- KEV processor (download, load)
- CVSS-BT processor (download, load, enrich)
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import polars as pl

from src.core.cvss_bt_processor import CVSSBTProcessor
from src.core.epss_processor import download_epss_scores
from src.core.kev_processor import (
    download_known_exploited_vulnerabilities,
    load_known_exploited_vulnerabilities,
)


class TestEPSSProcessor(unittest.TestCase):
    """Tests for EPSS processor functions."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    @patch("src.core.epss_processor.requests.get")
    def test_download_epss_scores_success(self, mock_get: MagicMock) -> None:
        """Test successful EPSS download."""
        import gzip

        # Create mock gzipped CSV content
        csv_content = b"cve,epss,percentile\nCVE-2021-1234,0.5,95.0\n"
        gzipped_content = gzip.compress(csv_content)

        mock_response = MagicMock()
        mock_response.content = gzipped_content
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = download_epss_scores("2024-01-15", self.temp_dir)

        self.assertIsNotNone(result)
        self.assertTrue(Path(result).exists())

    @patch("src.core.epss_processor.requests.get")
    def test_download_epss_scores_request_error(self, mock_get: MagicMock) -> None:
        """Test EPSS download with request error."""
        import requests

        mock_get.side_effect = requests.RequestException("Connection failed")

        result = download_epss_scores("2024-01-15", self.temp_dir)

        self.assertIsNone(result)

    def test_download_epss_scores_existing_file(self) -> None:
        """Test that existing file is not re-downloaded."""
        # Create the EPSS directory and file
        epss_dir = Path(self.temp_dir) / "EPSS"
        epss_dir.mkdir(parents=True, exist_ok=True)

        # Create a file for "yesterday" (2024-01-14)
        existing_file = epss_dir / "epss_scores-2024-01-14.csv"
        existing_file.write_text("cve,epss,percentile\nCVE-2021-1234,0.5,95.0\n")

        # Should return existing file without making request
        with patch("src.core.epss_processor.requests.get") as mock_get:
            result = download_epss_scores("2024-01-15", self.temp_dir)

            # Should not have made any requests
            mock_get.assert_not_called()
            self.assertIsNotNone(result)


class TestLoadEPSSScores(unittest.TestCase):
    """Tests for loading EPSS scores from CSV."""

    def test_load_epss_csv_with_polars(self) -> None:
        """Test loading EPSS CSV file with Polars."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("cve,epss,percentile\n")
            f.write("CVE-2021-1234,0.5,95.0\n")
            f.write("CVE-2021-5678,0.1,50.0\n")
            temp_path = f.name

        result = pl.read_csv(temp_path)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, pl.DataFrame)
        self.assertEqual(len(result), 2)
        self.assertIn("cve", result.columns)
        self.assertIn("epss", result.columns)

        Path(temp_path).unlink()

    def test_load_epss_csv_missing_file(self) -> None:
        """Test loading from non-existent file raises error."""
        with self.assertRaises(FileNotFoundError):
            pl.read_csv("/nonexistent/path/epss.csv")


class TestKEVProcessor(unittest.TestCase):
    """Tests for KEV processor functions."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    @patch("src.core.kev_processor.requests.get")
    def test_download_kev_success(self, mock_get: MagicMock) -> None:
        """Test successful KEV download."""
        csv_content = (
            "cveID,vendorProject,product,vulnerabilityName\n"
            "CVE-2021-1234,Vendor,Product,Test Vuln\n"
        )

        mock_response = MagicMock()
        mock_response.content = csv_content.encode()
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = download_known_exploited_vulnerabilities(self.temp_dir)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, pl.DataFrame)
        self.assertEqual(len(result), 1)

    @patch("src.core.kev_processor.requests.get")
    def test_download_kev_request_error(self, mock_get: MagicMock) -> None:
        """Test KEV download with request error."""
        import requests

        mock_get.side_effect = requests.RequestException("Connection failed")

        result = download_known_exploited_vulnerabilities(self.temp_dir)

        self.assertIsNone(result)

    def test_download_kev_existing_file(self) -> None:
        """Test that existing KEV file is loaded from disk."""
        # Create the KEV directory and file
        kev_dir = Path(self.temp_dir) / "KEV"
        kev_dir.mkdir(parents=True, exist_ok=True)

        existing_file = kev_dir / "known_exploited_vulnerabilities.csv"
        existing_file.write_text(
            "cveID,vendorProject,product,vulnerabilityName\n"
            "CVE-2021-1234,Vendor,Product,Test Vuln\n"
        )

        # Should load from disk without making request
        with patch("src.core.kev_processor.requests.get") as mock_get:
            result = download_known_exploited_vulnerabilities(self.temp_dir)

            mock_get.assert_not_called()
            self.assertIsNotNone(result)
            self.assertEqual(len(result), 1)

    def test_load_kev_success(self) -> None:
        """Test successful KEV loading."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("cveID,vendorProject,product,vulnerabilityName\n")
            f.write("CVE-2021-1234,Vendor,Product,Test Vuln\n")
            temp_path = f.name

        result = load_known_exploited_vulnerabilities(temp_path)

        self.assertIsNotNone(result)
        self.assertIsInstance(result, pl.DataFrame)
        self.assertEqual(len(result), 1)

        Path(temp_path).unlink()

    def test_load_kev_missing_file(self) -> None:
        """Test loading from non-existent file."""
        result = load_known_exploited_vulnerabilities("/nonexistent/path/kev.csv")
        self.assertIsNone(result)


class TestCVSSBTProcessor(unittest.TestCase):
    """Tests for CVSS-BT processor class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.processor = CVSSBTProcessor(self.temp_dir)

    def test_init(self) -> None:
        """Test processor initialization."""
        processor = CVSSBTProcessor(self.temp_dir, cache_days=7)
        self.assertEqual(processor.cache_days, 7)
        self.assertTrue(processor.cvss_bt_dir.exists())

    def test_get_cache_path(self) -> None:
        """Test cache path generation."""
        cache_path = self.processor._get_cache_path()
        self.assertEqual(cache_path.name, "cvss-bt.csv")
        self.assertEqual(cache_path.parent, self.processor.cvss_bt_dir)

    def test_is_cache_valid_no_file(self) -> None:
        """Test cache validity when file doesn't exist."""
        self.assertFalse(self.processor._is_cache_valid())

    def test_is_cache_valid_fresh_file(self) -> None:
        """Test cache validity with fresh file."""
        # Create a fresh cache file
        cache_path = self.processor._get_cache_path()
        cache_path.write_text("cve,cvss-bt_score\nCVE-2021-1234,7.5\n")

        self.assertTrue(self.processor._is_cache_valid())

    @patch("src.core.cvss_bt_processor.requests.get")
    def test_download_success(self, mock_get: MagicMock) -> None:
        """Test successful CVSS-BT download."""
        csv_content = "cve,cvss-bt_score,epss\nCVE-2021-1234,7.5,0.5\n"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = self.processor.download(force=True)

        self.assertIsNotNone(result)
        self.assertTrue(result.exists())

    @patch("src.core.cvss_bt_processor.requests.get")
    def test_download_uses_cache(self, mock_get: MagicMock) -> None:
        """Test that valid cache is used instead of downloading."""
        # Create a fresh cache file
        cache_path = self.processor._get_cache_path()
        cache_path.write_text("cve,cvss-bt_score\nCVE-2021-1234,7.5\n")

        result = self.processor.download()

        mock_get.assert_not_called()
        self.assertEqual(result, cache_path)

    @patch("src.core.cvss_bt_processor.requests.get")
    def test_download_request_error(self, mock_get: MagicMock) -> None:
        """Test download with request error."""
        import requests

        mock_get.side_effect = requests.RequestException("Connection failed")

        result = self.processor.download(force=True)

        self.assertIsNone(result)

    def test_load_success(self) -> None:
        """Test successful CVSS-BT loading."""
        # Create cache file with expected columns
        cache_path = self.processor._get_cache_path()
        cache_path.write_text(
            "cve,cvss-bt_score,cvss-bt_severity,epss,cisa_kev,exploitdb,metasploit\n"
            "CVE-2021-1234,7.5,High,0.5,true,false,true\n"
            "CVE-2021-5678,5.0,Medium,0.1,false,false,false\n"
        )

        result = self.processor.load()

        self.assertIsInstance(result, pl.DataFrame)
        self.assertEqual(len(result), 2)
        # Check column renaming
        self.assertIn("cve_id", result.columns)
        self.assertIn("cvss_bt_score", result.columns)

    def test_load_no_file(self) -> None:
        """Test loading when no file exists."""
        with patch.object(self.processor, "download", return_value=None):
            result = self.processor.load()

            self.assertIsInstance(result, pl.DataFrame)
            self.assertTrue(result.is_empty())

    def test_load_creates_combined_kev_flag(self) -> None:
        """Test that combined KEV flag is created."""
        cache_path = self.processor._get_cache_path()
        cache_path.write_text(
            "cve,cvss-bt_score,cisa_kev,vulncheck_kev\n"
            "CVE-2021-1234,7.5,true,false\n"
            "CVE-2021-5678,5.0,false,true\n"
            "CVE-2021-9999,3.0,false,false\n"
        )

        result = self.processor.load()

        self.assertIn("is_kev", result.columns)
        kev_values = result["is_kev"].to_list()
        self.assertTrue(kev_values[0])  # cisa_kev=true
        self.assertTrue(kev_values[1])  # vulncheck_kev=true
        self.assertFalse(kev_values[2])  # both false

    def test_load_creates_combined_exploit_flag(self) -> None:
        """Test that combined exploit flag is created."""
        cache_path = self.processor._get_cache_path()
        cache_path.write_text(
            "cve,cvss-bt_score,exploitdb,metasploit,nuclei,poc_github\n"
            "CVE-2021-1234,7.5,true,false,false,false\n"
            "CVE-2021-5678,5.0,false,false,false,false\n"
        )

        result = self.processor.load()

        self.assertIn("has_public_exploit", result.columns)
        exploit_values = result["has_public_exploit"].to_list()
        self.assertTrue(exploit_values[0])  # exploitdb=true
        self.assertFalse(exploit_values[1])  # all false


class TestCVSSBTEnrichment(unittest.TestCase):
    """Tests for CVSS-BT enrichment functionality."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.processor = CVSSBTProcessor(self.temp_dir)

        # Create cache file
        cache_path = self.processor._get_cache_path()
        cache_path.write_text(
            "cve,cvss-bt_score,cvss-bt_severity,epss,cisa_kev\n"
            "CVE-2021-1234,7.5,High,0.5,true\n"
            "CVE-2021-5678,5.0,Medium,0.1,false\n"
        )

    def test_enrich_with_cvss_bt(self) -> None:
        """Test enrichment of scan results with CVSS-BT data."""
        scan_results = pl.DataFrame(
            {
                "cve_id": ["CVE-2021-1234", "CVE-2021-9999"],
                "severity": ["High", "Low"],
            }
        )

        enriched, match_count = self.processor.enrich_with_cvss_bt(scan_results)

        self.assertEqual(match_count, 1)  # Only CVE-2021-1234 matches
        self.assertIn("cvss_bt_score", enriched.columns)

    def test_enrich_with_custom_cve_column(self) -> None:
        """Test enrichment with custom CVE ID column name."""
        scan_results = pl.DataFrame(
            {
                "vuln_id": ["CVE-2021-1234", "CVE-2021-5678"],
                "severity": ["High", "Medium"],
            }
        )

        enriched, match_count = self.processor.enrich_with_cvss_bt(
            scan_results, cve_id_col="vuln_id"
        )

        self.assertEqual(match_count, 2)

    def test_enrich_no_matches(self) -> None:
        """Test enrichment when no CVEs match."""
        scan_results = pl.DataFrame(
            {
                "cve_id": ["CVE-9999-1111", "CVE-9999-2222"],
                "severity": ["High", "Low"],
            }
        )

        enriched, match_count = self.processor.enrich_with_cvss_bt(scan_results)

        self.assertEqual(match_count, 0)


if __name__ == "__main__":
    unittest.main()
