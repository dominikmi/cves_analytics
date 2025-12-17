"""Unit tests for Docker image scanner module.

Tests cover:
- DockerImageScanner initialization
- Image listing from registry (mocked)
- Grype scanning (mocked subprocess)
- Error handling
- Result parsing
"""

import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import polars as pl

from src.core.docker_scanner import DockerImageScanner, validate_image_name


class TestDockerImageScannerInit(unittest.TestCase):
    """Tests for DockerImageScanner initialization."""

    def test_init_with_registry_url(self) -> None:
        """Test initialization with registry URL."""
        scanner = DockerImageScanner(registry_url="https://registry.example.com")
        self.assertEqual(scanner.registry_url, "https://registry.example.com")

    def test_init_with_grype_path(self) -> None:
        """Test initialization with grype binary path."""
        scanner = DockerImageScanner(grype_binary_path="/usr/local/bin/grype")
        self.assertEqual(scanner.grype_binary_path, "/usr/local/bin/grype")

    def test_init_with_both(self) -> None:
        """Test initialization with both registry and grype path."""
        scanner = DockerImageScanner(
            registry_url="https://registry.example.com",
            grype_binary_path="/usr/local/bin/grype",
        )
        self.assertEqual(scanner.registry_url, "https://registry.example.com")
        self.assertEqual(scanner.grype_binary_path, "/usr/local/bin/grype")

    def test_init_without_params(self) -> None:
        """Test initialization without parameters."""
        scanner = DockerImageScanner()
        self.assertIsNone(scanner.registry_url)
        self.assertIsNone(scanner.grype_binary_path)


class TestListImagesAndTags(unittest.TestCase):
    """Tests for list_images_and_tags method."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.scanner = DockerImageScanner(registry_url="https://registry.example.com")

    def test_no_registry_url(self) -> None:
        """Test that empty dict is returned when no registry URL."""
        scanner = DockerImageScanner()
        result = scanner.list_images_and_tags()
        self.assertEqual(result, {})

    @patch("src.core.docker_scanner.requests.get")
    def test_successful_listing(self, mock_get: MagicMock) -> None:
        """Test successful image listing from registry."""
        # Mock catalog response
        catalog_response = MagicMock()
        catalog_response.json.return_value = {"repositories": ["nginx", "python"]}
        catalog_response.raise_for_status = MagicMock()

        # Mock tags responses
        nginx_tags_response = MagicMock()
        nginx_tags_response.json.return_value = {"tags": ["1.18", "latest"]}
        nginx_tags_response.raise_for_status = MagicMock()

        python_tags_response = MagicMock()
        python_tags_response.json.return_value = {"tags": ["3.12", "3.11"]}
        python_tags_response.raise_for_status = MagicMock()

        mock_get.side_effect = [
            catalog_response,
            nginx_tags_response,
            python_tags_response,
        ]

        result = self.scanner.list_images_and_tags()

        self.assertEqual(result["nginx"], ["1.18", "latest"])
        self.assertEqual(result["python"], ["3.12", "3.11"])

    @patch("src.core.docker_scanner.requests.get")
    def test_request_exception(self, mock_get: MagicMock) -> None:
        """Test handling of request exceptions."""
        import requests

        mock_get.side_effect = requests.RequestException("Connection failed")

        result = self.scanner.list_images_and_tags()
        self.assertEqual(result, {})

    @patch("src.core.docker_scanner.requests.get")
    def test_empty_repositories(self, mock_get: MagicMock) -> None:
        """Test handling of empty repositories list."""
        catalog_response = MagicMock()
        catalog_response.json.return_value = {"repositories": []}
        catalog_response.raise_for_status = MagicMock()

        mock_get.return_value = catalog_response

        result = self.scanner.list_images_and_tags()
        self.assertEqual(result, {})


class TestScanImageWithGrype(unittest.TestCase):
    """Tests for scan_image_with_grype method."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.scanner = DockerImageScanner(grype_binary_path="/usr/local/bin/grype")
        self.sample_grype_output = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2021-1234",
                        "severity": "High",
                        "description": "Test vulnerability",
                    },
                    "artifact": {
                        "name": "openssl",
                        "version": "1.1.1",
                        "type": "deb",
                    },
                    "relatedVulnerabilities": [
                        {
                            "id": "CVE-2021-1234",
                            "cvss": [{"metrics": {"baseScore": 7.5}}],
                        }
                    ],
                },
                {
                    "vulnerability": {
                        "id": "CVE-2021-5678",
                        "severity": "Medium",
                        "description": "Another vulnerability",
                    },
                    "artifact": {
                        "name": "curl",
                        "version": "7.68.0",
                        "type": "deb",
                    },
                    "relatedVulnerabilities": [
                        {
                            "id": "CVE-2021-5678",
                            "cvss": [{"metrics": {"baseScore": 5.0}}],
                        }
                    ],
                },
            ],
            "source": {"target": {"userInput": "nginx:1.18"}},
        }

    @patch("src.core.docker_scanner.subprocess.run")
    def test_successful_scan(self, mock_run: MagicMock) -> None:
        """Test successful image scan."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(self.sample_grype_output),
            stderr="",
        )

        result = self.scanner.scan_image_with_grype("nginx:1.18")

        self.assertIsInstance(result, pl.DataFrame)
        self.assertEqual(len(result), 2)
        self.assertIn("vuln_id", result.columns)
        self.assertIn("severity", result.columns)

    @patch("src.core.docker_scanner.subprocess.run")
    def test_scan_nonzero_exit(self, mock_run: MagicMock) -> None:
        """Test handling of non-zero exit code."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error scanning image",
        )

        result = self.scanner.scan_image_with_grype("nginx:1.18")

        self.assertIsInstance(result, pl.DataFrame)
        self.assertTrue(result.is_empty())

    @patch("src.core.docker_scanner.subprocess.run")
    def test_scan_empty_output(self, mock_run: MagicMock) -> None:
        """Test handling of empty output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        result = self.scanner.scan_image_with_grype("nginx:1.18")

        self.assertIsInstance(result, pl.DataFrame)
        self.assertTrue(result.is_empty())

    @patch("src.core.docker_scanner.subprocess.run")
    def test_scan_invalid_json(self, mock_run: MagicMock) -> None:
        """Test handling of invalid JSON output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="not valid json",
            stderr="",
        )

        result = self.scanner.scan_image_with_grype("nginx:1.18")

        self.assertIsInstance(result, pl.DataFrame)
        self.assertTrue(result.is_empty())

    @patch("src.core.docker_scanner.subprocess.run")
    def test_scan_timeout(self, mock_run: MagicMock) -> None:
        """Test handling of subprocess timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="grype", timeout=300)

        result = self.scanner.scan_image_with_grype("nginx:1.18")

        self.assertIsInstance(result, pl.DataFrame)
        self.assertTrue(result.is_empty())

    @patch("src.core.docker_scanner.subprocess.run")
    def test_scan_no_matches(self, mock_run: MagicMock) -> None:
        """Test scan with no vulnerabilities found."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"matches": [], "source": {}}),
            stderr="",
        )

        result = self.scanner.scan_image_with_grype("nginx:1.18")

        self.assertIsInstance(result, pl.DataFrame)
        self.assertTrue(result.is_empty())

    @patch("src.core.docker_scanner.subprocess.run")
    def test_command_construction(self, mock_run: MagicMock) -> None:
        """Test that the grype command is constructed correctly."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"matches": []}),
            stderr="",
        )

        self.scanner.scan_image_with_grype("nginx:1.18")

        # Verify subprocess.run was called with correct arguments
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        cmd = call_args[0][0]

        self.assertEqual(cmd[0], "/usr/local/bin/grype")
        self.assertEqual(cmd[1], "nginx:1.18")
        self.assertIn("--output", cmd)
        self.assertIn("json", cmd)


class TestScanImageResultParsing(unittest.TestCase):
    """Tests for vulnerability result parsing."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.scanner = DockerImageScanner(grype_binary_path="/usr/local/bin/grype")

    @patch("src.core.docker_scanner.subprocess.run")
    def test_parse_vulnerability_fields(self, mock_run: MagicMock) -> None:
        """Test that vulnerability fields are parsed correctly."""
        grype_output = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2021-1234",
                        "severity": "Critical",
                        "description": "Critical vulnerability",
                    },
                    "artifact": {
                        "name": "openssl",
                        "version": "1.1.1k",
                        "type": "deb",
                    },
                    "relatedVulnerabilities": [
                        {
                            "id": "CVE-2021-1234",
                            "cvss": [
                                {
                                    "metrics": {
                                        "baseScore": 9.8,
                                    },
                                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            ],
                        }
                    ],
                }
            ],
            "source": {"target": {"userInput": "nginx:1.18"}},
        }

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(grype_output),
            stderr="",
        )

        result = self.scanner.scan_image_with_grype("nginx:1.18")

        self.assertEqual(len(result), 1)
        row = result.to_dicts()[0]
        self.assertEqual(row["vuln_id"], "CVE-2021-1234")
        self.assertEqual(row["severity"], "Critical")
        self.assertEqual(row["package_name"], "openssl")
        self.assertEqual(row["package_ver"], "1.1.1k")


class TestImageNameValidation(unittest.TestCase):
    """Tests for image name handling."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.scanner = DockerImageScanner(grype_binary_path="/usr/local/bin/grype")

    @patch("src.core.docker_scanner.subprocess.run")
    def test_image_with_tag(self, mock_run: MagicMock) -> None:
        """Test scanning image with tag."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"matches": []}),
            stderr="",
        )

        self.scanner.scan_image_with_grype("nginx:1.18")

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[1], "nginx:1.18")

    @patch("src.core.docker_scanner.subprocess.run")
    def test_image_with_registry(self, mock_run: MagicMock) -> None:
        """Test scanning image with registry prefix."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"matches": []}),
            stderr="",
        )

        self.scanner.scan_image_with_grype("registry.example.com/nginx:1.18")

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[1], "registry.example.com/nginx:1.18")

    @patch("src.core.docker_scanner.subprocess.run")
    def test_image_with_digest(self, mock_run: MagicMock) -> None:
        """Test scanning image with digest."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"matches": []}),
            stderr="",
        )

        digest = "sha256:abc123"
        self.scanner.scan_image_with_grype(f"nginx@{digest}")

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[1], f"nginx@{digest}")


class TestValidateImageName(unittest.TestCase):
    """Tests for validate_image_name function."""

    def test_valid_simple_image(self) -> None:
        """Test valid simple image name."""
        self.assertTrue(validate_image_name("nginx"))
        self.assertTrue(validate_image_name("python"))

    def test_valid_image_with_tag(self) -> None:
        """Test valid image with tag."""
        self.assertTrue(validate_image_name("nginx:1.18"))
        self.assertTrue(validate_image_name("python:3.12-slim"))

    def test_valid_image_with_registry(self) -> None:
        """Test valid image with registry prefix."""
        self.assertTrue(validate_image_name("registry.example.com/nginx:1.18"))
        self.assertTrue(validate_image_name("gcr.io/project/image:latest"))

    def test_valid_image_with_digest(self) -> None:
        """Test valid image with digest."""
        self.assertTrue(validate_image_name("nginx@sha256:abc123"))

    def test_invalid_empty(self) -> None:
        """Test empty image name is invalid."""
        self.assertFalse(validate_image_name(""))
        self.assertFalse(validate_image_name(None))

    def test_invalid_shell_metacharacters(self) -> None:
        """Test that shell metacharacters are rejected."""
        self.assertFalse(validate_image_name("nginx; rm -rf /"))
        self.assertFalse(validate_image_name("nginx && cat /etc/passwd"))
        self.assertFalse(validate_image_name("nginx | grep"))
        self.assertFalse(validate_image_name("$(whoami)"))
        self.assertFalse(validate_image_name("`whoami`"))
        self.assertFalse(validate_image_name("nginx\nmalicious"))

    def test_invalid_too_long(self) -> None:
        """Test that overly long names are rejected."""
        self.assertFalse(validate_image_name("a" * 300))

    def test_invalid_special_chars(self) -> None:
        """Test that special characters are rejected."""
        self.assertFalse(validate_image_name("nginx<script>"))
        self.assertFalse(validate_image_name("nginx>output"))
        self.assertFalse(validate_image_name("nginx{test}"))


class TestScanImageValidation(unittest.TestCase):
    """Tests for image validation in scan_image_with_grype."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.scanner = DockerImageScanner(grype_binary_path="/usr/local/bin/grype")

    def test_invalid_image_rejected(self) -> None:
        """Test that invalid image names are rejected before subprocess."""
        result = self.scanner.scan_image_with_grype("nginx; rm -rf /")
        self.assertTrue(result.is_empty())

    def test_command_injection_blocked(self) -> None:
        """Test that command injection attempts are blocked."""
        result = self.scanner.scan_image_with_grype("$(cat /etc/passwd)")
        self.assertTrue(result.is_empty())


if __name__ == "__main__":
    unittest.main()
