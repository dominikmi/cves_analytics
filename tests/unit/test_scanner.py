"""Tests for Docker scanner service."""

import pytest

from src.services.scanner import DockerScanner


class TestDockerScanner:
    """Test DockerScanner."""

    def test_unsupported_tool_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported scanner tool"):
            DockerScanner(tool="nonexistent_tool")

    def test_supported_tools_accepted(self) -> None:
        assert DockerScanner(tool="grype").tool == "grype"
        assert DockerScanner(tool="trivy").tool == "trivy"

    def test_scan_rejects_flag_injection(self) -> None:
        scanner = DockerScanner()
        df = scanner.scan("--config=/etc/passwd")
        assert df.is_empty()

    def test_scan_rejects_shell_metacharacters(self) -> None:
        scanner = DockerScanner()
        df = scanner.scan("nginx; rm -rf /")
        assert df.is_empty()

    def test_scan_rejects_empty_and_oversized(self) -> None:
        scanner = DockerScanner()
        assert scanner.scan("").is_empty()
        assert scanner.scan("a" * 1024).is_empty()

    def test_scan_accepts_valid_references(self) -> None:
        scanner = DockerScanner()
        assert scanner._validate_image("nginx:latest")
        assert scanner._validate_image("registry.example.com:5000/team/app:v1.2")
        assert scanner._validate_image("nginx@sha256:abc123")

    def test_scan_batch_empty(self) -> None:
        scanner = DockerScanner()
        df = scanner.scan_batch([])
        assert df.is_empty()

    def test_parse_grype_json(self) -> None:
        scanner = DockerScanner()
        raw = b'{"matches": [{"vulnerability": {"id": "CVE-2024-0001", "severity": "HIGH"}, "artifact": {"name": "libssl", "version": "1.0.0"}}]}'
        df = scanner._parse_output(raw)
        assert len(df) == 1
        assert df["cve_id"][0] == "CVE-2024-0001"

    def test_parse_invalid_json(self) -> None:
        scanner = DockerScanner()
        df = scanner._parse_output(b"not json")
        assert df.is_empty()
