"""Tests for configuration management module."""

import os
import unittest

from src.utils.config import AppConfig, get_config


class TestAppConfig(unittest.TestCase):
    """Test cases for AppConfig class."""

    def test_app_config_initialization(self):
        """Test AppConfig initialization."""
        config = AppConfig()
        self.assertEqual(config.grype_binary_path, "/opt/homebrew/bin/grype")
        self.assertEqual(config.data_path, "./data")
        self.assertEqual(config.output_path, "./output")
        self.assertEqual(config.log_level, "INFO")
        self.assertEqual(config.max_cve_files, 5000)
        self.assertEqual(config.max_concurrent_scans, 5)

    def test_app_config_from_env(self):
        """Test AppConfig loading from environment variables."""
        # Set environment variables
        os.environ["GRYPE_BINARY_PATH"] = "/custom/path/grype"
        os.environ["DATA_PATH"] = "/custom/data"
        os.environ["LOG_LEVEL"] = "DEBUG"

        try:
            config = AppConfig()
            self.assertEqual(config.grype_binary_path, "/custom/path/grype")
            self.assertEqual(config.data_path, "/custom/data")
            self.assertEqual(config.log_level, "DEBUG")
        finally:
            # Clean up environment variables
            del os.environ["GRYPE_BINARY_PATH"]
            del os.environ["DATA_PATH"]
            del os.environ["LOG_LEVEL"]

    def test_get_config_singleton(self):
        """Test that get_config returns singleton instance."""
        config1 = get_config()
        config2 = get_config()
        self.assertIs(config1, config2)

    def test_app_config_with_custom_values(self):
        """Test AppConfig with custom values."""
        config = AppConfig(
            grype_binary_path="/custom/grype",
            data_path="/custom/data",
            max_cve_files=1000,
            max_concurrent_scans=10,
        )
        self.assertEqual(config.grype_binary_path, "/custom/grype")
        self.assertEqual(config.data_path, "/custom/data")
        self.assertEqual(config.max_cve_files, 1000)
        self.assertEqual(config.max_concurrent_scans, 10)
