"""Tests for scenario configuration module."""

import unittest

from src.simulation.scenario_config import DEFAULT_CONFIG, ScenarioConfig


class TestScenarioConfig(unittest.TestCase):
    """Test cases for ScenarioConfig class."""

    def test_scenario_config_initialization(self):
        """Test ScenarioConfig initialization."""
        config = ScenarioConfig()

        self.assertEqual(config.PROD_FLAT_NETWORK_PROB, 0.1)
        self.assertEqual(config.DEV_SEGMENTED_NETWORK_PROB, 0.2)
        self.assertEqual(config.PATCH_MONTHLY_THRESHOLD, 4)

    def test_scenario_config_default_lists(self):
        """Test ScenarioConfig default lists initialization."""
        config = ScenarioConfig()

        self.assertGreater(len(config.SECRET_TYPES), 0)
        self.assertGreater(len(config.MISCONFIG_TYPES), 0)
        self.assertIn("api_key", config.SECRET_TYPES)
        self.assertIn("exposed_port", config.MISCONFIG_TYPES)

    def test_default_config_exists(self):
        """Test that DEFAULT_CONFIG is initialized."""
        self.assertIsNotNone(DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG, ScenarioConfig)

    def test_scenario_config_custom_values(self):
        """Test ScenarioConfig with custom values."""
        config = ScenarioConfig(
            PROD_FLAT_NETWORK_PROB=0.2,
            DEV_SEGMENTED_NETWORK_PROB=0.3,
        )

        self.assertEqual(config.PROD_FLAT_NETWORK_PROB, 0.2)
        self.assertEqual(config.DEV_SEGMENTED_NETWORK_PROB, 0.3)

    def test_scenario_config_threshold_values(self):
        """Test ScenarioConfig threshold values."""
        config = ScenarioConfig()

        self.assertEqual(config.PATCH_MONTHLY_THRESHOLD, 4)
        self.assertEqual(config.PATCH_WEEKLY_THRESHOLD, 7)
        self.assertEqual(config.MFA_THRESHOLD, 5)

    def test_scenario_config_probability_values(self):
        """Test ScenarioConfig probability values."""
        config = ScenarioConfig()

        self.assertGreaterEqual(config.PROD_FLAT_NETWORK_PROB, 0)
        self.assertLessEqual(config.PROD_FLAT_NETWORK_PROB, 1)
        self.assertGreaterEqual(config.DEV_SEGMENTED_NETWORK_PROB, 0)
        self.assertLessEqual(config.DEV_SEGMENTED_NETWORK_PROB, 1)
        self.assertGreaterEqual(config.APP_TIER_UNRESTRICTED_PROB, 0)
        self.assertLessEqual(config.APP_TIER_UNRESTRICTED_PROB, 1)
        self.assertGreaterEqual(config.DB_EXPOSED_PROB, 0)
        self.assertLessEqual(config.DB_EXPOSED_PROB, 1)

    def test_scenario_config_service_parameters(self):
        """Test ScenarioConfig service generation parameters."""
        config = ScenarioConfig()

        self.assertEqual(config.SERVICES_SMALL_SIZE, 3)
        self.assertEqual(config.SERVICES_MID_SIZE, 6)
        self.assertEqual(config.SERVICES_GLOBAL_MULTIPLIER, 1.5)

    def test_scenario_config_post_init(self):
        """Test ScenarioConfig __post_init__ method."""
        config = ScenarioConfig(SECRET_TYPES=[], MISCONFIG_TYPES=[])
        config.__post_init__()

        # Should populate with defaults
        self.assertGreater(len(config.SECRET_TYPES), 0)
        self.assertGreater(len(config.MISCONFIG_TYPES), 0)
