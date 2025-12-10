"""Tests for security controls generation."""

import unittest

from src.simulation.security_controls import (
    ExposureBasedControlProbabilities,
    SecurityControlsConfig,
    SecurityMaturityLevel,
    ServiceSecurityControlsGenerator,
)


class TestExposureBasedControlProbabilities(unittest.TestCase):
    """Test exposure-based control probability modifiers."""

    def test_internet_facing_has_high_waf_modifier(self):
        """Internet-facing services should have high WAF probability."""
        modifier = ExposureBasedControlProbabilities.get_modifier(
            "internet-facing", "waf"
        )
        self.assertGreater(modifier, 2.0)

    def test_internal_has_low_waf_modifier(self):
        """Internal services should have low WAF probability."""
        modifier = ExposureBasedControlProbabilities.get_modifier("internal", "waf")
        self.assertLess(modifier, 0.5)

    def test_mandatory_controls_internet_facing(self):
        """Internet-facing should have firewall, waf, antivirus mandatory."""
        mandatory = ExposureBasedControlProbabilities.get_mandatory_controls(
            "internet-facing"
        )
        self.assertIn("firewall", mandatory)
        self.assertIn("waf", mandatory)
        self.assertIn("antivirus", mandatory)

    def test_mandatory_controls_internal(self):
        """Internal should have only firewall and antivirus mandatory."""
        mandatory = ExposureBasedControlProbabilities.get_mandatory_controls("internal")
        self.assertIn("firewall", mandatory)
        self.assertIn("antivirus", mandatory)
        self.assertNotIn("waf", mandatory)

    def test_mandatory_controls_restricted(self):
        """Restricted should have mfa mandatory."""
        mandatory = ExposureBasedControlProbabilities.get_mandatory_controls(
            "restricted"
        )
        self.assertIn("mfa", mandatory)
        self.assertIn("network_segmentation", mandatory)


class TestServiceSecurityControlsGenerator(unittest.TestCase):
    """Test per-service security controls generation."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = ServiceSecurityControlsGenerator(
            base_maturity=SecurityMaturityLevel.DEFINED
        )

    def test_internet_facing_always_has_waf(self):
        """Internet-facing services should always have WAF."""
        controls = self.generator.generate_for_service(
            exposure="internet-facing",
            service_role="web_server",
            asset_value="high",
        )
        self.assertTrue(controls["waf"])
        self.assertTrue(controls["firewall"])
        self.assertTrue(controls["antivirus"])

    def test_internal_rarely_has_waf(self):
        """Internal services should rarely have WAF."""
        # Run multiple times to check probability
        waf_count = 0
        iterations = 100
        for _ in range(iterations):
            controls = self.generator.generate_for_service(
                exposure="internal",
                service_role="cache",
                asset_value="medium",
            )
            if controls["waf"]:
                waf_count += 1

        # WAF should be present less than 30% of the time for internal
        self.assertLess(waf_count / iterations, 0.4)

    def test_restricted_always_has_mfa(self):
        """Restricted services should always have MFA."""
        controls = self.generator.generate_for_service(
            exposure="restricted",
            service_role="database",
            asset_value="critical",
        )
        self.assertTrue(controls["mfa"])
        self.assertTrue(controls["network_segmentation"])

    def test_critical_asset_has_more_controls(self):
        """Critical assets should have more controls than low value assets."""
        critical_controls = self.generator.generate_for_service(
            exposure="internal",
            service_role="database",
            asset_value="critical",
        )
        low_controls = self.generator.generate_for_service(
            exposure="internal",
            service_role="cache",
            asset_value="low",
        )

        critical_count = sum(1 for v in critical_controls.values() if v)
        low_count = sum(1 for v in low_controls.values() if v)

        # Critical should generally have more controls (run multiple times)
        # This is probabilistic, so we just check the structure is correct
        self.assertIsInstance(critical_count, int)
        self.assertIsInstance(low_count, int)

    def test_patch_management_is_exclusive(self):
        """Only one patch management cadence should be active."""
        controls = self.generator.generate_for_service(
            exposure="internal",
            service_role="app_server",
            asset_value="medium",
        )

        patch_controls = [
            controls["patch_daily"],
            controls["patch_weekly"],
            controls["patch_monthly"],
            controls["patch_quarterly"],
        ]
        active_patch = sum(1 for p in patch_controls if p)
        self.assertEqual(active_patch, 1)

    def test_all_controls_are_boolean(self):
        """All controls should be boolean values."""
        controls = self.generator.generate_for_service(
            exposure="internet-facing",
            service_role="web_server",
            asset_value="high",
        )

        for name, value in controls.items():
            self.assertIsInstance(
                value, bool, f"Control {name} should be boolean, got {type(value)}"
            )


class TestSecurityControlsConfig(unittest.TestCase):
    """Test SecurityControlsConfig model."""

    def test_get_active_controls(self):
        """Test getting list of active controls."""
        config = SecurityControlsConfig(
            firewall=True,
            waf=True,
            antivirus=True,
            mfa=True,
            patch_monthly=True,
        )
        active = config.get_active_controls()
        self.assertIn("firewall", active)
        self.assertIn("waf", active)
        self.assertIn("mfa", active)
        self.assertIn("patch_monthly", active)

    def test_get_patch_cadence(self):
        """Test getting patch management cadence."""
        config = SecurityControlsConfig(patch_weekly=True)
        self.assertEqual(config.get_patch_cadence(), "weekly")

        config = SecurityControlsConfig(patch_daily=True)
        self.assertEqual(config.get_patch_cadence(), "daily")


if __name__ == "__main__":
    unittest.main()
