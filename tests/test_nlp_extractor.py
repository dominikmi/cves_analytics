"""Tests for NLP-based vulnerability feature extraction."""

import unittest

import pandas as pd

from src.core.nlp_extractor import (
    AttackType,
    NLPFeatureLR,
    NLPVulnFeatures,
    VulnDescriptionExtractor,
    enrich_with_nlp_features,
    extract_nlp_features,
)


class TestVulnDescriptionExtractor(unittest.TestCase):
    """Test cases for VulnDescriptionExtractor."""

    def setUp(self):
        """Set up test fixtures."""
        self.extractor = VulnDescriptionExtractor()

    def test_extract_rce(self):
        """Test extraction of remote code execution."""
        descriptions = [
            "A vulnerability allows remote code execution.",
            "An attacker can execute arbitrary code on the server.",
            "RCE vulnerability in the web application.",
        ]
        for desc in descriptions:
            features = self.extractor.extract(desc)
            self.assertIn(
                AttackType.REMOTE_CODE_EXECUTION,
                [at for at, _ in features.attack_types],
                f"Failed to detect RCE in: {desc}",
            )

    def test_extract_sql_injection(self):
        """Test extraction of SQL injection."""
        descriptions = [
            "SQL injection vulnerability in login form.",
            "SQLi allows attackers to bypass authentication.",
            "Blind SQL injection in search parameter.",
        ]
        for desc in descriptions:
            features = self.extractor.extract(desc)
            self.assertIn(
                AttackType.SQL_INJECTION,
                [at for at, _ in features.attack_types],
                f"Failed to detect SQLi in: {desc}",
            )

    def test_extract_xss(self):
        """Test extraction of cross-site scripting."""
        descriptions = [
            "Cross-site scripting vulnerability in comment field.",
            "Reflected XSS in the search parameter.",
            "Stored XSS allows script injection.",
        ]
        for desc in descriptions:
            features = self.extractor.extract(desc)
            self.assertIn(
                AttackType.XSS,
                [at for at, _ in features.attack_types],
                f"Failed to detect XSS in: {desc}",
            )

    def test_extract_buffer_overflow(self):
        """Test extraction of buffer overflow."""
        descriptions = [
            "Buffer overflow in image processing library.",
            "Stack-based buffer overflow allows code execution.",
            "Heap-based overflow in parser.",
            "Out-of-bounds write vulnerability.",
        ]
        for desc in descriptions:
            features = self.extractor.extract(desc)
            self.assertIn(
                AttackType.BUFFER_OVERFLOW,
                [at for at, _ in features.attack_types],
                f"Failed to detect buffer overflow in: {desc}",
            )

    def test_extract_auth_bypass(self):
        """Test extraction of authentication bypass."""
        descriptions = [
            "Authentication bypass allows unauthorized access.",
            "Improper authentication in API endpoint.",
            "Attacker can bypass authentication mechanism.",
        ]
        for desc in descriptions:
            features = self.extractor.extract(desc)
            self.assertIn(
                AttackType.AUTH_BYPASS,
                [at for at, _ in features.attack_types],
                f"Failed to detect auth bypass in: {desc}",
            )

    def test_extract_privilege_escalation(self):
        """Test extraction of privilege escalation."""
        descriptions = [
            "Local privilege escalation vulnerability.",
            "Attacker can elevate privileges to root.",
            "LPE allows gaining administrator access.",
        ]
        for desc in descriptions:
            features = self.extractor.extract(desc)
            self.assertIn(
                AttackType.PRIVILEGE_ESCALATION,
                [at for at, _ in features.attack_types],
                f"Failed to detect privilege escalation in: {desc}",
            )

    def test_extract_dos(self):
        """Test extraction of denial of service."""
        descriptions = [
            "Denial of service vulnerability.",
            "DoS attack via malformed packets.",
            "Causes the application to crash.",
            "Resource exhaustion vulnerability.",
        ]
        for desc in descriptions:
            features = self.extractor.extract(desc)
            self.assertIn(
                AttackType.DENIAL_OF_SERVICE,
                [at for at, _ in features.attack_types],
                f"Failed to detect DoS in: {desc}",
            )

    def test_extract_requires_auth(self):
        """Test extraction of authentication requirement."""
        desc = "An authenticated user can exploit this vulnerability."
        features = self.extractor.extract(desc)
        self.assertTrue(features.requires_auth)

    def test_extract_no_auth_required(self):
        """Test extraction of no authentication requirement."""
        desc = "An unauthenticated remote attacker can exploit this."
        features = self.extractor.extract(desc)
        self.assertFalse(features.requires_auth)

    def test_extract_user_interaction(self):
        """Test extraction of user interaction requirement."""
        desc = "Exploitation requires the victim to click a malicious link."
        features = self.extractor.extract(desc)
        self.assertTrue(features.requires_user_interaction)

    def test_extract_network_accessible(self):
        """Test extraction of network accessibility."""
        desc = "A remote attacker can exploit this vulnerability over the network."
        features = self.extractor.extract(desc)
        self.assertTrue(features.is_network_accessible)

    def test_extract_local_access(self):
        """Test extraction of local access requirement."""
        desc = "Local attacker with physical access can exploit this."
        features = self.extractor.extract(desc)
        self.assertFalse(features.is_network_accessible)

    def test_extract_default_config(self):
        """Test extraction of default configuration impact."""
        desc = "Affects systems with default configuration."
        features = self.extractor.extract(desc)
        self.assertTrue(features.affects_default_config)

    def test_extract_multiple_attack_types(self):
        """Test extraction of multiple attack types."""
        desc = (
            "SQL injection vulnerability that can lead to remote code execution "
            "and information disclosure."
        )
        features = self.extractor.extract(desc)
        attack_types = [at for at, _ in features.attack_types]
        self.assertIn(AttackType.SQL_INJECTION, attack_types)
        self.assertIn(AttackType.REMOTE_CODE_EXECUTION, attack_types)
        self.assertIn(AttackType.INFORMATION_DISCLOSURE, attack_types)

    def test_extract_empty_description(self):
        """Test extraction from empty description."""
        features = self.extractor.extract("")
        self.assertEqual(features.confidence, 0.0)
        self.assertEqual(len(features.attack_types), 0)

    def test_extract_none_description(self):
        """Test extraction from None description."""
        features = self.extractor.extract(None)
        self.assertEqual(features.confidence, 0.0)

    def test_extract_short_description(self):
        """Test extraction from very short description."""
        features = self.extractor.extract("Bug.")
        self.assertEqual(features.confidence, 0.0)

    def test_confidence_calculation(self):
        """Test that confidence is calculated reasonably."""
        # Detailed description should have higher confidence
        detailed = (
            "A remote code execution vulnerability exists in the web server "
            "that allows an unauthenticated attacker to execute arbitrary code "
            "via a specially crafted HTTP request. This affects the default "
            "configuration and requires no user interaction."
        )
        features = self.extractor.extract(detailed)
        self.assertGreater(features.confidence, 0.5)

        # Vague description should have lower confidence
        vague = "Vulnerability in software."
        features_vague = self.extractor.extract(vague)
        self.assertLess(features_vague.confidence, features.confidence)

    def test_to_dict(self):
        """Test conversion to dictionary."""
        features = NLPVulnFeatures(
            attack_types=[(AttackType.SQL_INJECTION, 0.8)],
            requires_auth=True,
            requires_user_interaction=False,
            is_network_accessible=True,
            affects_default_config=False,
            impacts={"confidentiality": True, "integrity": True, "availability": False},
            confidence=0.7,
        )
        result = features.to_dict()
        self.assertEqual(result["nlp_primary_attack"], "sql_injection")
        self.assertEqual(result["nlp_requires_auth"], True)
        self.assertEqual(result["nlp_confidence"], 0.7)


class TestExtractNLPFeatures(unittest.TestCase):
    """Test cases for extract_nlp_features convenience function."""

    def test_extract_nlp_features(self):
        """Test the convenience function."""
        desc = "SQL injection vulnerability allows remote code execution."
        features = extract_nlp_features(desc)
        self.assertIsInstance(features, NLPVulnFeatures)
        self.assertGreater(len(features.attack_types), 0)


class TestEnrichWithNLPFeatures(unittest.TestCase):
    """Test cases for DataFrame enrichment."""

    def test_enrich_dataframe(self):
        """Test enriching a DataFrame with NLP features."""
        df = pd.DataFrame(
            {
                "cve_id": ["CVE-2023-0001", "CVE-2023-0002"],
                "description": [
                    "SQL injection vulnerability in login form.",
                    "Buffer overflow allows remote code execution.",
                ],
            }
        )
        result = enrich_with_nlp_features(df, "description")

        self.assertIn("nlp_primary_attack", result.columns)
        self.assertIn("nlp_confidence", result.columns)
        self.assertIn("nlp_requires_auth", result.columns)

        # Check that attack types were detected
        self.assertEqual(result.iloc[0]["nlp_primary_attack"], "sql_injection")
        self.assertIn(
            result.iloc[1]["nlp_primary_attack"],
            ["buffer_overflow", "remote_code_execution"],
        )

    def test_enrich_empty_dataframe(self):
        """Test enriching an empty DataFrame."""
        df = pd.DataFrame(columns=["cve_id", "description"])
        result = enrich_with_nlp_features(df, "description")
        self.assertTrue(result.empty)

    def test_enrich_missing_column(self):
        """Test enriching DataFrame without description column."""
        df = pd.DataFrame({"cve_id": ["CVE-2023-0001"]})
        result = enrich_with_nlp_features(df, "description")
        # Should return original DataFrame unchanged
        self.assertNotIn("nlp_primary_attack", result.columns)


class TestNLPFeatureLR(unittest.TestCase):
    """Test cases for NLP feature likelihood ratios."""

    def test_attack_type_lr_rce(self):
        """Test LR for RCE is greater than 1."""
        lr = NLPFeatureLR.get_attack_type_lr(AttackType.REMOTE_CODE_EXECUTION)
        self.assertGreater(lr, 1.0)

    def test_attack_type_lr_dos(self):
        """Test LR for DoS is less than or equal to 1."""
        lr = NLPFeatureLR.get_attack_type_lr(AttackType.DENIAL_OF_SERVICE)
        self.assertLessEqual(lr, 1.0)

    def test_attack_type_lr_none(self):
        """Test LR for None attack type is 1.0."""
        lr = NLPFeatureLR.get_attack_type_lr(None)
        self.assertEqual(lr, 1.0)

    def test_context_lrs(self):
        """Test context likelihood ratios are reasonable."""
        self.assertGreater(NLPFeatureLR.NO_AUTH_REQUIRED, 1.0)
        self.assertLess(NLPFeatureLR.AUTH_REQUIRED, 1.0)
        self.assertGreater(NLPFeatureLR.NO_USER_INTERACTION, 1.0)
        self.assertLess(NLPFeatureLR.USER_INTERACTION_REQUIRED, 1.0)


class TestRealWorldDescriptions(unittest.TestCase):
    """Test with real-world CVE descriptions."""

    def setUp(self):
        """Set up test fixtures."""
        self.extractor = VulnDescriptionExtractor()

    def test_log4j_style(self):
        """Test Log4j-style RCE description."""
        desc = (
            "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in "
            "configuration, log messages, and parameters do not protect against "
            "attacker controlled LDAP and other JNDI related endpoints. An attacker "
            "who can control log messages or log message parameters can execute "
            "arbitrary code loaded from LDAP servers."
        )
        features = self.extractor.extract(desc)
        attack_types = [at for at, _ in features.attack_types]
        self.assertIn(AttackType.REMOTE_CODE_EXECUTION, attack_types)

    def test_heartbleed_style(self):
        """Test Heartbleed-style information disclosure."""
        desc = (
            "The TLS and DTLS implementations in OpenSSL do not properly handle "
            "Heartbeat Extension packets, which allows remote attackers to obtain "
            "sensitive information from process memory via crafted packets."
        )
        features = self.extractor.extract(desc)
        attack_types = [at for at, _ in features.attack_types]
        self.assertIn(AttackType.INFORMATION_DISCLOSURE, attack_types)
        self.assertTrue(features.is_network_accessible)

    def test_shellshock_style(self):
        """Test Shellshock-style command injection."""
        desc = (
            "GNU Bash through 4.3 processes trailing strings after function "
            "definitions in the values of environment variables, which allows "
            "remote attackers to execute arbitrary code via a crafted environment."
        )
        features = self.extractor.extract(desc)
        attack_types = [at for at, _ in features.attack_types]
        # Should detect either RCE or command injection
        self.assertTrue(
            AttackType.REMOTE_CODE_EXECUTION in attack_types
            or AttackType.COMMAND_INJECTION in attack_types
        )


if __name__ == "__main__":
    unittest.main()
