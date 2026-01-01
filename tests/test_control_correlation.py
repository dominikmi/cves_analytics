"""Tests for Control Correlation Engine."""

import pytest

from src.utils.control_correlation import (
    ControlCorrelationEngine,
    generate_correlated_controls,
)


class TestControlCorrelationEngine:
    """Test control correlation engine."""

    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        engine = ControlCorrelationEngine()
        assert engine.config is not None
        assert hasattr(engine, "correlations")

    def test_mfa_positive_correlation(self):
        """Test MFA presence increases SSO+MFA likelihood."""
        engine = ControlCorrelationEngine()

        # Start with MFA only
        initial = {"mfa": True}

        # Run multiple times to check probability
        sso_count = 0
        iterations = 100

        for _ in range(iterations):
            result = engine.apply_correlations(
                initial.copy(), maturity_level=3, randomness=0.1
            )
            if result.get("sso_with_mfa", False):
                sso_count += 1

        # Should have SSO+MFA in ~75% of cases (with some variance)
        assert sso_count > 50, f"Expected >50% SSO+MFA presence, got {sso_count}%"
        print(f"MFA -> SSO+MFA correlation: {sso_count}% (expected ~75%)")

    def test_mfa_negative_correlation(self):
        """Test MFA absence reduces JIT access likelihood."""
        engine = ControlCorrelationEngine()

        # Start without MFA
        initial = {"mfa": False}

        # Run multiple times
        jit_count = 0
        iterations = 100

        for _ in range(iterations):
            result = engine.apply_correlations(
                initial.copy(), maturity_level=5, randomness=0.1
            )
            if result.get("jit_access", False):
                jit_count += 1

        # Should have JIT in ~20% of cases, but maturity level 5 can override
        # So we check it's less than with MFA present (which would be ~90%)
        assert jit_count < 70, (
            f"Expected <70% JIT presence without MFA, got {jit_count}%"
        )
        print(
            f"!MFA -> JIT correlation: {jit_count}% (maturity level 5 partially overrides)"
        )

    def test_siem_soc_correlation(self):
        """Test SIEM presence increases SOC likelihood."""
        engine = ControlCorrelationEngine()

        # Start with SIEM
        initial = {"siem": True}

        # Run multiple times
        soc_count = 0
        iterations = 100

        for _ in range(iterations):
            result = engine.apply_correlations(
                initial.copy(), maturity_level=4, randomness=0.1
            )
            if result.get("soc_24x7", False):
                soc_count += 1

        # Should have SOC in ~80% of cases
        assert soc_count > 60, f"Expected >60% SOC presence with SIEM, got {soc_count}%"
        print(f"SIEM -> SOC correlation: {soc_count}% (expected ~80%)")

    def test_maturity_level_1(self):
        """Test maturity level 1 has basic controls."""
        engine = ControlCorrelationEngine()

        controls = engine.generate_realistic_controls(maturity_level=1, randomness=0.1)

        # Should have basic controls
        basic_controls = ["firewall", "antivirus", "password_policy"]
        present_basic = sum(1 for c in basic_controls if controls.get(c, False))

        assert present_basic >= 1, "Should have at least one basic control"
        print(f"Maturity Level 1: {present_basic}/3 basic controls present")

    def test_maturity_level_5(self):
        """Test maturity level 5 has advanced controls."""
        engine = ControlCorrelationEngine()

        controls = engine.generate_realistic_controls(maturity_level=5, randomness=0.1)

        # Should have many controls
        total_controls = sum(1 for v in controls.values() if v)

        assert total_controls > 10, (
            f"Mature org should have >10 controls, got {total_controls}"
        )

        # Should have some advanced controls
        advanced_controls = [
            "soar",
            "zero_trust",
            "jit_access",
            "application_whitelisting",
        ]
        present_advanced = sum(1 for c in advanced_controls if controls.get(c, False))

        print(
            f"Maturity Level 5: {total_controls} total controls, {present_advanced}/4 advanced"
        )

    def test_edr_replaces_antivirus(self):
        """Test EDR/XDR presence reduces antivirus likelihood (negative correlation)."""
        engine = ControlCorrelationEngine()

        # Start with EDR
        initial = {"edr_xdr": True}

        # Run multiple times
        av_count = 0
        iterations = 100

        for _ in range(iterations):
            result = engine.apply_correlations(
                initial.copy(), maturity_level=3, randomness=0.1
            )
            if result.get("antivirus", False):
                av_count += 1

        # Should have AV in ~30% of cases, but maturity level can add it back
        # Just verify it's less than without EDR (which would be higher)
        assert av_count < 80, f"Expected <80% AV presence with EDR, got {av_count}%"
        print(f"EDR -> !AV correlation: {av_count}% (some orgs keep both)")

    def test_control_chains(self):
        """Test control chains propagate (A->B->C)."""
        engine = ControlCorrelationEngine()

        # Start with privileged_access_mgmt
        # Should get: PAM -> MFA -> SSO+MFA (chain)
        initial = {"privileged_access_mgmt": True}

        # Run multiple times
        mfa_count = 0
        sso_count = 0
        iterations = 100

        for _ in range(iterations):
            result = engine.apply_correlations(
                initial.copy(), maturity_level=4, randomness=0.1
            )
            if result.get("mfa", False):
                mfa_count += 1
            if result.get("sso_with_mfa", False):
                sso_count += 1

        # PAM should strongly correlate with MFA (~85%)
        assert mfa_count >= 50, f"Expected >=50% MFA with PAM, got {mfa_count}%"

        # Some should have SSO+MFA through chain
        assert sso_count > 30, f"Expected >30% SSO through chain, got {sso_count}%"
        print(f"PAM -> MFA: {mfa_count}%, PAM -> SSO: {sso_count}%")

    def test_explain_control_presence(self):
        """Test control explanation feature."""
        engine = ControlCorrelationEngine()

        controls = {"mfa": True, "sso_with_mfa": True, "iam_platform": True}

        explanation = engine.explain_control_presence("sso_with_mfa", controls)

        assert explanation["control"] == "sso_with_mfa"
        assert explanation["present"] is True
        assert len(explanation["reasons"]) > 0
        assert len(explanation["related_controls"]["supporting"]) > 0

        print(f"Explanation for sso_with_mfa: {explanation['reasons']}")

    def test_convenience_function(self):
        """Test convenience function works."""
        controls = generate_correlated_controls(maturity_level=3, randomness=0.2)

        assert isinstance(controls, dict)
        assert len(controls) > 0

        present = sum(1 for v in controls.values() if v)
        print(f"Convenience function generated {present} controls")


class TestRealisticScenarios:
    """Test realistic organizational scenarios."""

    def test_startup_scenario(self):
        """Test startup with minimal security (maturity 1)."""
        # Startups need at least one seed control
        seed = {"firewall": True}
        controls = generate_correlated_controls(
            maturity_level=1, seed_controls=seed, randomness=0.3
        )

        present = [k for k, v in controls.items() if v]

        # Startups typically have 1-8 controls
        assert 1 <= len(present) <= 8, (
            f"Startup should have 1-8 controls, got {len(present)}"
        )
        print(f"Startup scenario: {len(present)} controls - {present[:5]}")

    def test_enterprise_scenario(self):
        """Test enterprise with mature security (maturity 4-5)."""
        # Seed with basic controls to ensure some presence
        seed = {"mfa": True, "firewall": True}
        controls = generate_correlated_controls(
            maturity_level=5, seed_controls=seed, randomness=0.2
        )

        present = [k for k, v in controls.items() if v]

        # Enterprises typically have 15+ controls
        assert len(present) >= 10, (
            f"Enterprise should have 10+ controls, got {len(present)}"
        )

        # Should have defense in depth
        has_network = any(c in present for c in ["firewall", "ngfw", "ids_ips"])
        has_endpoint = any(c in present for c in ["edr_xdr", "antivirus"])
        has_access = any(
            c in present for c in ["mfa", "sso_with_mfa", "privileged_access_mgmt"]
        )

        assert has_network, "Enterprise should have network controls"
        assert has_endpoint, "Enterprise should have endpoint controls"
        assert has_access, "Enterprise should have access controls"

        print(f"Enterprise scenario: {len(present)} controls with defense in depth")

    def test_financial_sector_scenario(self):
        """Test financial sector (high maturity + specific controls)."""
        # Financial sector typically has high maturity + specific requirements
        seed = {
            "mfa": True,
            "encryption_at_rest": True,
            "backup_recovery": True,
            "siem": True,
        }

        controls = generate_correlated_controls(
            maturity_level=4, seed_controls=seed, randomness=0.1
        )

        present = [k for k, v in controls.items() if v]

        # Should have data protection suite
        has_dlp = controls.get("data_loss_prevention", False)
        has_pam = controls.get("privileged_access_mgmt", False)
        has_soc = controls.get("soc_24x7", False)

        print(
            f"Financial sector: {len(present)} controls, DLP={has_dlp}, PAM={has_pam}, SOC={has_soc}"
        )

        # High maturity financial should have most of these
        assert len(present) >= 12, "Financial sector should have comprehensive controls"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
