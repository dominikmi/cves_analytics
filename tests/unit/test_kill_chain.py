"""Unit tests for the kill chain assessment module.

Covers KillChainCalculator classification methods, probability calculations,
threat level categorization, and the convenience wrapper function.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.core.attack.kill_chain import (
    KillChainCalculator,
    _apply_lr,
    _extract_cwes,
    _odds_to_prob,
    _parse_cvss_vector,
    calculate_application_kill_chain,
)
from src.core.models import KillChainResult, KillChainStage


class TestIsRemoteCodeExecution:
    """Test _is_remote_code_execution classification logic."""

    @pytest.fixture
    def calc(self) -> KillChainCalculator:
        return KillChainCalculator()

    def test_network_high_impact_vector(self, calc: KillChainCalculator) -> None:
        """CVSS vector with AV=N and any H impact yields True."""
        vuln = {"cvss_vector": "AV=N/C=H"}
        assert calc._is_remote_code_execution(vuln) is True

    def test_network_integrity_high(self, calc: KillChainCalculator) -> None:
        """AV=N with I=H also yields True."""
        vuln = {"cvss_vector": "AV=N/I=H"}
        assert calc._is_remote_code_execution(vuln) is True

    def test_rce_cwe(self, calc: KillChainCalculator) -> None:
        """CWE-94 (code injection) is classified as RCE."""
        vuln = {"cwe_ids": [94]}
        assert calc._is_remote_code_execution(vuln) is True

    def test_rce_cwe_string(self, calc: KillChainCalculator) -> None:
        """CWE string format 'CWE-79' is parsed correctly."""
        vuln = {"cwe_ids": ["CWE-79"]}
        assert calc._is_remote_code_execution(vuln) is True

    def test_negative_case(self, calc: KillChainCalculator) -> None:
        """Local attack with low impact is not RCE."""
        vuln = {
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
            "cwe_ids": [779],
        }
        assert calc._is_remote_code_execution(vuln) is False

    def test_cvss3_vector_field(self, calc: KillChainCalculator) -> None:
        """Also reads from cvss3_vector field."""
        vuln = {"cvss3_vector": "AV=N/A=H"}
        assert calc._is_remote_code_execution(vuln) is True


class TestIsPrivilegeEscalation:
    """Test _is_privilege_escalation classification logic."""

    @pytest.fixture
    def calc(self) -> KillChainCalculator:
        return KillChainCalculator()

    def test_low_priv_high_integrity(self, calc: KillChainCalculator) -> None:
        """PR=L with I=H yields True."""
        vuln = {"cvss_vector": "PR=L/I=H"}
        assert calc._is_privilege_escalation(vuln) is True

    def test_no_priv_high_integrity(self, calc: KillChainCalculator) -> None:
        """PR=N with I=H yields True."""
        vuln = {"cvss_vector": "PR=N/I=H"}
        assert calc._is_privilege_escalation(vuln) is True

    def test_privesc_cwe(self, calc: KillChainCalculator) -> None:
        """CWE-269 (relative path traversal) is privesc."""
        vuln = {"cwe_ids": [269]}
        assert calc._is_privilege_escalation(vuln) is True

    def test_negative_case(self, calc: KillChainCalculator) -> None:
        """High privilege requirement with low impact is not privesc."""
        vuln = {
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N",
            "cwe_ids": [779],
        }
        assert calc._is_privilege_escalation(vuln) is False


class TestIsContainerEscape:
    """Test _is_container_escape keyword matching."""

    @pytest.fixture
    def calc(self) -> KillChainCalculator:
        return KillChainCalculator()

    def test_container_escape_keyword(self, calc: KillChainCalculator) -> None:
        """Description containing 'container escape' yields True."""
        vuln = {"description": "This vulnerability allows a container escape."}
        assert calc._is_container_escape(vuln) is True

    def test_docker_socket_keyword(self, calc: KillChainCalculator) -> None:
        """Description containing 'docker socket' yields True."""
        vuln = {"description": "Access to the docker socket enables breakout."}
        assert calc._is_container_escape(vuln) is True

    def test_kernel_exploit_keyword(self, calc: KillChainCalculator) -> None:
        """Description containing 'kernel exploit' yields True."""
        vuln = {"description": "A kernel exploit can be leveraged."}
        assert calc._is_container_escape(vuln) is True

    def test_case_insensitive(self, calc: KillChainCalculator) -> None:
        """Matching is case-insensitive."""
        vuln = {"description": "CONTAINER ESCAPE via namespace escape."}
        assert calc._is_container_escape(vuln) is True

    def test_negative_case(self, calc: KillChainCalculator) -> None:
        """Normal description yields False."""
        vuln = {"description": "A regular buffer overflow vulnerability."}
        assert calc._is_container_escape(vuln) is False

    def test_missing_description(self, calc: KillChainCalculator) -> None:
        """Missing description field yields False."""
        vuln: dict[str, object] = {"cvss_score": 7.0}
        assert calc._is_container_escape(vuln) is False


class TestCalculateKillChainProbability:
    """Test the full kill chain probability calculation."""

    @pytest.fixture
    def calc(self) -> KillChainCalculator:
        return KillChainCalculator()

    @pytest.fixture
    def mock_application(self) -> dict[str, Any]:
        return {
            "name": "test-app",
            "components": [{"name": "web", "type": "container"}],
            "kill_chain_stages": {"initial_access": True},
        }

    @pytest.fixture
    def sample_vulns(self) -> list[dict[str, Any]]:
        return [
            {
                "cvss_vector": "AV=N/AC=L/PR=N/UI=N/S=U/C=H/I=H/A=H",
                "epss_score": 0.15,
                "cwe_ids": [94],
                "description": "Remote code execution vulnerability.",
            }
        ]

    @pytest.fixture
    def sample_controls(self) -> dict[str, bool]:
        return {"waf": False, "mfa": False, "ids_ips": False}

    def test_returns_kill_chain_result(
        self,
        calc: KillChainCalculator,
        mock_application: dict[str, Any],
        sample_vulns: list[dict[str, Any]],
        sample_controls: dict[str, bool],
    ) -> None:
        """calculate_kill_chain_probability returns a KillChainResult."""
        result = calc.calculate_kill_chain_probability(
            mock_application, sample_vulns, sample_controls, True
        )
        assert isinstance(result, KillChainResult)

    def test_all_probabilities_in_range(
        self,
        calc: KillChainCalculator,
        mock_application: dict[str, Any],
        sample_vulns: list[dict[str, Any]],
        sample_controls: dict[str, bool],
    ) -> None:
        """All stage probabilities are in [0, 1]."""
        result = calc.calculate_kill_chain_probability(
            mock_application, sample_vulns, sample_controls, True
        )
        assert 0.0 <= result.initial_access_probability <= 1.0
        assert 0.0 <= result.execution_probability <= 1.0
        assert 0.0 <= result.lateral_movement_probability <= 1.0
        assert 0.0 <= result.objective_probability <= 1.0
        assert 0.0 <= result.overall_probability <= 1.0

    def test_overall_is_product(
        self,
        calc: KillChainCalculator,
        mock_application: dict[str, Any],
        sample_vulns: list[dict[str, Any]],
        sample_controls: dict[str, bool],
    ) -> None:
        """Overall probability equals product of stage probabilities."""
        result = calc.calculate_kill_chain_probability(
            mock_application, sample_vulns, sample_controls, True
        )
        expected = (
            result.initial_access_probability
            * result.execution_probability
            * result.lateral_movement_probability
            * result.objective_probability
        )
        assert result.overall_probability == pytest.approx(expected)

    def test_rce_count_detected(
        self,
        calc: KillChainCalculator,
        mock_application: dict[str, Any],
        sample_vulns: list[dict[str, Any]],
        sample_controls: dict[str, bool],
    ) -> None:
        """RCE vulnerabilities are counted."""
        result = calc.calculate_kill_chain_probability(
            mock_application, sample_vulns, sample_controls, True
        )
        assert result.rce_vulnerabilities >= 1

    def test_controls_reduce_probability(
        self,
        calc: KillChainCalculator,
        mock_application: dict[str, Any],
        sample_vulns: list[dict[str, Any]],
    ) -> None:
        """Enabling controls reduces initial access probability."""
        no_controls: dict[str, bool] = {"waf": False, "mfa": False}
        with_controls: dict[str, bool] = {"waf": True, "mfa": True}
        result_none = calc.calculate_kill_chain_probability(
            mock_application, sample_vulns, no_controls, True
        )
        result_ctrl = calc.calculate_kill_chain_probability(
            mock_application, sample_vulns, with_controls, True
        )
        assert (
            result_ctrl.initial_access_probability
            < result_none.initial_access_probability
        )

    def test_critical_path_ordered(
        self,
        calc: KillChainCalculator,
        mock_application: dict[str, Any],
        sample_vulns: list[dict[str, Any]],
        sample_controls: dict[str, bool],
    ) -> None:
        """Critical path stages are ordered by descending probability."""
        result = calc.calculate_kill_chain_probability(
            mock_application, sample_vulns, sample_controls, True
        )
        stage_probs: dict[KillChainStage, float] = {
            KillChainStage.INITIAL_ACCESS: result.initial_access_probability,
            KillChainStage.EXECUTION: result.execution_probability,
            KillChainStage.LATERAL_MOVEMENT: result.lateral_movement_probability,
            KillChainStage.OBJECTIVE: result.objective_probability,
        }
        for i in range(len(result.critical_path) - 1):
            assert (
                stage_probs[result.critical_path[i]]
                >= stage_probs[result.critical_path[i + 1]]
            )


class TestCategorizeThreatLevel:
    """Test _categorize_threat_level threshold boundaries."""

    @pytest.fixture
    def calc(self) -> KillChainCalculator:
        return KillChainCalculator()

    def test_critical(self, calc: KillChainCalculator) -> None:
        assert calc._categorize_threat_level(0.4) == "critical"
        assert calc._categorize_threat_level(0.9) == "critical"

    def test_high(self, calc: KillChainCalculator) -> None:
        assert calc._categorize_threat_level(0.2) == "high"
        assert calc._categorize_threat_level(0.39) == "high"

    def test_medium(self, calc: KillChainCalculator) -> None:
        assert calc._categorize_threat_level(0.1) == "medium"
        assert calc._categorize_threat_level(0.19) == "medium"

    def test_low(self, calc: KillChainCalculator) -> None:
        assert calc._categorize_threat_level(0.05) == "low"
        assert calc._categorize_threat_level(0.0) == "low"


class TestCalculateApplicationKillChain:
    """Test the convenience wrapper function."""

    def test_returns_result(self) -> None:
        """Function returns KillChainResult."""
        app = {"name": "test", "components": [], "kill_chain_stages": {}}
        vulns = [{"epss_score": 0.1}]
        controls: dict[str, bool] = {}
        result = calculate_application_kill_chain(app, vulns, controls, True)
        assert isinstance(result, KillChainResult)

    def test_equivalent_to_calculator(self) -> None:
        """Convenience function matches KillChainCalculator directly."""
        from src.core.attack.kill_chain import KillChainCalculator

        app = {"name": "test", "components": [], "kill_chain_stages": {}}
        vulns = [{"epss_score": 0.2}]
        controls: dict[str, bool] = {"waf": True}
        result = calculate_application_kill_chain(app, vulns, controls, False)
        calc = KillChainCalculator()
        expected = calc.calculate_kill_chain_probability(app, vulns, controls, False)
        assert result.overall_probability == expected.overall_probability


class TestHelperFunctions:
    """Test internal helper functions exposed for testing."""

    def test_parse_cvss_vector(self) -> None:
        """Vector parsing extracts key=value pairs using = separator."""
        result = _parse_cvss_vector("AV=N/AC=L/PR=N")
        assert result == {"AV": "N", "AC": "L", "PR": "N"}

    def test_parse_cvss_vector_none(self) -> None:
        """None input returns empty dict."""
        assert _parse_cvss_vector(None) == {}

    def test_extract_cwes_int_list(self) -> None:
        """List of ints extracted directly."""
        assert _extract_cwes({"cwe_ids": [94, 79]}) == {94, 79}

    def test_extract_cwes_string(self) -> None:
        """Single string CWE parsed."""
        assert _extract_cwes({"cwe": "CWE-94"}) == {94}

    def test_extract_cwes_empty(self) -> None:
        """Missing CWE field returns empty set."""
        assert _extract_cwes({}) == set()

    def test_odds_to_prob_clamps(self) -> None:
        """Zero/near-zero odds clamped to 0, very large odds clamped to 1."""
        assert _odds_to_prob(-0.5) == 0.0
        assert _odds_to_prob(1e10) == pytest.approx(1.0)

    def test_apply_lr_zero_prob(self) -> None:
        """Zero probability stays zero."""
        assert _apply_lr(0.0, 2.0) == 0.0

    def test_apply_lr_one_prob(self) -> None:
        """Probability 1.0 stays 1.0."""
        assert _apply_lr(1.0, 0.5) == 1.0

    def test_apply_lr_reduces(self) -> None:
        """LR < 1 reduces probability."""
        result = _apply_lr(0.5, 0.5)
        assert result < 0.5

    def test_apply_lr_increases(self) -> None:
        """LR > 1 increases probability."""
        result = _apply_lr(0.5, 2.0)
        assert result > 0.5
