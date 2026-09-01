"""Additional coverage tests for uncovered branches."""

from src.core.attack.kill_chain import KillChainCalculator
from src.core.models import ThreatIndicatorsInput
from src.core.risk.bayesian_assessor import BayesianRiskAssessor


class TestKillChainCoverage:
    """Cover remaining branches in kill chain calculator."""

    def test_execution_with_edr_xdr(self) -> None:
        calc = KillChainCalculator()
        prob = calc._calculate_execution([], {"edr_xdr": True}, True)
        assert prob < 0.8

    def test_execution_with_waf(self) -> None:
        calc = KillChainCalculator()
        prob = calc._calculate_execution([], {"waf": True}, True)
        assert prob < 0.8

    def test_lateral_with_network_segmentation(self) -> None:
        calc = KillChainCalculator()
        prob = calc._calculate_lateral_movement(
            [], {"network_segmentation": True}, True
        )
        assert prob < 0.7

    def test_lateral_with_flat_network(self) -> None:
        calc = KillChainCalculator()
        prob = calc._calculate_lateral_movement([], {"flat_network": True}, True)
        assert prob < 0.7

    def test_lateral_with_edr_xdr(self) -> None:
        calc = KillChainCalculator()
        prob = calc._calculate_lateral_movement([], {"edr_xdr": True}, True)
        assert prob < 0.7

    def test_lateral_with_siem(self) -> None:
        calc = KillChainCalculator()
        prob = calc._calculate_lateral_movement([], {"siem": True}, True)
        assert prob < 0.7

    def test_objective_with_controls(self) -> None:
        calc = KillChainCalculator()
        prob = calc._calculate_objective(
            [], {"dlp": True, "encryption": True, "backup": True, "siem": True}
        )
        assert prob < 0.9


class TestBayesianAssessorCoverage:
    """Cover remaining branches in bayesian assessor."""

    def test_cvss_vector_lr_with_valid_vector(self) -> None:
        assessor = BayesianRiskAssessor()
        lr = assessor._apply_cvss_vector_lrs("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert lr > 0

    def test_parse_cvss_vector_valid(self) -> None:
        assessor = BayesianRiskAssessor()
        result = assessor._parse_cvss_vector("AV:N/AC:L/PR:N")
        assert "AV" in result
        assert result["AV"] == "N"

    def test_parse_cvss_vector_skips_prefix(self) -> None:
        assessor = BayesianRiskAssessor()
        result = assessor._parse_cvss_vector("CVSS:3.1/AV:N")
        assert "AV" in result
        assert "CVSS" not in result

    def test_nlp_features_with_values(self) -> None:
        assessor = BayesianRiskAssessor()
        lr = assessor._apply_nlp_features({"feature1": 0.8, "feature2": 0.6})
        assert 0.5 < lr < 2.0

    def test_nlp_features_empty_dict(self) -> None:
        assessor = BayesianRiskAssessor()
        lr = assessor._apply_nlp_features({})
        assert lr == 1.0

    def test_nlp_features_none(self) -> None:
        assessor = BayesianRiskAssessor()
        lr = assessor._apply_nlp_features(None)
        assert lr == 1.0

    def test_criticality_lr_high(self) -> None:
        assessor = BayesianRiskAssessor()
        lr = assessor._get_criticality_lr(1.0)
        assert lr > 1.0

    def test_criticality_lr_low(self) -> None:
        assessor = BayesianRiskAssessor()
        lr = assessor._get_criticality_lr(0.0)
        assert abs(lr - 1.0) < 0.01

    def test_threat_lrs_all_active(self) -> None:
        assessor = BayesianRiskAssessor()
        threats = ThreatIndicatorsInput(
            active_exploitation=True,
            exploit_available=True,
            threat_intel_confidence=0.9,
        )
        lr = assessor._apply_threat_lrs(threats)
        assert lr > 1.0

    def test_normalize_threats_empty(self) -> None:
        assessor = BayesianRiskAssessor()
        threats = ThreatIndicatorsInput()
        result = assessor._normalize_threats(threats)
        assert result == {}
