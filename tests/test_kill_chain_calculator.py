"""Unit tests for kill-chain calculator module."""

import polars as pl
import pytest

from src.core.kill_chain_calculator import (
    KillChainCalculator,
    KillChainResult,
    KillChainStage,
    calculate_application_kill_chain,
)
from src.simulation.application_templates import (
    ApplicationComponent,
    ApplicationTemplate,
    ApplicationType,
    ComponentRole,
)


@pytest.fixture
def sample_application():
    """Create a sample application for testing."""
    components = [
        ApplicationComponent(
            name="nginx-ingress",
            role=ComponentRole.INGRESS,
            service_category="proxy",
            exposure="internet-facing",
            asset_value="high",
            required=True,
        ),
        ApplicationComponent(
            name="api-backend",
            role=ComponentRole.BACKEND,
            service_category="app_server",
            exposure="internal",
            asset_value="high",
            required=True,
            depends_on=["nginx-ingress"],
        ),
        ApplicationComponent(
            name="database",
            role=ComponentRole.DATABASE,
            service_category="database",
            exposure="internal",
            asset_value="critical",
            required=True,
            depends_on=["api-backend"],
        ),
    ]

    return ApplicationTemplate(
        name="Test Application",
        type=ApplicationType.CONSULTING,
        description="Test application for unit tests",
        components=components,
        kill_chain_stages={
            "initial_access": ["ingress"],
            "execution": ["backend"],
            "lateral_movement": ["backend", "database"],
            "exfiltration": ["database"],
        },
        data_flow=[
            ("nginx-ingress", "api-backend"),
            ("api-backend", "database"),
        ],
    )


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerability data."""
    return pl.DataFrame(
        {
            "cve_id": ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"],
            "service_name": ["nginx-ingress", "api-backend", "database"],
            "service_role": ["ingress", "backend", "database"],
            "exposure": ["internet-facing", "internal", "internal"],
            "bayesian_risk_score": [0.083, 0.025, 0.015],
            "epss_score": [0.08, 0.02, 0.01],
            "cvss_score": [8.5, 6.0, 5.0],
        }
    )


@pytest.fixture
def security_controls():
    """Create sample security controls."""
    return {
        "waf": True,
        "ids_ips": True,
        "mfa": False,
        "network_segmentation": True,
        "edr_xdr": True,
        "siem": True,
    }


class TestKillChainStage:
    """Test KillChainStage model."""

    def test_create_stage(self):
        """Test creating a kill-chain stage."""
        stage = KillChainStage(
            name="Initial Access",
            components=["ingress", "frontend"],
            base_probability=0.08,
            conditional_probability=0.08,
            contributing_factors={"max_vuln_probability": 0.08},
        )

        assert stage.name == "Initial Access"
        assert len(stage.components) == 2
        assert stage.base_probability == 0.08
        assert stage.conditional_probability == 0.08
        assert "max_vuln_probability" in stage.contributing_factors


class TestKillChainResult:
    """Test KillChainResult model."""

    def test_create_result(self):
        """Test creating a kill-chain result."""
        stages = [
            KillChainStage(
                name="Initial Access",
                components=["ingress"],
                base_probability=0.08,
                conditional_probability=0.08,
                contributing_factors={},
            ),
        ]

        result = KillChainResult(
            application_name="Test App",
            total_probability=0.05,
            stages=stages,
            critical_path=["nginx", "backend", "database"],
            bottleneck_stage="Lateral Movement",
            threat_level="Medium",
        )

        assert result.application_name == "Test App"
        assert result.total_probability == 0.05
        assert len(result.stages) == 1
        assert result.threat_level == "Medium"


class TestKillChainCalculator:
    """Test KillChainCalculator class."""

    def test_calculator_initialization(self):
        """Test calculator initializes correctly."""
        calculator = KillChainCalculator()
        assert calculator is not None

    def test_calculate_initial_access_with_vulnerabilities(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test initial access calculation with vulnerabilities."""
        calculator = KillChainCalculator()

        stage = calculator._calculate_initial_access(
            sample_application,
            sample_vulnerabilities,
            security_controls,
        )

        assert stage.name == "Initial Access"
        assert stage.base_probability > 0
        assert stage.conditional_probability > 0
        assert "max_vuln_probability" in stage.contributing_factors

    def test_calculate_initial_access_no_vulnerabilities(
        self,
        sample_application,
        security_controls,
    ):
        """Test initial access with no vulnerabilities."""
        calculator = KillChainCalculator()
        empty_vulns = pl.DataFrame(
            {
                "cve_id": [],
                "service_role": [],
                "bayesian_risk_score": [],
            }
        )

        stage = calculator._calculate_initial_access(
            sample_application,
            empty_vulns,
            security_controls,
        )

        assert stage.base_probability == 0.01  # Minimal baseline

    def test_calculate_execution_good_docker(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test execution calculation with good Docker security.

        Good Docker practices (non-root, read-only FS, seccomp, AppArmor)
        provide 50% reduction for general vulnerabilities.
        """
        calculator = KillChainCalculator()

        stage = calculator._calculate_execution(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=True,
            prior_probability=0.08,
        )

        assert stage.name == "Execution"
        # Should have vulnerability-specific or general good practices factor
        assert any(
            key in stage.contributing_factors
            for key in [
                "docker_good_practices",
                "docker_good_rce_protection",
                "docker_good_privesc_protection",
                "docker_good_escape_protection",
            ]
        )
        # General good practices = 0.5 (50% reduction)
        if "docker_good_practices" in stage.contributing_factors:
            assert stage.contributing_factors["docker_good_practices"] == 0.5

    def test_calculate_execution_poor_docker(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test execution calculation with poor Docker security.

        With poor Docker practices (root user, writable FS), the reduction
        depends on vulnerability type. For general vulnerabilities, minimal
        reduction (0.9x = 10% reduction).
        """
        calculator = KillChainCalculator()

        stage = calculator._calculate_execution(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=False,
            prior_probability=0.08,
        )

        # Should have minimal reduction for non-RCE vulnerabilities
        assert (
            "docker_poor_practices" in stage.contributing_factors
            or "docker_poor_rce_no_protection" in stage.contributing_factors
        )
        # Minimal reduction (0.9) for general vulnerabilities
        if "docker_poor_practices" in stage.contributing_factors:
            assert stage.contributing_factors["docker_poor_practices"] == 0.9

    def test_calculate_execution_rce_poor_docker(
        self,
        sample_application,
        security_controls,
    ):
        """Test execution with RCE vulnerability and poor Docker practices.

        CRITICAL: RCE + root user = NO reduction (immediate root access).
        """
        calculator = KillChainCalculator()

        # Create RCE vulnerability
        rce_vuln = pl.DataFrame(
            {
                "cve_id": ["CVE-2023-RCE"],
                "service_name": ["api-backend"],
                "service_role": ["backend"],
                "cvss_vector": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
                "cwe_id": ["CWE-78"],  # OS Command Injection
                "bayesian_risk_score": [0.85],
            }
        )

        stage = calculator._calculate_execution(
            sample_application,
            rce_vuln,
            security_controls,
            docker_security_good=False,
            prior_probability=0.08,
        )

        # CRITICAL: RCE with poor Docker = NO reduction
        assert "docker_poor_rce_no_protection" in stage.contributing_factors
        assert stage.contributing_factors["docker_poor_rce_no_protection"] == 1.0

    def test_calculate_lateral_movement_with_segmentation(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test lateral movement with network segmentation."""
        calculator = KillChainCalculator()

        stage = calculator._calculate_lateral_movement(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=True,
            prior_probability=0.05,
        )

        assert stage.name == "Lateral Movement"
        assert "network_segmentation" in stage.contributing_factors
        assert stage.contributing_factors["network_segmentation"] == 0.3

    def test_calculate_lateral_movement_flat_network(
        self,
        sample_application,
        sample_vulnerabilities,
    ):
        """Test lateral movement without network segmentation."""
        calculator = KillChainCalculator()
        controls = {"network_segmentation": False}

        stage = calculator._calculate_lateral_movement(
            sample_application,
            sample_vulnerabilities,
            controls,
            docker_security_good=False,
            prior_probability=0.05,
        )

        assert "flat_network" in stage.contributing_factors
        assert stage.contributing_factors["flat_network"] == 0.9

    def test_calculate_objective(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test objective achievement calculation."""
        calculator = KillChainCalculator()

        stage = calculator._calculate_objective(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            prior_probability=0.01,
        )

        assert stage.name == "Objective Achievement"
        assert stage.base_probability > 0
        assert stage.conditional_probability > 0

    def test_categorize_threat_level(self):
        """Test threat level categorization."""
        calculator = KillChainCalculator()

        assert calculator._categorize_threat_level(0.50) == "Critical"
        assert calculator._categorize_threat_level(0.20) == "High"
        assert calculator._categorize_threat_level(0.08) == "Medium"
        assert calculator._categorize_threat_level(0.02) == "Low"
        assert calculator._categorize_threat_level(0.005) == "Negligible"

    def test_full_kill_chain_calculation(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test complete kill-chain probability calculation."""
        calculator = KillChainCalculator()

        result = calculator.calculate_kill_chain_probability(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=True,
        )

        assert isinstance(result, KillChainResult)
        assert result.application_name == "Test Application"
        assert 0 <= result.total_probability <= 1
        assert len(result.stages) == 4
        assert result.threat_level in [
            "Critical",
            "High",
            "Medium",
            "Low",
            "Negligible",
        ]
        assert result.bottleneck_stage is not None

    def test_probability_bounds(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test that probabilities stay within valid bounds."""
        calculator = KillChainCalculator()

        result = calculator.calculate_kill_chain_probability(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=True,
        )

        # Check all probabilities are between 0 and 1
        assert 0 <= result.total_probability <= 1

        for stage in result.stages:
            assert 0 <= stage.base_probability <= 1
            assert 0 <= stage.conditional_probability <= 1

    def test_sequential_probability_calculation(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test that total probability is product of conditional probabilities."""
        calculator = KillChainCalculator()

        result = calculator.calculate_kill_chain_probability(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=True,
        )

        # Calculate expected total
        expected_total = 1.0
        for stage in result.stages:
            if stage.name == "Initial Access":
                expected_total *= stage.base_probability
            else:
                expected_total *= stage.conditional_probability

        # Allow small floating point differences
        assert abs(result.total_probability - expected_total) < 0.0001

    def test_bottleneck_identification(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test that bottleneck stage is correctly identified."""
        calculator = KillChainCalculator()

        result = calculator.calculate_kill_chain_probability(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=True,
        )

        # Find stage with lowest conditional probability
        min_prob = min(s.conditional_probability for s in result.stages)
        bottleneck_stages = [
            s.name for s in result.stages if s.conditional_probability == min_prob
        ]

        assert result.bottleneck_stage in bottleneck_stages


class TestConvenienceFunction:
    """Test convenience function."""

    def test_calculate_application_kill_chain(
        self,
        sample_application,
        sample_vulnerabilities,
        security_controls,
    ):
        """Test convenience function works correctly."""
        result = calculate_application_kill_chain(
            sample_application,
            sample_vulnerabilities,
            security_controls,
            docker_security_good=True,
        )

        assert isinstance(result, KillChainResult)
        assert result.total_probability >= 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_security_controls(
        self,
        sample_application,
        sample_vulnerabilities,
    ):
        """Test with no security controls."""
        calculator = KillChainCalculator()

        result = calculator.calculate_kill_chain_probability(
            sample_application,
            sample_vulnerabilities,
            {},
            docker_security_good=False,
        )

        # Should still work, just higher probabilities
        assert result.total_probability > 0

    def test_high_vulnerability_scores(self, sample_application, security_controls):
        """Test with very high vulnerability scores."""
        high_vulns = pl.DataFrame(
            {
                "cve_id": ["CVE-2023-CRITICAL"],
                "service_name": ["nginx-ingress"],
                "service_role": ["ingress"],
                "exposure": ["internet-facing"],
                "bayesian_risk_score": [0.95],
                "epss_score": [0.95],
                "cvss_score": [10.0],
            }
        )

        calculator = KillChainCalculator()
        result = calculator.calculate_kill_chain_probability(
            sample_application,
            high_vulns,
            security_controls,
            docker_security_good=False,
        )

        # Should result in measurable probability (controls reduce it significantly)
        assert result.total_probability > 0.0001
        # Initial access should be high despite controls
        assert result.stages[0].base_probability > 0.05

    def test_all_controls_enabled(
        self,
        sample_application,
        sample_vulnerabilities,
    ):
        """Test with all security controls enabled."""
        all_controls = {
            "waf": True,
            "ids_ips": True,
            "mfa": True,
            "network_segmentation": True,
            "edr_xdr": True,
            "siem": True,
            "soc_24x7": True,
            "data_loss_prevention": True,
            "encryption_at_rest": True,
            "backup_recovery": True,
        }

        calculator = KillChainCalculator()
        result = calculator.calculate_kill_chain_probability(
            sample_application,
            sample_vulnerabilities,
            all_controls,
            docker_security_good=True,
        )

        # Should result in low total probability
        assert result.total_probability < 0.1
        assert result.threat_level in ["Low", "Negligible", "Medium"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
