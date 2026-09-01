"""Unit tests for the src.simulation subsystem.

Covers scenario generation, security control models, probabilistic type
selection, application templates/builders, and system simulation.

Determinism strategy: random branches are forced with extreme ScenarioConfig
probabilities (0.0/1.0) or by monkeypatching ``random.random`` /
``random.choices`` so the suite is stable across runs.
"""

from typing import Any

import pytest
from pydantic import ValidationError

from src.simulation import (
    APPLICATION_TEMPLATES,
    ApplicationBuilder,
    ApplicationComponent,
    ApplicationTemplate,
    ApplicationType,
    ComponentRole,
    EndpointProtectionType,
    ExposureBasedControlProbabilities,
    FirewallType,
    IDSIPSType,
    MFAType,
    PatchManagementQuality,
    SecurityControlsConfig,
    SecurityControlsGenerator,
    SecurityMaturityLevel,
    SegmentationType,
    ServiceSecurityControlsGenerator,
    SIEMMaturity,
    SimSystem,
    WAFType,
    build_application_for_scenario,
    estimate_maturity_from_posture,
    get_all_templates,
    get_application_templates,
    get_template_for_industry,
)
from src.simulation.application_templates import _load_application_templates
from src.simulation.control_type_selector import (
    _apply_modifiers,
    _normalize_probabilities,
    _select_from_distribution,
    select_endpoint_type,
    select_firewall_type,
    select_ids_ips_type,
    select_mfa_type,
    select_patch_quality,
    select_segmentation_type,
    select_siem_maturity,
    select_waf_type,
)
from src.simulation.scenario_config import ScenarioConfig
from src.simulation.scenario_generator import ScenarioGenerator
from src.simulation.system_simulator import SYSTEM_POSTURE_P_WEIGHTS

MATURITY_LEVELS = ["initial", "developing", "defined", "managed", "optimizing"]
INDUSTRIES = [
    "financial-services",
    "healthcare",
    "technology",
    "government",
    "small-business",
    "general",
]


def _argmax_choices(
    options: list[Any], weights: list[float] | None = None, k: int = 1
) -> list[Any]:
    """Deterministic stand-in for random.choices: always pick the max weight."""
    if weights is None:
        weights = [1.0] * len(options)
    best = max(zip(options, weights, strict=True), key=lambda pair: pair[1])
    return [best[0]] * k


def _first_choices(
    options: list[Any], weights: list[float] | None = None, k: int = 1
) -> list[Any]:
    """Deterministic stand-in for random.choices: always pick the first option."""
    return [options[0]] * k


@pytest.fixture()
def all_on_config() -> ScenarioConfig:
    """Scenario config forcing every random branch to its True side."""
    return ScenarioConfig(
        PROD_FLAT_NETWORK_PROB=0.0,
        DEV_SEGMENTED_NETWORK_PROB=1.0,
        APP_TIER_UNRESTRICTED_PROB=1.0,
        DB_EXPOSED_PROB=1.0,
        CICD_PROBABILITY=1.0,
        SIDECAR_PROBABILITY=1.0,
        SECRETS_PROBABILITY=1.0,
        MISCONFIG_PROBABILITY=1.0,
    )


@pytest.fixture()
def all_off_config() -> ScenarioConfig:
    """Scenario config forcing every random branch to its False side."""
    return ScenarioConfig(
        PROD_FLAT_NETWORK_PROB=0.0,
        DEV_SEGMENTED_NETWORK_PROB=0.0,
        APP_TIER_UNRESTRICTED_PROB=0.0,
        DB_EXPOSED_PROB=0.0,
        CICD_PROBABILITY=0.0,
        SIDECAR_PROBABILITY=0.0,
        SECRETS_PROBABILITY=0.0,
        MISCONFIG_PROBABILITY=0.0,
    )


@pytest.fixture()
def generator(all_on_config: ScenarioConfig) -> ScenarioGenerator:
    return ScenarioGenerator(scenario_config=all_on_config)


@pytest.fixture()
def generator_off(all_off_config: ScenarioConfig) -> ScenarioGenerator:
    return ScenarioGenerator(scenario_config=all_off_config)


@pytest.fixture()
def deterministic_random(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the module-level random functions to deterministic values."""
    monkeypatch.setattr("random.random", lambda: 0.5)
    monkeypatch.setattr("random.choices", _argmax_choices)
    monkeypatch.setattr("random.randint", lambda lower, upper: 0)


# ---------------------------------------------------------------------------
# ScenarioConfig
# ---------------------------------------------------------------------------


class TestScenarioConfig:
    def test_default_lists_populated(self) -> None:
        cfg = ScenarioConfig()
        assert "api_key" in cfg.SECRET_TYPES
        assert "exposed_port" in cfg.MISCONFIG_TYPES

    def test_probability_out_of_range_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioConfig(PROD_FLAT_NETWORK_PROB=1.5)

    def test_get_maturity_level_upgrades(self) -> None:
        cfg = ScenarioConfig()
        # managed(3) + mid(0) + global(+1) + prod(0) = 4 -> optimizing
        assert (
            cfg.get_maturity_level("mid", "global", "financial-services", "prod")
            == "optimizing"
        )

    def test_get_maturity_level_clamps_to_initial(self) -> None:
        cfg = ScenarioConfig()
        # developing(1) + small(-1) + local(0) + dev(-2) = -2 -> clamped
        assert (
            cfg.get_maturity_level("small", "local", "on-line-store", "dev")
            == "initial"
        )

    def test_get_maturity_level_unknown_industry_uses_default(self) -> None:
        cfg = ScenarioConfig()
        # default developing(1) + small(-1) + local(0) + prod(0) = 0
        assert cfg.get_maturity_level("small", "local", "unknown-industry", "prod") == (
            "initial"
        )

    def test_get_maturity_level_invalid_base_falls_back(self) -> None:
        cfg = ScenarioConfig(
            MATURITY_LEVEL_MAPPING={
                "industry": {"weird": "not-a-real-level"},
            }
        )
        assert cfg.get_maturity_level("mid", "local", "weird", "prod") == "developing"


# ---------------------------------------------------------------------------
# ScenarioGenerator
# ---------------------------------------------------------------------------


class TestScenarioGenerator:
    def test_load_config_missing_returns_empty(self, tmp_path: Any) -> None:
        gen = ScenarioGenerator(config_path=str(tmp_path / "missing.yaml"))
        assert gen.service_catalog == {}

    def test_load_config_invalid_yaml_returns_empty(self, tmp_path: Any) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("key: [unclosed\n")
        gen = ScenarioGenerator(config_path=str(bad))
        assert gen.service_catalog == {}

    def test_default_config_used_when_not_given(self) -> None:
        gen = ScenarioGenerator()
        assert isinstance(gen.scenario_config, ScenarioConfig)

    def test_generate_scenario_prod_structured(
        self, generator: ScenarioGenerator
    ) -> None:
        env = generator.generate_scenario(
            "mid", "global", "consulting", environment_type="prod"
        )
        assert isinstance(env, dict)
        for key in (
            "scenario_id",
            "company_name",
            "metadata",
            "network_zones",
            "services",
            "network_policies",
            "security_posture",
            "security_controls",
            "security_maturity",
        ):
            assert key in env

        # PROD_FLAT_NETWORK_PROB=0.0 -> segmentation never flipped off
        assert env["metadata"]["topology"] == "segmented"
        assert len(env["services"]) > 0

        # all-on config: every service carries a misconfiguration and a secret
        for svc in env["services"]:
            assert svc["misconfigurations"]
            assert svc["hardcoded_secrets"]

        # consulting + complexity 3 includes monitoring -> sidecars on all
        assert any("sidecar_exporter" in s for s in env["services"])

        # CICD_PROBABILITY=1.0 -> CI/CD services appended
        assert any(s["role"] in ("vcs", "ci", "registry") for s in env["services"])

        # APP_TIER_UNRESTRICTED_PROB / DB_EXPOSED_PROB = 1.0 -> misconfig policies
        descriptions = [p["description"] for p in env["network_policies"]]
        assert any("MISCONFIGURATION" in d for d in descriptions)

        # consulting(defined=2) + mid(0) + global(+1) + prod(0) = managed
        assert env["security_maturity"] == "managed"

    def test_generate_scenario_flat_dev(self, generator_off: ScenarioGenerator) -> None:
        env = generator_off.generate_scenario(
            "small", "local", "consulting", environment_type="dev"
        )
        assert env["metadata"]["topology"] == "flat"
        assert env["network_zones"] == ["flat_network"]

        for svc in env["services"]:
            assert svc["misconfigurations"] == []
            assert svc["hardcoded_secrets"] == []

        # flat network -> single allow-all policy
        assert [p for p in env["network_policies"] if p["source"] == "*"]

        # dev environments always get CI/CD services
        assert any(s["role"] == "vcs" for s in env["services"])

    def test_generate_scenario_csv(self, generator: ScenarioGenerator) -> None:
        csv_text = generator.generate_scenario(
            "mid",
            "global",
            "on-line-store",
            environment_type="prod",
            output_format="csv",
        )
        assert isinstance(csv_text, str)
        assert csv_text.startswith("scenario_id,company_name")

    def test_export_to_csv_without_services(self, generator: ScenarioGenerator) -> None:
        scenario = {
            "scenario_id": "s1",
            "company_name": "Acme",
            "metadata": {
                "size": "small",
                "reach": "local",
                "industry": "consulting",
                "environment": "dev",
                "topology": "flat",
            },
            "security_posture": {
                "patch_management": "monthly",
                "compliance_standards": [],
            },
            "services": [],
        }
        csv_text = generator.export_to_csv(scenario)
        # no services -> only the header row is written
        assert len(csv_text.strip().splitlines()) == 1
        assert csv_text.startswith("scenario_id,company_name")

    def test_generate_scenario_empty_catalog(
        self, tmp_path: Any, all_on_config: ScenarioConfig
    ) -> None:
        gen = ScenarioGenerator(
            config_path=str(tmp_path / "missing.yaml"), scenario_config=all_on_config
        )
        env = gen.generate_scenario(
            "small", "local", "unknown-industry", environment_type="dev"
        )
        # no catalog entries, but dev env still gets the 3 CI/CD services
        assert [s["name"] for s in env["services"]] == [
            "git-repository",
            "ci-runner",
            "artifact-registry",
        ]
        assert env["metadata"]["topology"] == "segmented"  # DEV_SEGMENTED=1.0

    def test_design_architecture_non_list_category(
        self, generator: ScenarioGenerator
    ) -> None:
        generator.service_catalog = {"proxy": "not-a-list"}  # type: ignore[assignment]
        services = generator._design_architecture(
            "on-line-store", 1, "local", "dev", False
        )
        assert services == []

    def test_design_architecture_uses_fallback_categories(
        self, generator: ScenarioGenerator
    ) -> None:
        # unknown industry -> default categories from the real catalog
        services = generator._design_architecture(
            "unknown-industry", 1, "local", "dev", False
        )
        assert services
        roles = {s["role"] for s in services}
        assert roles & {"load_balancer", "web_server", "app_server"}

    def test_network_policies_bastion_and_monitoring(
        self, generator: ScenarioGenerator
    ) -> None:
        services = [{"role": "bastion"}, {"role": "monitoring"}]
        policies = generator._generate_network_policies(services, True, "prod")
        descriptions = [p["description"] for p in policies]
        assert any("Bastion" in d for d in descriptions)
        assert any("Prometheus" in d for d in descriptions)

    def test_network_policies_flat_allows_all(
        self, generator: ScenarioGenerator
    ) -> None:
        policies = generator._generate_network_policies([], False, "dev")
        assert len(policies) == 1
        assert policies[0] == {
            "source": "*",
            "destination": "*",
            "port": "*",
            "action": "allow",
            "description": "Flat network allows all traffic by default",
        }

    def test_generate_posture_prod_financial_global(
        self, generator: ScenarioGenerator, deterministic_random: None
    ) -> None:
        posture = generator._generate_posture(
            "mid", "global", "financial-services", "prod"
        )
        # base 1 + 3 + 4 = 8, randint pinned to 0 -> daily patching
        assert posture["patch_management"] == "daily"
        assert posture["incident_response_plan"] is True
        assert posture["encryption_at_rest"] is True
        assert posture["network_segmentation"] is True
        assert posture["mfa_enforced"] is True
        assert posture["security_training"] is True
        assert "PCI-DSS" in posture["compliance_standards"]
        assert "SOC2" in posture["compliance_standards"]
        assert "GDPR" in posture["compliance_standards"]

    def test_generate_posture_dev_low_score(
        self, generator: ScenarioGenerator, deterministic_random: None
    ) -> None:
        posture = generator._generate_posture("small", "local", "consulting", "dev")
        # base 0 + 0 + 0 - 3 = -3 -> clamped to 0
        assert posture["patch_management"] == "monthly"
        assert posture["incident_response_plan"] is False
        assert posture["encryption_at_rest"] is False
        assert posture["mfa_enforced"] is False

    def test_generate_posture_stage_low_score(
        self, generator: ScenarioGenerator, deterministic_random: None
    ) -> None:
        posture = generator._generate_posture("mid", "local", "on-line-store", "stage")
        # base 1 + 0 + 2 - 1 = 2 -> monthly band; 2 is not > threshold (2)
        assert posture["patch_management"] == "monthly"
        assert posture["network_segmentation"] is False

    def test_generate_posture_weekly_band(
        self, generator: ScenarioGenerator, deterministic_random: None
    ) -> None:
        posture = generator._generate_posture("mid", "global", "on-line-store", "prod")
        # base 1 + 3 + 2 = 6 -> weekly band (4 <= score < 7)
        assert posture["patch_management"] == "weekly"

    @pytest.mark.parametrize(
        ("exposure", "segmented"),
        [
            ("internet-facing", True),
            ("internal", False),
            ("internal", True),
        ],
    )
    def test_get_zone(
        self, generator: ScenarioGenerator, exposure: str, segmented: bool
    ) -> None:
        zone = generator._get_zone(exposure, segmented)
        if exposure == "internet-facing" and segmented:
            assert zone == "dmz"
        elif not segmented:
            assert zone == "flat_network"
        else:
            assert zone in {"app_tier", "data_tier", "internal"}

    @pytest.mark.parametrize(
        ("role", "expected"),
        [
            ("database", "critical"),
            ("payment", "critical"),
            ("iam", "critical"),
            ("secrets_management", "critical"),
            ("api_server", "high"),
            ("web_server", "high"),
            ("app_server", "high"),
            ("cicd_server", "high"),
            ("message_broker", "high"),
            ("load_balancer", "medium"),
        ],
    )
    def test_calculate_asset_value(
        self, generator: ScenarioGenerator, role: str, expected: str
    ) -> None:
        assert generator._calculate_asset_value(role, "general") == expected

    @pytest.mark.parametrize(
        ("role", "industry", "expected"),
        [
            ("database", "financial-services", "DBTEAM"),
            ("iam", "financial-services", "SECURITY"),
            ("database", "consulting", "DBTEAM"),
            ("monitoring", "consulting", "DEVOPS"),
            ("web_server", "general", "DEV"),
            # ingress_controller matches devops_roles before cloudnet_roles
            ("ingress_controller", "general", "DEVOPS"),
            ("network_infra", "general", "CLOUDNET"),
            ("cache", "general", "DBTEAM"),
            ("waf", "general", "SECURITY"),
            ("mystery_role", "general", "DEV"),
        ],
    )
    def test_determine_ownership(
        self, generator: ScenarioGenerator, role: str, industry: str, expected: str
    ) -> None:
        assert generator._determine_ownership(role, industry) == expected

    @pytest.mark.parametrize(
        ("role", "expected"),
        [
            ("database", ["pii", "financial"]),
            ("payment", ["pci-dss", "financial"]),
            ("iam", ["credentials", "confidential"]),
            ("secrets_management", ["secrets", "confidential"]),
            ("siem_storage", ["logs", "audit"]),
            ("bi_tool", ["analytics", "business-intelligence"]),
            ("web_server", []),
        ],
    )
    def test_get_data_classification(
        self, generator: ScenarioGenerator, role: str, expected: list[str]
    ) -> None:
        assert generator._get_data_classification(role) == expected

    def test_add_sidecar_exporters_all(self, generator: ScenarioGenerator) -> None:
        services = [
            {"name": "svc-a", "role": "app_server"},
            {"name": "svc-b", "role": "database"},
        ]
        result = generator._add_sidecar_exporters(services)
        assert all("sidecar_exporter" in s for s in result)

    def test_add_cicd_services_segmented(self, generator: ScenarioGenerator) -> None:
        result = generator._add_cicd_services([], "dev", True)
        assert len(result) == 3
        # all-on config: misconfigs and secrets always present
        assert all(s["misconfigurations"] for s in result)
        assert all(s["hardcoded_secrets"] for s in result)
        assert {s["zone"] for s in result} <= {"internal", "app_tier"}

    def test_add_cicd_services_flat(self, generator_off: ScenarioGenerator) -> None:
        result = generator_off._add_cicd_services([], "dev", False)
        assert {s["zone"] for s in result} == {"flat_network"}

    def test_generate_security_controls_invalid_maturity(
        self, generator: ScenarioGenerator
    ) -> None:
        cfg = generator._generate_security_controls(
            "not-a-level", "general", "prod", "mid"
        )
        assert isinstance(cfg, SecurityControlsConfig)


# ---------------------------------------------------------------------------
# Security controls
# ---------------------------------------------------------------------------


class TestSecurityControlsGenerator:
    def test_generate_with_enum_and_string_maturity(
        self, deterministic_random: None
    ) -> None:
        gen = SecurityControlsGenerator()
        cfg_enum = gen.generate(
            SecurityMaturityLevel.DEFINED, "financial-services", "prod", "mid"
        )
        cfg_str = gen.generate("defined", "general", "dev", "small")
        assert isinstance(cfg_enum, SecurityControlsConfig)
        assert isinstance(cfg_str, SecurityControlsConfig)
        assert isinstance(cfg_enum.segmentation_type, SegmentationType)
        assert isinstance(cfg_enum.firewall_type, FirewallType)
        assert isinstance(cfg_enum.mfa_type, MFAType)

    @pytest.mark.parametrize("industry", INDUSTRIES)
    def test_generate_industries(
        self, deterministic_random: None, industry: str
    ) -> None:
        cfg = SecurityControlsGenerator().generate("managed", industry, "prod", "mid")
        assert isinstance(cfg, SecurityControlsConfig)

    @pytest.mark.parametrize("environment", ["prod", "stage", "qa", "dev", "test"])
    def test_generate_environments(
        self, deterministic_random: None, environment: str
    ) -> None:
        cfg = SecurityControlsGenerator().generate(
            "defined", "general", environment, "mid"
        )
        assert isinstance(cfg, SecurityControlsConfig)

    @pytest.mark.parametrize("size", ["small", "mid", "large"])
    def test_generate_sizes(self, deterministic_random: None, size: str) -> None:
        cfg = SecurityControlsGenerator().generate("defined", "general", "prod", size)
        assert isinstance(cfg, SecurityControlsConfig)

    def test_should_have_control_thresholds(self, deterministic_random: None) -> None:
        gen = SecurityControlsGenerator()
        # random pinned to 0.5
        assert gen._should_have_control(1.0, 1.0, 1.0, 1.0) is True
        assert gen._should_have_control(0.4, 1.0, 1.0, 1.0) is False
        # modifiers can push a sub-threshold base probability over 0.5
        assert gen._should_have_control(0.4, 2.0, 1.0, 1.0) is True

    def test_select_patch_cadence_first_and_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        gen = SecurityControlsGenerator()
        monkeypatch.setattr("random.random", lambda: 0.0)
        assert gen._select_patch_cadence("initial") == "daily"
        monkeypatch.setattr("random.random", lambda: 1.0)
        assert gen._select_patch_cadence("initial") == "monthly"

    def test_get_active_controls_all_none(self) -> None:
        cfg = SecurityControlsConfig(
            segmentation_type="none",
            firewall_type="none",
            waf_type="none",
            ids_ips_type="none",
            endpoint_protection_type="none",
            mfa_type="none",
            privileged_access_mgmt=False,
            patch_management_quality="none",
            siem_maturity="none",
            soc_24x7=False,
            incident_response_plan=False,
            security_training=False,
            air_gapped=False,
        )
        # quirk: the cadence guard only excludes "ad_hoc", so a "none"
        # patch quality is still counted as one active control
        assert cfg.get_active_controls() == ["patch_none"]
        assert cfg.count_controls() == 1

    def test_get_active_controls_populated(self) -> None:
        cfg = SecurityControlsConfig(
            segmentation_type="zero_trust",
            firewall_type="next_gen",
            waf_type="managed",
            ids_ips_type="ips_signature",
            endpoint_protection_type="xdr",
            mfa_type="fido2",
            privileged_access_mgmt=True,
            patch_management_quality="weekly",
            siem_maturity="advanced",
            soc_24x7=True,
            incident_response_plan=True,
            security_training=False,
            air_gapped=True,
        )
        active = cfg.get_active_controls()
        for expected in (
            "segmentation",
            "firewall",
            "waf",
            "ids_ips",
            "endpoint_protection",
            "mfa",
            "privileged_access_mgmt",
            "patch_management",
            "siem",
            "soc_24x7",
            "incident_response_plan",
            "air_gapped",
            "patch_weekly",
        ):
            assert expected in active
        assert "security_training" not in active
        assert cfg.count_controls() == len(active)

    def test_get_patch_cadence_and_to_dict(self) -> None:
        cfg = SecurityControlsConfig(patch_management_quality="weekly")
        assert cfg.get_patch_cadence() == "weekly"
        data = cfg.to_dict()
        assert data["patch_management_quality"] == "weekly"


class TestExposureBasedControlProbabilities:
    @pytest.mark.parametrize(
        ("exposure", "control", "expected"),
        [
            ("internet-facing", "waf", 2.5),
            ("internal", "siem", 0.6),
            ("dmz", "network_segmentation", 1.5),
            ("restricted", "privileged_access_mgmt", 1.5),
            ("internet-facing", "patch_daily", 1.0),  # unknown control -> default
            ("unknown-zone", "waf", 1.0),  # unknown exposure -> default
            ("INTERNET-FACING", "waf", 2.5),  # case-insensitive
        ],
    )
    def test_get_modifier(self, exposure: str, control: str, expected: float) -> None:
        assert ExposureBasedControlProbabilities.get_modifier(exposure, control) == (
            expected
        )

    @pytest.mark.parametrize(
        ("exposure", "expected"),
        [
            ("internet-facing", ["firewall", "waf", "antivirus"]),
            ("dmz", ["firewall", "antivirus", "network_segmentation"]),
            ("internal", ["firewall", "antivirus"]),
            ("restricted", ["firewall", "antivirus", "network_segmentation", "mfa"]),
            ("unknown-zone", ["firewall", "antivirus"]),
        ],
    )
    def test_get_mandatory_controls(self, exposure: str, expected: list[str]) -> None:
        assert ExposureBasedControlProbabilities.get_mandatory_controls(exposure) == (
            expected
        )


class TestServiceSecurityControlsGenerator:
    def test_generate_for_service_exposures(self, deterministic_random: None) -> None:
        gen = ServiceSecurityControlsGenerator(base_maturity="defined")
        for exposure in ("internet-facing", "dmz", "internal", "restricted"):
            controls = gen.generate_for_service(exposure)
            assert set(controls) >= {
                "firewall",
                "waf",
                "antivirus",
                "network_segmentation",
                "mfa",
                "incident_response_plan",
                "security_training",
                "patch_daily",
                "patch_weekly",
                "patch_monthly",
                "patch_quarterly",
                "air_gapped",
            }
        # mandatory controls are forced on regardless of probability
        internet = gen.generate_for_service("internet-facing")
        assert internet["firewall"] is True
        assert internet["waf"] is True
        assert internet["antivirus"] is True

    def test_generate_for_service_asset_and_role_modifiers(
        self, deterministic_random: None
    ) -> None:
        gen = ServiceSecurityControlsGenerator(base_maturity="developing")
        for asset_value in ("critical", "high", "medium", "low"):
            for role in (
                "database",
                "web_server",
                "app_server",
                "cache",
                "secrets_management",
                "load_balancer",
                "mystery-role",
            ):
                controls = gen.generate_for_service(
                    "internal", service_role=role, asset_value=asset_value
                )
                assert isinstance(controls["mfa"], bool)

    def test_air_gapped_for_restricted_critical_infrastructure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        gen = ServiceSecurityControlsGenerator(base_maturity="defined")
        monkeypatch.setattr("random.random", lambda: 0.2)  # < 0.3 -> air-gapped
        controls = gen.generate_for_service(
            "restricted", industry="critical-infrastructure"
        )
        assert controls["air_gapped"] is True

    def test_air_gapped_false_for_non_restricted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        gen = ServiceSecurityControlsGenerator(base_maturity="defined")
        monkeypatch.setattr("random.random", lambda: 0.2)
        controls = gen.generate_for_service(
            "internal", industry="critical-infrastructure"
        )
        assert controls["air_gapped"] is False

    def test_initial_maturity_branches(self, deterministic_random: None) -> None:
        gen = ServiceSecurityControlsGenerator(base_maturity="initial")
        controls = gen.generate_for_service("internal")
        assert isinstance(controls["incident_response_plan"], bool)


def test_estimate_maturity_from_posture() -> None:
    assert (
        estimate_maturity_from_posture(
            {
                "network_segmentation": False,
                "mfa_enforced": False,
                "encryption_at_rest": False,
                "incident_response_plan": False,
                "security_training": False,
                "patch_management": "monthly",  # score 1 -> initial
            }
        )
        is SecurityMaturityLevel.INITIAL
    )
    assert (
        estimate_maturity_from_posture(
            {
                "mfa_enforced": True,  # +2
                "patch_management": "monthly",  # +1 -> score 3 -> developing
            }
        )
        is SecurityMaturityLevel.DEVELOPING
    )
    assert (
        estimate_maturity_from_posture(
            {
                "network_segmentation": True,  # +2
                "mfa_enforced": True,  # +2
                "patch_management": "monthly",  # +1 -> score 5 -> defined
            }
        )
        is SecurityMaturityLevel.DEFINED
    )
    assert (
        estimate_maturity_from_posture(
            {
                "network_segmentation": True,  # +2
                "mfa_enforced": True,  # +2
                "encryption_at_rest": True,  # +1
                "incident_response_plan": True,  # +1
                "patch_management": "weekly",  # +2 -> score 8 -> managed
            }
        )
        is SecurityMaturityLevel.MANAGED
    )
    assert (
        estimate_maturity_from_posture(
            {
                "network_segmentation": True,  # +2
                "mfa_enforced": True,  # +2
                "encryption_at_rest": True,  # +1
                "incident_response_plan": True,  # +1
                "security_training": True,  # +1
                "patch_management": "daily",  # +3
                "compliance_standards": ["PCI-DSS"],  # +1 -> score 11
            }
        )
        is SecurityMaturityLevel.OPTIMIZING
    )


# ---------------------------------------------------------------------------
# Control type selector
# ---------------------------------------------------------------------------


class TestSelectorHelpers:
    def test_normalize_probabilities(self) -> None:
        assert _normalize_probabilities({"a": 0.5, "b": 1.5}) == {"a": 0.25, "b": 0.75}

    def test_normalize_probabilities_all_zero(self) -> None:
        assert _normalize_probabilities({"a": 0.0, "b": 0.0}) == {"a": 0.0, "b": 0.0}

    def test_apply_modifiers(self) -> None:
        base = {MFAType.SMS: 1.0, MFAType.FIDO2: 1.0}
        result = _apply_modifiers(base, {MFAType.SMS: 0.5})
        assert result == {MFAType.SMS: 0.5, MFAType.FIDO2: 1.0}

    def test_select_from_distribution_argmax(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert (
            _select_from_distribution({MFAType.NONE: 0.2, MFAType.FIDO2: 0.8})
            is MFAType.FIDO2
        )


class TestSelectors:
    @pytest.mark.parametrize("maturity", MATURITY_LEVELS)
    def test_select_mfa_type(
        self, monkeypatch: pytest.MonkeyPatch, maturity: str
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert isinstance(select_mfa_type(maturity), MFAType)

    def test_select_mfa_type_exact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert select_mfa_type("initial") is MFAType.NONE  # 0.70 dominates
        assert select_mfa_type("optimizing") is MFAType.FIDO2  # 0.40 dominates

    @pytest.mark.parametrize("industry", INDUSTRIES)
    def test_select_mfa_type_industries(
        self, monkeypatch: pytest.MonkeyPatch, industry: str
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert isinstance(select_mfa_type("initial", industry=industry), MFAType)

    def test_select_firewall_type_modifier_shifts_winner(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        # small-business boosts BASIC 0.60 * 1.5 = 0.90 above NONE's 0.10
        assert (
            select_firewall_type("initial", industry="small-business")
            is FirewallType.BASIC
        )

    @pytest.mark.parametrize("maturity", MATURITY_LEVELS)
    def test_select_waf_type(
        self, monkeypatch: pytest.MonkeyPatch, maturity: str
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert isinstance(select_waf_type(maturity), WAFType)

    def test_select_waf_type_exposures(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        for exposure in ("internet-facing", "restricted", "internal", "unknown"):
            assert isinstance(select_waf_type("initial", exposure=exposure), WAFType)

    @pytest.mark.parametrize("maturity", MATURITY_LEVELS)
    def test_select_endpoint_type(
        self, monkeypatch: pytest.MonkeyPatch, maturity: str
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert isinstance(select_endpoint_type(maturity), EndpointProtectionType)

    def test_select_endpoint_type_industry_modifier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # healthcare boosts TRADITIONAL_AV (0.70 * 1.3) above NONE's 0.15
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert (
            select_endpoint_type("initial", industry="healthcare")
            is EndpointProtectionType.TRADITIONAL_AV
        )

    def test_select_segmentation_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert (
            select_segmentation_type("optimizing")
            is SegmentationType.MICRO_SEGMENTATION
        )
        for exposure in ("internet-facing", "restricted", "unknown"):
            assert isinstance(
                select_segmentation_type("initial", exposure=exposure), SegmentationType
            )

    @pytest.mark.parametrize("maturity", MATURITY_LEVELS)
    def test_select_ids_ips_type(
        self, monkeypatch: pytest.MonkeyPatch, maturity: str
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert isinstance(select_ids_ips_type(maturity), IDSIPSType)

    @pytest.mark.parametrize("maturity", MATURITY_LEVELS)
    def test_select_siem_maturity(
        self, monkeypatch: pytest.MonkeyPatch, maturity: str
    ) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert isinstance(select_siem_maturity(maturity), SIEMMaturity)

    def test_select_siem_maturity_industry_modifier(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # financial-services has no siem type modifier in the probability table,
        # but exercises the industry-modifier lookup path
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert (
            select_siem_maturity("optimizing", industry="financial-services")
            is SIEMMaturity.ADVANCED_ANALYTICS
        )

    def test_select_patch_quality(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("random.choices", _argmax_choices)
        assert select_patch_quality("optimizing") is PatchManagementQuality.WEEKLY


# ---------------------------------------------------------------------------
# Application templates and builder
# ---------------------------------------------------------------------------


def _test_template() -> ApplicationTemplate:
    return ApplicationTemplate(
        name="Test App",
        type=ApplicationType.ECOMMERCE,
        description="test application",
        components=[
            ApplicationComponent(
                name=c_name,
                role=role,
                service_category="web_server",
                exposure=exposure,
            )
            for c_name, role, exposure in [
                ("ingress-1", ComponentRole.INGRESS, "internet-facing"),
                ("frontend-1", ComponentRole.FRONTEND, "dmz"),
                ("backend-1", ComponentRole.BACKEND, "internal"),
                ("db-1", ComponentRole.DATABASE, "internal"),
                ("cache-1", ComponentRole.CACHE, "restricted"),
                ("queue-1", ComponentRole.MESSAGING, "internal"),
                ("payment-1", ComponentRole.PAYMENT, "internal"),
                ("auth-1", ComponentRole.AUTH, "internal"),
                ("monitoring-1", ComponentRole.MONITORING, "internal"),
                ("cicd-1", ComponentRole.CICD, "internal"),
            ]
        ],
    )


@pytest.fixture()
def service_catalog() -> dict[str, Any]:
    return {
        "web_server": [
            {
                "name": "nginx",
                "image": "nginx:1.25",
                "versions": ["nginx:1.25"],
                "role": "web_server",
            },
            {
                "name": "apache",
                "image": "httpd:2.4",
                "versions": ["httpd:2.4"],
                "role": "web_server",
            },
        ],
    }


class TestApplicationTemplates:
    def test_get_application_templates(self) -> None:
        templates = get_application_templates()
        assert set(templates) == {
            ApplicationType.ECOMMERCE,
            ApplicationType.FINANCIAL_SERVICES,
            ApplicationType.CONSULTING,
            ApplicationType.SAAS_PLATFORM,
            ApplicationType.DATA_ANALYTICS,
        }

    def test_module_level_constants_loaded(self) -> None:
        assert len(APPLICATION_TEMPLATES) == 5
        ecommerce = APPLICATION_TEMPLATES[ApplicationType.ECOMMERCE]
        assert len(ecommerce.components) > 0

    def test_get_all_templates(self) -> None:
        assert len(get_all_templates()) == 5

    @pytest.mark.parametrize(
        ("industry", "expected_type"),
        [
            ("on-line-store", ApplicationType.ECOMMERCE),
            ("financial-services", ApplicationType.FINANCIAL_SERVICES),
            ("consulting", ApplicationType.CONSULTING),
            ("saas", ApplicationType.SAAS_PLATFORM),
            ("data-analytics", ApplicationType.DATA_ANALYTICS),
            ("unknown-industry", ApplicationType.CONSULTING),
        ],
    )
    def test_get_template_for_industry(
        self, industry: str, expected_type: ApplicationType
    ) -> None:
        assert get_template_for_industry(industry).type is expected_type

    def test_load_templates_missing_file(self, tmp_path: Any) -> None:
        assert _load_application_templates(str(tmp_path / "missing.yaml")) == {}

    def test_load_templates_without_applications_section(self, tmp_path: Any) -> None:
        cfg = tmp_path / "services.yaml"
        cfg.write_text("proxy:\n  - name: nginx\n")
        assert _load_application_templates(str(cfg)) == {}

    def test_load_templates_skips_invalid_app(self, tmp_path: Any) -> None:
        cfg = tmp_path / "services.yaml"
        cfg.write_text(
            "applications:\n"
            "  good_app:\n"
            "    name: Good App\n"
            "    type: ecommerce\n"
            "    description: ok\n"
            "    components:\n"
            "      - name: web-1\n"
            "        role: frontend\n"
            "        service_category: web_server\n"
            "  bad_app:\n"
            "    name: Bad App\n"
            "    type: ecommerce\n"
            "    description: broken role\n"
            "    components:\n"
            "      - name: web-1\n"
            "        role: not-a-role\n"
            "        service_category: web_server\n"
        )
        templates = _load_application_templates(str(cfg))
        assert set(templates) == {"good_app"}

    def test_load_templates_invalid_yaml(self, tmp_path: Any) -> None:
        cfg = tmp_path / "services.yaml"
        cfg.write_text("applications: {{{ not valid yaml\n")
        assert _load_application_templates(str(cfg)) == {}


class TestApplicationBuilder:
    def test_build_application_all_roles(self, service_catalog: dict[str, Any]) -> None:
        app = ApplicationBuilder(service_catalog).build_application(
            _test_template(), "Acme Corp", True
        )
        assert app["name"] == "Test App"
        assert app["company_name"] == "Acme Corp"
        assert app["component_count"] == 10
        assert len(app["services"]) == 10

        by_name = {s["name"]: s for s in app["services"]}
        assert by_name["db-1"]["ownership"] == "DBTEAM"
        assert by_name["db-1"]["data_classification"] == ["pii", "financial"]
        assert by_name["ingress-1"]["zone"] == "dmz"  # internet-facing
        assert by_name["cache-1"]["zone"] == "internal"  # restricted
        assert by_name["frontend-1"]["depends_on"] == []
        for service in app["services"]:
            assert service["image"].startswith(("nginx", "httpd"))

    def test_build_application_flat_network(
        self, service_catalog: dict[str, Any]
    ) -> None:
        app = ApplicationBuilder(service_catalog).build_application(
            _test_template(), "Acme Corp", False
        )
        assert {s["zone"] for s in app["services"]} == {"flat_network"}

    def test_build_application_missing_category(
        self, service_catalog: dict[str, Any]
    ) -> None:
        template = ApplicationTemplate(
            name="Orphan App",
            type=ApplicationType.SAAS_PLATFORM,
            description="component in a missing catalog category",
            components=[
                ApplicationComponent(
                    name="orphan-1",
                    role=ComponentRole.BACKEND,
                    service_category="does_not_exist",
                )
            ],
        )
        app = ApplicationBuilder(service_catalog).build_application(
            template, "Acme Corp", True
        )
        assert app["services"] == []
        assert app["component_count"] == 0

    def test_build_application_non_list_category(self) -> None:
        catalog: dict[str, Any] = {"web_server": "not-a-list"}  # type: ignore[dict-item]
        template = ApplicationTemplate(
            name="Broken App",
            type=ApplicationType.SAAS_PLATFORM,
            description="category value is not a list",
            components=[
                ApplicationComponent(
                    name="broken-1",
                    role=ComponentRole.BACKEND,
                    service_category="web_server",
                )
            ],
        )
        app = ApplicationBuilder(catalog).build_application(template, "Acme Corp", True)
        assert app["services"] == []

    def test_build_application_for_scenario(self) -> None:
        app = build_application_for_scenario(
            "on-line-store",
            "Acme Corp",
            True,
            {
                "proxy": [
                    {
                        "name": "nginx",
                        "image": "nginx:1.25",
                        "versions": ["nginx:1.25"],
                        "role": "load_balancer",
                    },
                ],
            },
        )
        assert app["name"] == "E-Commerce Platform"
        assert len(app["services"]) > 0


# ---------------------------------------------------------------------------
# System simulator
# ---------------------------------------------------------------------------


class TestSimSystem:
    def test_linux_system(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("random.choice", lambda options: "Linux")
        monkeypatch.setattr("random.choices", _first_choices)
        system = SimSystem()
        assert system.os == "Linux"
        assert system.hostname.startswith("L-")
        assert system.group in {"REV", "AUX", "NBC", "INF"}
        assert system.os_ver == "Ubuntu 22.04"
        assert set(system.posture) >= {"PatchMgmt", "SIEM", "NetworkSeg"}
        assert str(system).startswith("System: L-")

    def test_windows_system(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("random.choice", lambda options: "Windows")
        monkeypatch.setattr("random.choices", _first_choices)
        system = SimSystem()
        assert system.os == "Windows"
        assert system.hostname.startswith("W-")
        assert system.os_ver == "Windows Server 2019"

    def test_custom_weights(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("random.choice", lambda options: "Linux")
        monkeypatch.setattr(
            "random.choices",
            lambda options, weights=None, k=1: [options[-1]] * k,
        )
        system = SimSystem(
            os_p_weights={"Linux": {"INF": 1.0}},
            sys_p_weights={},  # falsy -> falls back to the default weights table
            lin_svs={"Alpine 3": 1.0},
        )
        assert system.group == "INF"
        assert system.os_ver == "Alpine 3"
        assert set(system.posture) == set(SYSTEM_POSTURE_P_WEIGHTS["INF_L"])
        assert all(isinstance(v, bool) for v in system.posture.values())
