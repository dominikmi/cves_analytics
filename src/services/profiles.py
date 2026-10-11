"""Profile snapshot generation for persistent scan environments."""

from dataclasses import dataclass
from typing import Any

from src.simulation.scenario_generator import ScenarioGenerator
from src.utils.logging_config import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class ProfileSnapshot:
    """Serializable environment state stored with a profile."""

    image_inventory: list[str]
    controls_snapshot: dict[str, Any]
    scenario_snapshot: dict[str, Any]


_MATURITY_LEVELS = ("initial", "developing", "defined", "managed", "optimizing")

_BASE_PROBS: dict[str, dict[str, float]] = {
    "network_segmentation": {
        "initial": 0.10,
        "developing": 0.30,
        "defined": 0.60,
        "managed": 0.85,
        "optimizing": 0.95,
    },
    "firewall": {
        "initial": 0.50,
        "developing": 0.80,
        "defined": 0.95,
        "managed": 0.99,
        "optimizing": 0.99,
    },
    "waf": {
        "initial": 0.05,
        "developing": 0.20,
        "defined": 0.50,
        "managed": 0.75,
        "optimizing": 0.90,
    },
    "ids_ips": {
        "initial": 0.10,
        "developing": 0.30,
        "defined": 0.60,
        "managed": 0.80,
        "optimizing": 0.95,
    },
    "edr_xdr": {
        "initial": 0.05,
        "developing": 0.15,
        "defined": 0.40,
        "managed": 0.70,
        "optimizing": 0.90,
    },
    "antivirus": {
        "initial": 0.60,
        "developing": 0.80,
        "defined": 0.90,
        "managed": 0.95,
        "optimizing": 0.95,
    },
    "mfa": {
        "initial": 0.10,
        "developing": 0.30,
        "defined": 0.60,
        "managed": 0.85,
        "optimizing": 0.95,
    },
    "privileged_access_mgmt": {
        "initial": 0.02,
        "developing": 0.10,
        "defined": 0.30,
        "managed": 0.60,
        "optimizing": 0.85,
    },
    "siem": {
        "initial": 0.05,
        "developing": 0.15,
        "defined": 0.40,
        "managed": 0.70,
        "optimizing": 0.90,
    },
    "soc_24x7": {
        "initial": 0.01,
        "developing": 0.05,
        "defined": 0.20,
        "managed": 0.50,
        "optimizing": 0.80,
    },
    "incident_response_plan": {
        "initial": 0.30,
        "developing": 0.60,
        "defined": 0.85,
        "managed": 0.95,
        "optimizing": 0.99,
    },
    "security_training": {
        "initial": 0.20,
        "developing": 0.50,
        "defined": 0.75,
        "managed": 0.90,
        "optimizing": 0.99,
    },
    "air_gapped": {
        "initial": 0.01,
        "developing": 0.01,
        "defined": 0.01,
        "managed": 0.02,
        "optimizing": 0.02,
    },
}

_PATCH_CADENCE = {
    "initial": "quarterly",
    "developing": "monthly",
    "defined": "monthly",
    "managed": "weekly",
    "optimizing": "daily",
}


def _maturity_label(score: float) -> str:
    """Map the API's numeric maturity scale to CMMI-style labels."""
    index = min(int(max(score, 0.0) * len(_MATURITY_LEVELS)), len(_MATURITY_LEVELS) - 1)
    return _MATURITY_LEVELS[index]


def _fallback_controls(security_maturity: float) -> dict[str, Any]:
    """Build a deterministic controls snapshot if scenario generation fails."""
    maturity = _maturity_label(security_maturity)
    controls: dict[str, Any] = {
        control: probabilities[maturity] >= 0.5
        for control, probabilities in _BASE_PROBS.items()
    }
    controls["patch_management"] = _PATCH_CADENCE[maturity]
    controls["maturity_level"] = maturity
    return controls


def _normalise_controls(controls: dict[str, Any]) -> dict[str, Any]:
    """Expose scenario control types in the dashboard's boolean vocabulary."""
    normalized = dict(controls)
    type_fields = {
        "network_segmentation": ("network_segmentation", "segmentation_type"),
        "firewall": ("firewall", "firewall_type"),
        "waf": ("waf", "waf_type"),
        "ids_ips": ("ids_ips", "ids_ips_type"),
        "edr_xdr": ("edr_xdr", "endpoint_protection_type"),
        "mfa": ("mfa", "mfa_type"),
        "siem": ("siem", "siem_maturity"),
    }
    for output_key, aliases in type_fields.items():
        if output_key in normalized:
            continue
        value = next((controls[alias] for alias in aliases if alias in controls), None)
        normalized[output_key] = value not in (None, "", "none", False)
    normalized.setdefault(
        "patch_management",
        controls.get("patch_management")
        or controls.get("patch_management_quality")
        or controls.get("patch_cadence"),
    )
    return normalized


def build_profile_snapshot(
    *,
    org_size: str,
    org_reach: str,
    industry: str,
    environment: str,
    security_maturity: float,
    image_inventory: list[str],
) -> ProfileSnapshot:
    """Generate the profile's immutable starting environment.

    The scenario is generated once at profile creation so subsequent scans use
    the same image inventory and control posture unless the user explicitly
    changes the profile.
    """
    images = list(image_inventory)
    controls: dict[str, Any] = {}
    scenario: dict[str, Any] = {}

    try:
        generated = ScenarioGenerator().generate_scenario(
            size=org_size,
            reach=org_reach,
            industry=industry,
            environment_type=environment,
            output_format="json",
        )
        if isinstance(generated, dict):
            scenario = generated
            raw_controls = generated.get("security_controls", {})
            controls = raw_controls if isinstance(raw_controls, dict) else {}
            if not images:
                images = [
                    str(service["image"])
                    for service in generated.get("services", [])
                    if isinstance(service, dict) and service.get("image")
                ]
    except Exception as exc:
        logger.warning("Scenario snapshot generation failed: %s", exc)

    if not controls:
        controls = _fallback_controls(security_maturity)

    return ProfileSnapshot(
        image_inventory=images,
        controls_snapshot=_normalise_controls(controls),
        scenario_snapshot=scenario,
    )
