"""Tests for durable profile snapshot generation."""

from typing import Any

import pytest

import src.services.profiles as profile_service


class _FakeScenarioGenerator:
    def generate_scenario(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "metadata": kwargs,
            "services": [
                {"image": "nginx:1.25"},
                {"image": "postgres:16"},
                {"name": "no-image"},
            ],
            "security_controls": {
                "firewall_type": "stateful",
                "waf_type": "none",
                "ids_ips_type": "network",
                "endpoint_protection_type": "edr",
                "mfa_type": "totp",
                "siem_maturity": "centralized",
                "patch_management_quality": "weekly",
                "soc_24x7": True,
            },
        }


def test_profile_snapshot_uses_scenario_images_and_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generated scenario data becomes the durable profile starting point."""
    monkeypatch.setattr(
        profile_service, "ScenarioGenerator", lambda: _FakeScenarioGenerator()
    )

    snapshot = profile_service.build_profile_snapshot(
        org_size="mid",
        org_reach="global",
        industry="on-line-store",
        environment="prod",
        security_maturity=0.8,
        image_inventory=[],
    )

    assert snapshot.image_inventory == ["nginx:1.25", "postgres:16"]
    assert snapshot.controls_snapshot["firewall"] is True
    assert snapshot.controls_snapshot["waf"] is False
    assert snapshot.controls_snapshot["patch_management"] == "weekly"
    assert snapshot.scenario_snapshot["metadata"]["environment_type"] == "prod"


def test_profile_snapshot_falls_back_on_generator_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed scenario generation still produces deterministic controls."""

    class BrokenGenerator:
        def generate_scenario(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("generator unavailable")

    monkeypatch.setattr(profile_service, "ScenarioGenerator", lambda: BrokenGenerator())

    snapshot = profile_service.build_profile_snapshot(
        org_size="small",
        org_reach="local",
        industry="consulting",
        environment="dev",
        security_maturity=0.0,
        image_inventory=["app:latest"],
    )

    assert snapshot.image_inventory == ["app:latest"]
    assert snapshot.controls_snapshot["maturity_level"] == "initial"
    assert snapshot.controls_snapshot["patch_management"] == "quarterly"
    assert snapshot.scenario_snapshot == {}
