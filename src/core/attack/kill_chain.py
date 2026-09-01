from contextlib import suppress
from typing import Any

from pydantic import BaseModel

from src.core.models import KillChainResult, KillChainStage

# Hardcoded likelihood ratios for security controls.
_CONTROL_LRS: dict[str, float] = {
    "waf": 0.5,
    "ids_ips": 0.5,
    "mfa": 0.3,
    "edr_xdr": 0.5,
    "network_segmentation": 0.4,
    "flat_network": 1.2,
    "siem": 0.6,
    "dlp": 0.5,
    "encryption": 0.6,
    "backup": 0.5,
    "docker_good": 0.7,
    "docker_poor": 1.0,
}

# CWE IDs associated with remote code execution.
_RCE_CWEs = frozenset(
    {
        94,
        78,
        73,
        22,
        89,
        79,
        289,
        434,
        502,
        917,
        918,
        16,
        612,
        924,
    }
)

# CWE IDs associated with privilege escalation.
_PRIVESC_CWEs = frozenset(
    {
        269,
        250,
        1188,
        267,
        268,
        271,
        272,
        274,
        275,
        276,
        277,
        281,
        282,
        283,
        284,
        285,
        425,
        599,
        649,
        669,
        693,
        732,
        754,
    }
)

# Keywords indicating container escape potential.
_CONTAINER_ESCAPE_KEYWORDS = (
    "container escape",
    "container breakout",
    "privileged container",
    "docker socket",
    "namespace escape",
    "cgroup escape",
    "kernel exploit",
    "privilege escalation",
    "host filesystem",
    "pid namespace",
)


def _parse_cvss_vector(vector: str | None) -> dict[str, str]:
    """Parse a CVSS v3 vector string into a key-value mapping."""
    if not vector:
        return {}
    parts = vector.split("/")
    result: dict[str, str] = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            result[key] = value
    return result


def _extract_cwes(vuln: dict[str, Any]) -> set[int]:
    """Extract CWE identifiers from a vulnerability dict."""
    cwe_field = vuln.get("cwe_ids") or vuln.get("cwe") or vuln.get("cwes", [])
    if isinstance(cwe_field, str):
        cwe_field = [cwe_field]
    cwe_ints: set[int] = set()
    for cwe in cwe_field:
        cwe_str = str(cwe).replace("CWE-", "").strip()
        with suppress(ValueError):
            cwe_ints.add(int(cwe_str))
    return cwe_ints


def _odds_to_prob(odds: float) -> float:
    """Convert odds to probability, clamped to [0, 1]."""
    return min(max(odds / (1.0 + odds), 0.0), 1.0)


def _apply_lr(probability: float, lr: float) -> float:
    """Apply a likelihood ratio to a probability via odds space."""
    if probability <= 0.0:
        return 0.0
    if probability >= 1.0:
        return 1.0
    odds = probability / (1.0 - probability)
    return _odds_to_prob(odds * lr)


class KillChainCalculator:
    """Calculate kill chain stage probabilities for an application.

    Assesses the likelihood of an attacker progressing through each
    kill chain stage based on vulnerability characteristics and the
    deployed security controls.
    """

    def __init__(self) -> None:
        """Initialize the calculator. No external configuration loaded."""
        pass

    def _is_remote_code_execution(self, vuln: dict[str, Any]) -> bool:
        """Determine if a vulnerability enables remote code execution.

        Checks CVSS vector for network-accessible attacks with high
        impact, and matches CWE identifiers against known RCE categories.

        Args:
            vuln: Vulnerability dict containing CVSS vector, CWE IDs,
                and optionally a description.

        Returns:
            True if the vulnerability is classified as RCE-capable.
        """
        vector = _parse_cvss_vector(vuln.get("cvss_vector") or vuln.get("cvss3_vector"))
        av = vector.get("AV", "")
        conf_impact = vector.get("C", "")
        integ_impact = vector.get("I", "")
        avail_impact = vector.get("A", "")
        high_impact = any(v == "H" for v in (conf_impact, integ_impact, avail_impact))
        if av == "N" and high_impact:
            return True

        return bool(_extract_cwes(vuln) & _RCE_CWEs)

    def _is_privilege_escalation(self, vuln: dict[str, Any]) -> bool:
        """Determine if a vulnerability enables privilege escalation.

        Checks CVSS vector for low/no-privilege-requirement attacks
        with high integrity impact, and matches CWEs against privesc
        categories.

        Args:
            vuln: Vulnerability dict containing CVSS vector and CWE IDs.

        Returns:
            True if the vulnerability is classified as privilege escalation.
        """
        vector = _parse_cvss_vector(vuln.get("cvss_vector") or vuln.get("cvss3_vector"))
        pr = vector.get("PR", "")
        integ_impact = vector.get("I", "")
        if pr in ("L", "N") and integ_impact == "H":
            return True

        return bool(_extract_cwes(vuln) & _PRIVESC_CWEs)

    def _is_container_escape(self, vuln: dict[str, Any]) -> bool:
        """Determine if a vulnerability enables container escape.

        Scans the vulnerability description for keywords associated
        with container breakout techniques.

        Args:
            vuln: Vulnerability dict containing a description field.

        Returns:
            True if the description suggests container escape capability.
        """
        desc = (vuln.get("description") or "").lower()
        return any(keyword in desc for keyword in _CONTAINER_ESCAPE_KEYWORDS)

    def _calculate_initial_access(
        self,
        vulnerabilities: list[dict[str, Any]],
        security_controls: dict[str, bool],
    ) -> float:
        """Calculate the probability of successful initial access.

        Uses the maximum bayesian_risk_score or epss_score across
        vulnerabilities, then applies likelihood ratios for relevant
        security controls (WAF, IDS/IPS, MFA).

        Args:
            vulnerabilities: List of vulnerability dicts.
            security_controls: Dict mapping control names to boolean
                enabled flags.

        Returns:
            Probability value in [0, 1].
        """
        max_score = 0.0
        for vuln in vulnerabilities:
            for score_key in ("bayesian_risk_score", "epss_score", "epss"):
                score = vuln.get(score_key)
                if score is not None:
                    with suppress(ValueError, TypeError):
                        max_score = max(max_score, float(score))

        prob = max_score

        for control in ("waf", "ids_ips", "mfa"):
            if security_controls.get(control):
                prob = _apply_lr(prob, _CONTROL_LRS[control])

        return prob

    def _calculate_execution(
        self,
        vulnerabilities: list[dict[str, Any]],
        security_controls: dict[str, bool],
        docker_security_good: bool,
    ) -> float:
        """Calculate the probability of successful code execution.

        Starts from a base of 0.8, modified by Docker security posture,
        EDR/XDR presence, and WAF coverage.

        Args:
            vulnerabilities: List of vulnerability dicts.
            security_controls: Dict mapping control names to boolean flags.
            docker_security_good: Whether Docker security is well-configured.

        Returns:
            Probability value in [0, 1].
        """
        prob = 0.8

        docker_lr = (
            _CONTROL_LRS["docker_good"]
            if docker_security_good
            else _CONTROL_LRS["docker_poor"]
        )
        prob = _apply_lr(prob, docker_lr)

        if security_controls.get("edr_xdr"):
            prob = _apply_lr(prob, _CONTROL_LRS["edr_xdr"])

        if security_controls.get("waf"):
            prob = _apply_lr(prob, _CONTROL_LRS["waf"])

        return prob

    def _calculate_lateral_movement(
        self,
        vulnerabilities: list[dict[str, Any]],
        security_controls: dict[str, bool],
        docker_security_good: bool,
    ) -> float:
        """Calculate the probability of successful lateral movement.

        Starts from a base of 0.7, modified by network segmentation,
        Docker security, EDR/XDR, and SIEM capabilities.

        Args:
            vulnerabilities: List of vulnerability dicts.
            security_controls: Dict mapping control names to boolean flags.
            docker_security_good: Whether Docker security is well-configured.

        Returns:
            Probability value in [0, 1].
        """
        prob = 0.7

        if security_controls.get("network_segmentation"):
            prob = _apply_lr(prob, _CONTROL_LRS["network_segmentation"])
        elif security_controls.get("flat_network"):
            prob = _apply_lr(prob, _CONTROL_LRS["flat_network"])

        docker_lr = (
            _CONTROL_LRS["docker_good"]
            if docker_security_good
            else _CONTROL_LRS["docker_poor"]
        )
        prob = _apply_lr(prob, docker_lr)

        if security_controls.get("edr_xdr"):
            prob = _apply_lr(prob, _CONTROL_LRS["edr_xdr"])

        if security_controls.get("siem"):
            prob = _apply_lr(prob, _CONTROL_LRS["siem"])

        return prob

    def _calculate_objective(
        self,
        vulnerabilities: list[dict[str, Any]],
        security_controls: dict[str, bool],
    ) -> float:
        """Calculate the probability of achieving the attacker objective.

        Starts from a base of 0.9, modified by DLP, encryption,
        backup, and SIEM controls.

        Args:
            vulnerabilities: List of vulnerability dicts.
            security_controls: Dict mapping control names to boolean flags.

        Returns:
            Probability value in [0, 1].
        """
        prob = 0.9

        for control in ("dlp", "encryption", "backup", "siem"):
            if security_controls.get(control):
                prob = _apply_lr(prob, _CONTROL_LRS[control])

        return prob

    def _categorize_threat_level(self, overall: float) -> str:
        """Map an overall probability to a threat level label.

        Args:
            overall: End-to-end kill chain probability in [0, 1].

        Returns:
            One of 'critical', 'high', 'medium', or 'low'.
        """
        if overall >= 0.4:
            return "critical"
        if overall >= 0.2:
            return "high"
        if overall >= 0.1:
            return "medium"
        return "low"

    def _build_critical_path(
        self,
        probabilities: dict[KillChainStage, float],
    ) -> list[KillChainStage]:
        """Order kill chain stages by descending probability.

        Args:
            probabilities: Mapping from stage to its probability.

        Returns:
            List of stages sorted from most to least likely.
        """
        return sorted(probabilities, key=lambda s: probabilities[s], reverse=True)

    def calculate_kill_chain_probability(
        self,
        application: dict[str, Any] | BaseModel,
        vulnerabilities: list[dict[str, Any]],
        security_controls: dict[str, bool],
        docker_security_good: bool,
    ) -> KillChainResult:
        """Compute the full kill chain assessment for an application.

        Evaluates each kill chain stage probability, derives the
        end-to-end success probability as the product of stage
        probabilities, and identifies the most likely attack path.

        Args:
            application: Application template as a dict or pydantic model.
            vulnerabilities: List of vulnerability dicts to assess.
            security_controls: Dict mapping control names to boolean
                enabled flags.
            docker_security_good: Whether Docker security is well-configured.

        Returns:
            KillChainResult with per-stage probabilities, threat level,
            and critical path.
        """
        initial_access = self._calculate_initial_access(
            vulnerabilities, security_controls
        )
        execution = self._calculate_execution(
            vulnerabilities, security_controls, docker_security_good
        )
        lateral_movement = self._calculate_lateral_movement(
            vulnerabilities, security_controls, docker_security_good
        )
        objective = self._calculate_objective(vulnerabilities, security_controls)

        overall = initial_access * execution * lateral_movement * objective

        stage_probs: dict[KillChainStage, float] = {
            KillChainStage.INITIAL_ACCESS: initial_access,
            KillChainStage.EXECUTION: execution,
            KillChainStage.LATERAL_MOVEMENT: lateral_movement,
            KillChainStage.OBJECTIVE: objective,
        }

        rce_count = sum(1 for v in vulnerabilities if self._is_remote_code_execution(v))
        privesc_count = sum(
            1 for v in vulnerabilities if self._is_privilege_escalation(v)
        )
        container_escape_count = sum(
            1 for v in vulnerabilities if self._is_container_escape(v)
        )

        return KillChainResult(
            initial_access_probability=initial_access,
            execution_probability=execution,
            lateral_movement_probability=lateral_movement,
            objective_probability=objective,
            overall_probability=overall,
            threat_level=self._categorize_threat_level(overall),
            critical_path=self._build_critical_path(stage_probs),
            rce_vulnerabilities=rce_count,
            privesc_vulnerabilities=privesc_count,
            container_escape_vulnerabilities=container_escape_count,
        )


def calculate_application_kill_chain(
    application: dict[str, Any] | BaseModel,
    vulnerabilities: list[dict[str, Any]],
    security_controls: dict[str, bool],
    docker_security_good: bool = True,
) -> KillChainResult:
    """Convenience function to compute a kill chain assessment.

    Creates a KillChainCalculator instance and invokes
    calculate_kill_chain_probability in a single call.

    Args:
        application: Application template as a dict or pydantic model.
        vulnerabilities: List of vulnerability dicts to assess.
        security_controls: Dict mapping control names to boolean flags.
        docker_security_good: Whether Docker security is well-configured.
            Defaults to True.

    Returns:
        KillChainResult with the full assessment.
    """
    calculator = KillChainCalculator()
    return calculator.calculate_kill_chain_probability(
        application, vulnerabilities, security_controls, docker_security_good
    )
