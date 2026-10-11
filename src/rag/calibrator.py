"""Threat parameter calibration via LLM reasoning over retrieved context.

Takes retrieved threat intelligence passages and uses the local LLM
to extract structured parameter estimates with source citations.
Outputs YAML provenance files per (finding, context, parameter).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import requests
from ruamel.yaml import YAML

from src.rag.config import RAGConfig
from src.rag.retriever import ThreatIntelRetriever

logger = logging.getLogger(__name__)

_NUMERIC_RE = re.compile(r"[-+]?\d*\.?\d+")
_PARAMETER_BOUNDS = {
    "reachability": (0.0, 1.0),
    "detectability": (0.0, 1.0),
    "exploit_maturity": (0.5, 1.5),
}


def _parameter_bounds(parameter: str) -> tuple[float, float]:
    """Return the valid numeric range for a calibrated parameter."""
    return _PARAMETER_BOUNDS.get(parameter, (0.0, 1.0))


def _safe_float(value: Any) -> float:
    """Convert a value to float, extracting the first number from strings.

    Handles LLM quirks like "0.05-0.15" (takes first number),
    "~0.3", "approximately 0.5", or string-wrapped floats.

    Args:
        value: Raw value from parsed JSON.

    Returns:
        Extracted float value.

    Raises:
        ValueError: If no numeric value can be extracted.
    """
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    match = _NUMERIC_RE.search(s)
    if match:
        return float(match.group())
    msg = f"Cannot extract float from: {value!r}"
    raise ValueError(msg)


# Findings from the APPSEC report — defines the calibration targets
FINDINGS: list[dict[str, str]] = [
    {
        "id": "F1",
        "cwe": "CWE-297",
        "vulnerability_type": "inverted TLS default (TLS verification disabled by default)",
        "description": "CLI flag defaults to TLS off; MITM on registry connections",
    },
    {
        "id": "F2",
        "cwe": "CWE-78",
        "vulnerability_type": "configuration injection chain leading to OS command injection (RCE)",
        "description": "extra='allow' in pydantic-settings + grype_binary_path in subprocess.run",
    },
    {
        "id": "F3",
        "cwe": "CWE-22",
        "vulnerability_type": "path traversal via unsanitized output file path",
        "description": "CLI --output argument passed directly to file write without validation",
    },
    {
        "id": "F4",
        "cwe": "CWE-918",
        "vulnerability_type": "server-side request forgery (SSRF) via unvalidated registry URL",
        "description": "registry_url interpolated into HTTP requests without scheme/hostname validation",
    },
    {
        "id": "F5",
        "cwe": "CWE-79",
        "vulnerability_type": "cross-site scripting via Jinja2 |safe filter on external data",
        "description": "Jinja2 |safe filter on plot variables derived from CVE descriptions",
    },
]

CONTEXTS: list[dict[str, str]] = [
    {"name": "Local Developer Workstation", "short": "A"},
    {"name": "Shared CI/CD Pipeline (Build-Only)", "short": "B"},
    {"name": "CI/CD to Staging K8s", "short": "C"},
    {"name": "CI/CD to Production K8s (Single-Tenant)", "short": "D"},
    {"name": "CI/CD to Production K8s (Multi-Tenant)", "short": "E"},
]

PARAMETERS: list[str] = ["reachability", "detectability", "exploit_maturity"]


@dataclass
class ParameterEstimate:
    """Structured output from the LLM calibration.

    Attributes:
        finding_id: Finding identifier (F1-F5).
        context: Deployment context short name (A-E).
        parameter: Parameter name.
        tri_min: Triangular distribution minimum.
        tri_mode: Triangular distribution mode (most likely).
        tri_max: Triangular distribution maximum.
        expected_value: Expected value of the triangular distribution.
        sources: List of source citations supporting the estimate.
        reasoning: LLM's reasoning chain for the estimate.
        confidence: Self-assessed confidence (low/moderate/high).
        raw_statistics: Extracted raw statistics from sources.
    """

    finding_id: str
    context: str
    parameter: str
    tri_min: float
    tri_mode: float
    tri_max: float
    expected_value: float
    sources: list[str] = field(default_factory=list)
    reasoning: str = ""
    confidence: str = "low"
    raw_statistics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for YAML serialization."""
        return {
            "finding_id": self.finding_id,
            "context": self.context,
            "parameter": self.parameter,
            "distribution": {
                "type": "triangular",
                "min": self.tri_min,
                "mode": self.tri_mode,
                "max": self.tri_max,
                "expected_value": self.expected_value,
            },
            "provenance": {
                "sources": self.sources,
                "raw_statistics": self.raw_statistics,
                "reasoning": self.reasoning,
                "confidence": self.confidence,
            },
        }


SYSTEM_PROMPT = """\
You are a security risk analyst calibrating threat model parameters from \
empirical threat intelligence data. Your task is to extract specific \
numeric estimates from the provided source passages.

RULES:
1. Only use information explicitly stated in the provided passages.
2. If passages don't contain relevant data, say so — do NOT fabricate.
3. Always cite which source passage supports each claim.
4. Express uncertainty honestly. If data is from a different domain, say so.
5. Output MUST be valid JSON matching the schema below.

OUTPUT SCHEMA:
{
  "tri_min": <float 0-1>,
  "tri_mode": <float 0-1>,
  "tri_max": <float 0-1>,
  "sources": ["Source 1 description", "Source 2 description"],
  "raw_statistics": ["15% of breaches involved X (DBIR 2024, p.12)"],
  "reasoning": "Step-by-step reasoning from raw statistics to parameter estimate",
  "confidence": "low|moderate|high",
  "data_gaps": "What additional data would improve this estimate"
}
"""


def _build_user_prompt(
    parameter: str,
    finding: dict[str, str],
    context: dict[str, str],
    retrieved_context: str,
) -> str:
    """Build the user prompt for a specific calibration query.

    Args:
        parameter: Parameter name (reachability/detectability/exploit_maturity).
        finding: Finding metadata dict.
        context: Context metadata dict.
        retrieved_context: Formatted retrieved passages.

    Returns:
        User prompt string.
    """
    param_definitions = {
        "reachability": (
            "REACHABILITY: The conditional probability that, given the flaw's "
            "intrinsic properties, the specific deployment configuration in this "
            "context actually exposes the code path to an attacker. "
            "Range: 0.0 (unreachable) to 1.0 (certainly reachable). "
            "This is NOT the same as CVSS Attack Vector — it measures how likely "
            "the specific deployment makes the theoretical attack path real."
        ),
        "detectability": (
            "DETECTABILITY: The probability that an exploitation attempt will be "
            "detected by monitoring, logging, or human observation in this context. "
            "Range: 0.0 (undetectable) to 1.0 (certainly detected). "
            "Consider dwell time data, SOC coverage, and monitoring maturity."
        ),
        "exploit_maturity": (
            "EXPLOIT MATURITY: A multiplier reflecting how mature and available "
            "exploit tooling is for this vulnerability class. "
            "Range: 0.5 (no known exploitation) to 1.5 (actively exploited with "
            "commodity tools). Mode 0.7 = unreported, 1.0 = PoC available, "
            "1.3 = actively exploited."
        ),
    }

    return f"""\
TASK: Estimate the {parameter.upper()} parameter for the following scenario.

PARAMETER DEFINITION:
{param_definitions[parameter]}

FINDING: {finding["id"]} — {finding["cwe"]}
  Type: {finding["vulnerability_type"]}
  Description: {finding["description"]}

DEPLOYMENT CONTEXT: {context["short"]} — {context["name"]}

RETRIEVED THREAT INTELLIGENCE:
{retrieved_context}

Based ONLY on the retrieved passages above, estimate the triangular distribution \
parameters (min, mode, max) for {parameter} in this scenario. \
If the passages don't contain directly relevant data, use the closest available \
data and clearly state the extrapolation in your reasoning.

Respond with valid JSON only, no markdown fences.
"""


class ThreatCalibrator:
    """Orchestrates the full calibration pipeline.

    For each (finding, context, parameter) triple:
    1. Builds a targeted retrieval query
    2. Retrieves relevant passages from ChromaDB
    3. Sends context + prompt to local LLM
    4. Parses structured output
    5. Writes YAML provenance file

    Args:
        config: RAG configuration instance.
    """

    def __init__(self, config: RAGConfig | None = None) -> None:
        self.config = config or RAGConfig()
        self.retriever = ThreatIntelRetriever(self.config)
        self._yaml = YAML()
        self._yaml.default_flow_style = False

    def _load_existing(self) -> dict[tuple[str, str, str], ParameterEstimate]:
        """Load existing provenance file and return keyed estimates.

        Returns:
            Dict keyed by (finding_id, context, parameter) → ParameterEstimate.
        """
        provenance_path = self.config.output_dir / "parameter_provenance.yaml"
        if not provenance_path.exists():
            return {}

        with open(provenance_path) as f:
            data = self._yaml.load(f)

        existing: dict[tuple[str, str, str], ParameterEstimate] = {}
        for entry in data.get("estimates", []):
            dist = entry.get("distribution", {})
            prov = entry.get("provenance", {})
            parameter = entry["parameter"]
            lower, upper = _parameter_bounds(parameter)
            tri_min = min(upper, max(lower, float(dist.get("min", lower))))
            tri_mode = min(upper, max(lower, float(dist.get("mode", lower))))
            tri_max = min(upper, max(lower, float(dist.get("max", lower))))
            est = ParameterEstimate(
                finding_id=entry["finding_id"],
                context=entry["context"],
                parameter=entry["parameter"],
                tri_min=tri_min,
                tri_mode=tri_mode,
                tri_max=tri_max,
                expected_value=(tri_min + tri_mode + tri_max) / 3.0,
                sources=prov.get("sources", []),
                reasoning=prov.get("reasoning", ""),
                confidence=prov.get("confidence", "low"),
                raw_statistics=prov.get("raw_statistics", []),
            )
            key = (est.finding_id, est.context, est.parameter)
            existing[key] = est
        logger.info(
            "Loaded %d existing estimates from %s", len(existing), provenance_path
        )
        return existing

    def calibrate_all(
        self,
        findings: list[dict[str, str]] | None = None,
        contexts: list[dict[str, str]] | None = None,
        parameters: list[str] | None = None,
        *,
        retry_failed: bool = False,
    ) -> list[ParameterEstimate]:
        """Run calibration for all (finding, context, parameter) triples.

        Args:
            findings: Override default findings list.
            contexts: Override default contexts list.
            parameters: Override default parameter list.
            retry_failed: If True, load existing results, skip succeeded
                entries, and only re-run failed or missing ones. Results are
                merged into the existing provenance file.

        Returns:
            List of all parameter estimates (including carried-over ones).
        """
        findings = findings or FINDINGS
        contexts = contexts or CONTEXTS
        parameters = parameters or PARAMETERS

        # Load existing results for merge when retrying
        existing: dict[tuple[str, str, str], ParameterEstimate] = {}
        if retry_failed:
            existing = self._load_existing()

        total = len(findings) * len(contexts) * len(parameters)
        logger.info(
            "Starting calibration: %d findings × %d contexts × %d parameters = %d queries",
            len(findings),
            len(contexts),
            len(parameters),
            total,
        )

        estimates: list[ParameterEstimate] = []
        skipped = 0
        completed = 0

        for finding in findings:
            for context in contexts:
                for parameter in parameters:
                    completed += 1
                    key = (finding["id"], context["short"], parameter)

                    # In retry mode, skip already-succeeded estimates
                    if retry_failed and key in existing:
                        prev = existing[key]
                        if prev.confidence != "failed":
                            estimates.append(prev)
                            skipped += 1
                            continue

                    logger.info(
                        "[%d/%d] %s / Context %s / %s%s",
                        completed,
                        total,
                        finding["id"],
                        context["short"],
                        parameter,
                        " (retry)" if retry_failed and key in existing else "",
                    )

                    try:
                        estimate = self._calibrate_single(
                            finding,
                            context,
                            parameter,
                        )
                        estimates.append(estimate)
                    except Exception:
                        logger.exception(
                            "Failed: %s / %s / %s",
                            finding["id"],
                            context["short"],
                            parameter,
                        )

        # Write consolidated output
        self._write_output(estimates)
        new_count = len(estimates) - skipped
        logger.info(
            "Calibration complete: %d total estimates (%d new, %d carried over)",
            len(estimates),
            new_count,
            skipped,
        )
        return estimates

    def _calibrate_single(
        self,
        finding: dict[str, str],
        context: dict[str, str],
        parameter: str,
    ) -> ParameterEstimate:
        """Calibrate a single (finding, context, parameter) triple.

        Args:
            finding: Finding metadata.
            context: Context metadata.
            parameter: Parameter name.

        Returns:
            Structured parameter estimate.
        """
        # Step 1: Build retrieval query
        query = self.retriever.build_calibration_query(
            parameter=parameter,
            finding_id=finding["id"],
            context_name=context["name"],
            cwe=finding["cwe"],
            vulnerability_type=finding["vulnerability_type"],
        )

        # Step 2: Retrieve relevant passages
        chunks = self.retriever.retrieve(query)
        retrieved_context = self.retriever.format_context(chunks)

        # Step 3: Build LLM prompt
        user_prompt = _build_user_prompt(
            parameter,
            finding,
            context,
            retrieved_context,
        )

        # Step 4: Call local LLM
        llm_response = self._call_llm(user_prompt)

        # Step 5: Parse response
        return self._parse_response(
            llm_response,
            finding["id"],
            context["short"],
            parameter,
        )

    def _call_llm(self, user_prompt: str) -> str:
        """Call the local LLM via OpenAI-compatible API.

        Retries on read timeouts up to ``config.llm_retries`` times,
        doubling the timeout on each attempt.

        Args:
            user_prompt: The user message content.

        Returns:
            Raw LLM response text.

        Raises:
            ConnectionError: If the LLM server is unreachable.
            RuntimeError: If the LLM returns an error or all retries exhausted.
        """
        url = f"{self.config.llm_base_url}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.config.llm_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.config.llm_temperature,
            "max_tokens": self.config.llm_max_tokens,
        }

        max_attempts = 1 + self.config.llm_retries
        timeout = self.config.llm_timeout

        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(url, json=payload, timeout=timeout)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
            except requests.ConnectionError as exc:
                msg = (
                    f"Cannot connect to LLM at {self.config.llm_base_url}. "
                    "Is LM Studio running?"
                )
                raise ConnectionError(msg) from exc
            except requests.exceptions.ReadTimeout:
                if attempt < max_attempts:
                    logger.warning(
                        "LLM read timeout after %ds (attempt %d/%d), retrying with %ds...",
                        timeout,
                        attempt,
                        max_attempts,
                        timeout * 2,
                    )
                    timeout *= 2
                else:
                    msg = (
                        f"LLM read timeout after {timeout}s "
                        f"({max_attempts} attempt(s) exhausted)"
                    )
                    raise RuntimeError(msg) from None
            except requests.HTTPError as exc:
                error_response = exc.response
                status_code = (
                    error_response.status_code
                    if error_response is not None
                    else "unknown"
                )
                response_text = (
                    error_response.text if error_response is not None else ""
                )
                msg = f"LLM API error: {status_code} — {response_text}"
                raise RuntimeError(msg) from exc
        msg = "Unreachable: retry loop exited without return or raise"
        raise RuntimeError(msg)

    def _parse_response(
        self,
        raw_response: str,
        finding_id: str,
        context_short: str,
        parameter: str,
    ) -> ParameterEstimate:
        """Parse the LLM JSON response into a ParameterEstimate.

        Handles common LLM output quirks: markdown fences, trailing
        text after JSON, etc.

        Args:
            raw_response: Raw LLM output text.
            finding_id: Finding ID for the estimate.
            context_short: Context short name.
            parameter: Parameter name.

        Returns:
            Parsed ParameterEstimate.
        """
        # Strip markdown code fences if present
        cleaned = raw_response.strip()
        if cleaned.startswith("```"):
            # Remove opening fence (possibly with language tag)
            first_newline = cleaned.index("\n")
            cleaned = cleaned[first_newline + 1 :]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning(
                "Failed to parse LLM JSON for %s/%s/%s. Raw: %s",
                finding_id,
                context_short,
                parameter,
                raw_response[:200],
            )
            # Return a low-confidence fallback
            return ParameterEstimate(
                finding_id=finding_id,
                context=context_short,
                parameter=parameter,
                tri_min=0.0,
                tri_mode=0.0,
                tri_max=0.0,
                expected_value=0.0,
                reasoning=f"PARSE FAILURE. Raw response: {raw_response[:500]}",
                confidence="failed",
            )

        try:
            tri_min = _safe_float(parsed.get("tri_min", 0.0))
            tri_mode = _safe_float(parsed.get("tri_mode", 0.0))
            tri_max = _safe_float(parsed.get("tri_max", 0.0))
        except ValueError:
            logger.warning(
                "Unparsable tri values for %s/%s/%s: min=%r mode=%r max=%r",
                finding_id,
                context_short,
                parameter,
                parsed.get("tri_min"),
                parsed.get("tri_mode"),
                parsed.get("tri_max"),
            )
            return ParameterEstimate(
                finding_id=finding_id,
                context=context_short,
                parameter=parameter,
                tri_min=0.0,
                tri_mode=0.0,
                tri_max=0.0,
                expected_value=0.0,
                reasoning=(
                    f"PARSE FAILURE (bad numeric values). "
                    f"Raw: {parsed.get('reasoning', raw_response[:500])}"
                ),
                confidence="failed",
            )

        lower, upper = _parameter_bounds(parameter)
        for label, val in [
            ("tri_min", tri_min),
            ("tri_mode", tri_mode),
            ("tri_max", tri_max),
        ]:
            if val < lower or val > upper:
                logger.warning(
                    "%s/%s/%s: %s=%.4f outside [%.1f,%.1f], clamping",
                    finding_id,
                    context_short,
                    parameter,
                    label,
                    val,
                    lower,
                    upper,
                )
        tri_min = min(upper, max(lower, tri_min))
        tri_mode = min(upper, max(lower, tri_mode))
        tri_max = min(upper, max(lower, tri_max))

        expected_value = (tri_min + tri_mode + tri_max) / 3.0

        return ParameterEstimate(
            finding_id=finding_id,
            context=context_short,
            parameter=parameter,
            tri_min=tri_min,
            tri_mode=tri_mode,
            tri_max=tri_max,
            expected_value=expected_value,
            sources=parsed.get("sources", []),
            reasoning=parsed.get("reasoning", ""),
            confidence=parsed.get("confidence", "low"),
            raw_statistics=parsed.get("raw_statistics", []),
        )

    def _write_output(self, estimates: list[ParameterEstimate]) -> None:
        """Write calibration results to YAML.

        Produces two files:
        - parameter_provenance.yaml: Full provenance with reasoning
        - parameter_summary.yaml: Just the distributions for quick reference

        Args:
            estimates: List of all parameter estimates.
        """
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        # Full provenance
        provenance_path = self.config.output_dir / "parameter_provenance.yaml"
        provenance_data = {
            "metadata": {
                "generated_by": "threat_calibration_rag",
                "total_estimates": len(estimates),
                "failed": sum(1 for e in estimates if e.confidence == "failed"),
            },
            "estimates": [e.to_dict() for e in estimates],
        }
        with open(provenance_path, "w") as f:
            self._yaml.dump(provenance_data, f)
        logger.info("Full provenance written to: %s", provenance_path)

        # Summary (just distributions, grouped by finding and context)
        summary_path = self.config.output_dir / "parameter_summary.yaml"
        summary: dict[str, dict[str, dict[str, Any]]] = {}
        for e in estimates:
            if e.confidence == "failed":
                continue
            key = f"{e.finding_id}_Context{e.context}"
            if key not in summary:
                summary[key] = {}
            summary[key][e.parameter] = {
                "tri": [e.tri_min, e.tri_mode, e.tri_max],
                "E": round(e.expected_value, 3),
                "confidence": e.confidence,
            }

        with open(summary_path, "w") as f:
            self._yaml.dump(summary, f)
        logger.info("Summary written to: %s", summary_path)
