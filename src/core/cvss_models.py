"""Pydantic models for CVSS and EPSS data validation."""

from pydantic import BaseModel, Field


class CVSSv31(BaseModel):
    """CVSS v3.1 metrics."""

    baseScore: float = Field(ge=0.0, le=10.0, description="CVSS base score (0-10)")
    baseSeverity: str = Field(
        description="Base severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)",
    )
    vectorString: str = Field(description="CVSS vector string")
    attackVector: str | None = Field(None, description="Attack Vector (N, A, L, P)")
    attackComplexity: str | None = Field(None, description="Attack Complexity (L, H)")
    privilegesRequired: str | None = Field(
        None,
        description="Privileges Required (N, L, H)",
    )
    userInteraction: str | None = Field(None, description="User Interaction (N, R)")
    scope: str | None = Field(None, description="Scope (U, C)")
    confidentialityImpact: str | None = Field(
        None,
        description="Confidentiality Impact (N, L, H)",
    )
    integrityImpact: str | None = Field(None, description="Integrity Impact (N, L, H)")
    availabilityImpact: str | None = Field(
        None,
        description="Availability Impact (N, L, H)",
    )
    version: str | None = Field(None, description="CVSS version")

    class Config:
        """Pydantic config."""

        extra = "allow"  # Allow extra fields


class CVSSv30(BaseModel):
    """CVSS v3.0 metrics."""

    baseScore: float = Field(ge=0.0, le=10.0, description="CVSS base score (0-10)")
    baseSeverity: str = Field(
        description="Base severity (CRITICAL, HIGH, MEDIUM, LOW, NONE)",
    )
    vectorString: str = Field(description="CVSS vector string")
    attackVector: str | None = Field(None, description="Attack Vector (N, A, L, P)")
    attackComplexity: str | None = Field(None, description="Attack Complexity (L, H)")
    privilegesRequired: str | None = Field(
        None,
        description="Privileges Required (N, L, H)",
    )
    userInteraction: str | None = Field(None, description="User Interaction (N, R)")
    scope: str | None = Field(None, description="Scope (U, C)")
    confidentialityImpact: str | None = Field(
        None,
        description="Confidentiality Impact (N, L, H)",
    )
    integrityImpact: str | None = Field(None, description="Integrity Impact (N, L, H)")
    availabilityImpact: str | None = Field(
        None,
        description="Availability Impact (N, L, H)",
    )
    version: str | None = Field(None, description="CVSS version")

    class Config:
        """Pydantic config."""

        extra = "allow"


class CVSSv20(BaseModel):
    """CVSS v2.0 metrics."""

    baseScore: float = Field(ge=0.0, le=10.0, description="CVSS base score (0-10)")
    baseSeverity: str | None = Field(
        None,
        description="Base severity (HIGH, MEDIUM, LOW)",
    )
    vectorString: str = Field(description="CVSS vector string")
    accessVector: str | None = Field(None, description="Access Vector (L, A, N)")
    accessComplexity: str | None = Field(
        None,
        description="Access Complexity (H, M, L)",
    )
    authentication: str | None = Field(None, description="Authentication (M, S, N)")
    confidentialityImpact: str | None = Field(
        None,
        description="Confidentiality Impact (N, P, C)",
    )
    integrityImpact: str | None = Field(None, description="Integrity Impact (N, P, C)")
    availabilityImpact: str | None = Field(
        None,
        description="Availability Impact (N, P, C)",
    )
    version: str | None = Field(None, description="CVSS version")

    class Config:
        """Pydantic config."""

        extra = "allow"


class CVSSv40(BaseModel):
    """CVSS v4.0 metrics."""

    baseScore: float = Field(ge=0.0, le=10.0, description="CVSS base score (0-10)")
    baseSeverity: str = Field(description="Base severity")
    vectorString: str = Field(description="CVSS vector string")
    # v4.0 has different metrics, but we'll keep it flexible
    version: str | None = Field(None, description="CVSS version")

    class Config:
        """Pydantic config."""

        extra = "allow"


class EPSSScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) score."""

    score: float = Field(ge=0.0, le=1.0, description="EPSS score (0-1 probability)")
    percentile: float | None = Field(
        None,
        ge=0.0,
        le=100.0,
        description="EPSS percentile",
    )
    date: str | None = Field(None, description="Date of EPSS score")

    class Config:
        """Pydantic config."""

        extra = "allow"


class CVEVulnerability(BaseModel):
    """Complete CVE vulnerability record with CVSS and EPSS."""

    cve_id: str = Field(description="CVE identifier")
    description: str | None = Field(None, description="Vulnerability description")
    cwe_id: str | None = Field(None, description="CWE identifier")
    published_date: str | None = Field(None, description="Publication date")
    last_modified_date: str | None = Field(None, description="Last modified date")
    cvss_v4_0: CVSSv40 | None = Field(None, description="CVSS v4.0 metrics")
    cvss_v3_1: CVSSv31 | None = Field(None, description="CVSS v3.1 metrics")
    cvss_v3_0: CVSSv30 | None = Field(None, description="CVSS v3.0 metrics")
    cvss_v2_0: CVSSv20 | None = Field(None, description="CVSS v2.0 metrics")
    epss: EPSSScore | None = Field(None, description="EPSS score")
    is_kev: bool = Field(
        False,
        description="Is in Known Exploited Vulnerabilities catalog",
    )

    class Config:
        """Pydantic config."""

        extra = "allow"

    @property
    def primary_cvss_score(self) -> float | None:
        """Get primary CVSS score (prefer v4.0 > v3.1 > v3.0 > v2.0)."""
        if self.cvss_v4_0:
            return self.cvss_v4_0.baseScore
        if self.cvss_v3_1:
            return self.cvss_v3_1.baseScore
        if self.cvss_v3_0:
            return self.cvss_v3_0.baseScore
        if self.cvss_v2_0:
            return self.cvss_v2_0.baseScore
        return None

    @property
    def primary_cvss_vector(self) -> str | None:
        """Get primary CVSS vector (prefer v4.0 > v3.1 > v3.0 > v2.0)."""
        if self.cvss_v4_0:
            return self.cvss_v4_0.vectorString
        if self.cvss_v3_1:
            return self.cvss_v3_1.vectorString
        if self.cvss_v3_0:
            return self.cvss_v3_0.vectorString
        if self.cvss_v2_0:
            return self.cvss_v2_0.vectorString
        return None

    @property
    def epss_score(self) -> float:
        """Get EPSS score (0-1)."""
        return self.epss.score if self.epss else 0.0
