"""
NLP-based vulnerability feature extraction from CVE descriptions.

Uses rule-based pattern matching to extract:
- Attack types (RCE, SQLi, XSS, etc.)
- Authentication requirements
- User interaction requirements
- Affected components
- Exploit conditions

These features can be used as weak signals in Bayesian risk assessment.
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AttackType(str, Enum):
    """Common vulnerability attack types."""

    REMOTE_CODE_EXECUTION = "remote_code_execution"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    XSS = "cross_site_scripting"
    XXE = "xml_external_entity"
    SSRF = "server_side_request_forgery"
    PATH_TRAVERSAL = "path_traversal"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"
    MEMORY_CORRUPTION = "memory_corruption"
    AUTH_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    DESERIALIZATION = "insecure_deserialization"
    CSRF = "cross_site_request_forgery"
    OPEN_REDIRECT = "open_redirect"
    RACE_CONDITION = "race_condition"
    CRYPTOGRAPHIC = "cryptographic_weakness"


# Regex patterns for attack type detection (case-insensitive)
ATTACK_TYPE_PATTERNS: dict[AttackType, list[str]] = {
    AttackType.REMOTE_CODE_EXECUTION: [
        r"remote code execution",
        r"\bRCE\b",
        r"execute arbitrary code",
        r"arbitrary code execution",
        r"code execution vulnerability",
        r"allows? (?:an )?attacker[s]? to execute",
    ],
    AttackType.SQL_INJECTION: [
        r"SQL injection",
        r"\bSQLi\b",
        r"SQL command injection",
        r"blind SQL",
    ],
    AttackType.COMMAND_INJECTION: [
        r"command injection",
        r"OS command injection",
        r"shell command injection",
        r"arbitrary command",
        r"execute (?:arbitrary )?(?:system |OS )?commands?",
    ],
    AttackType.XSS: [
        r"cross[- ]?site[- ]?scripting",
        r"\bXSS\b",
        r"reflected XSS",
        r"stored XSS",
        r"DOM[- ]?based XSS",
        r"script injection",
    ],
    AttackType.XXE: [
        r"XML external entity",
        r"\bXXE\b",
        r"XML injection",
    ],
    AttackType.SSRF: [
        r"server[- ]?side request forgery",
        r"\bSSRF\b",
    ],
    AttackType.PATH_TRAVERSAL: [
        r"path traversal",
        r"directory traversal",
        r"\.\.\/",
        r"\.\.\\\\",
        r"file inclusion",
        r"local file inclusion",
        r"\bLFI\b",
        r"remote file inclusion",
        r"\bRFI\b",
    ],
    AttackType.BUFFER_OVERFLOW: [
        r"buffer overflow",
        r"buffer over-?read",
        r"stack[- ]?based (?:buffer )?overflow",
        r"heap[- ]?based (?:buffer )?overflow",
        r"out[- ]?of[- ]?bounds (?:read|write)",
    ],
    AttackType.USE_AFTER_FREE: [
        r"use[- ]?after[- ]?free",
        r"\bUAF\b",
    ],
    AttackType.INTEGER_OVERFLOW: [
        r"integer overflow",
        r"integer underflow",
        r"integer wraparound",
    ],
    AttackType.MEMORY_CORRUPTION: [
        r"memory corruption",
        r"heap corruption",
        r"stack corruption",
        r"double[- ]?free",
        r"null pointer dereference",
    ],
    AttackType.AUTH_BYPASS: [
        r"authentication bypass",
        r"bypass authentication",
        r"auth(?:entication)? bypass",
        r"bypass (?:the )?auth(?:entication)?",
        r"improper authentication",
    ],
    AttackType.PRIVILEGE_ESCALATION: [
        r"privilege escalation",
        r"elevat(?:e|ion of) privileges?",
        r"gain (?:elevated |root |admin(?:istrator)? )?privileges?",
        r"local privilege escalation",
        r"\bLPE\b",
    ],
    AttackType.INFORMATION_DISCLOSURE: [
        r"information disclosure",
        r"sensitive information (?:disclosure|leak|exposure)",
        r"data (?:leak|exposure|disclosure)",
        r"(?:read|access) sensitive (?:data|information|files?)",
        r"expose sensitive",
        r"leak(?:s|ing)? (?:sensitive )?(?:data|information|memory)",
        r"read (?:arbitrary )?memory",
        r"obtain sensitive",
        r"disclose (?:sensitive )?information",
    ],
    AttackType.DENIAL_OF_SERVICE: [
        r"denial[- ]?of[- ]?service",
        r"\bDoS\b",
        r"\bDDoS\b",
        r"crash(?:es)? the (?:application|service|server)",
        r"cause(?:s)? (?:a )?(?:the )?(?:system |application |service |server )?(?:to )?crash",
        r"(?:application|service|server|system) (?:to )?crash",
        r"resource exhaustion",
        r"infinite loop",
        r"unresponsive",
        r"hang(?:s|ing)?",
    ],
    AttackType.DESERIALIZATION: [
        r"(?:insecure |unsafe )?deserialization",
        r"deserialize untrusted",
        r"object injection",
    ],
    AttackType.CSRF: [
        r"cross[- ]?site request forgery",
        r"\bCSRF\b",
        r"\bXSRF\b",
    ],
    AttackType.OPEN_REDIRECT: [
        r"open redirect",
        r"URL redirect",
        r"unvalidated redirect",
    ],
    AttackType.RACE_CONDITION: [
        r"race condition",
        r"time[- ]?of[- ]?check[- ]?time[- ]?of[- ]?use",
        r"\bTOCTOU\b",
    ],
    AttackType.CRYPTOGRAPHIC: [
        r"weak (?:crypto|encryption|cipher)",
        r"cryptographic (?:weakness|vulnerability|flaw)",
        r"insecure (?:crypto|encryption)",
        r"broken (?:crypto|encryption)",
    ],
}

# Context patterns for additional features
CONTEXT_PATTERNS = {
    "requires_authentication": [
        r"authenticated (?:user|attacker|adversary)",
        r"requires? authentication",
        r"must be authenticated",
        r"logged[- ]?in (?:user|attacker)",
        r"with valid credentials",
    ],
    "no_authentication_required": [
        r"unauthenticated (?:user|attacker|adversary|remote)",
        r"without authentication",
        r"no authentication (?:required|needed)",
        r"anonymous (?:user|attacker)",
        r"pre[- ]?auth(?:entication)?",
    ],
    "requires_user_interaction": [
        r"requires? user interaction",
        r"user interaction (?:is )?required",
        r"victim (?:to |must )(?:click|visit|open|download)",
        r"trick(?:ing)? (?:a |the )?(?:user|victim)",
        r"social engineering",
        r"phishing",
        r"malicious (?:link|URL|website|page|file)",
    ],
    "no_user_interaction": [
        r"no user interaction",
        r"without user interaction",
        r"automatically",
        r"wormable",
    ],
    "default_configuration": [
        r"default (?:configuration|settings?|install(?:ation)?)",
        r"out[- ]?of[- ]?the[- ]?box",
        r"factory (?:default|settings?)",
    ],
    "network_accessible": [
        r"remote attacker",
        r"remotely exploitable",
        r"over the network",
        r"network[- ]?accessible",
        r"via (?:the )?(?:network|internet)",
    ],
    "local_access_required": [
        r"local attacker",
        r"local access",
        r"locally",
        r"physical access",
    ],
}

# Impact patterns
IMPACT_PATTERNS = {
    "confidentiality": [
        r"read (?:sensitive |arbitrary )?(?:data|files?|memory)",
        r"information (?:disclosure|leak)",
        r"expose (?:sensitive )?(?:data|information)",
        r"access (?:to )?(?:sensitive |confidential )?(?:data|information)",
    ],
    "integrity": [
        r"modify (?:data|files?|configuration)",
        r"write (?:arbitrary )?(?:data|files?)",
        r"tamper",
        r"inject",
        r"overwrite",
    ],
    "availability": [
        r"denial[- ]?of[- ]?service",
        r"crash",
        r"hang",
        r"resource exhaustion",
        r"infinite loop",
        r"unresponsive",
    ],
}


@dataclass
class NLPVulnFeatures:
    """
    Extracted vulnerability features from description.

    Attributes:
        attack_types: List of detected attack types with confidence
        requires_auth: Whether authentication is required (None if unknown)
        requires_user_interaction: Whether user interaction needed (None if unknown)
        is_network_accessible: Whether remotely exploitable (None if unknown)
        affects_default_config: Whether affects default configuration
        impacts: Detected CIA impacts
        mentioned_components: Software/components mentioned
        confidence: Overall extraction confidence (0-1)
        raw_matches: Raw pattern matches for debugging
    """

    attack_types: list[tuple[AttackType, float]] = field(default_factory=list)
    requires_auth: bool | None = None
    requires_user_interaction: bool | None = None
    is_network_accessible: bool | None = None
    affects_default_config: bool = False
    impacts: dict[str, bool] = field(default_factory=dict)
    mentioned_components: list[str] = field(default_factory=list)
    confidence: float = 0.0
    raw_matches: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for DataFrame storage."""
        return {
            "nlp_attack_types": [at.value for at, _ in self.attack_types],
            "nlp_primary_attack": (
                self.attack_types[0][0].value if self.attack_types else None
            ),
            "nlp_requires_auth": self.requires_auth,
            "nlp_requires_user_interaction": self.requires_user_interaction,
            "nlp_network_accessible": self.is_network_accessible,
            "nlp_default_config": self.affects_default_config,
            "nlp_impact_confidentiality": self.impacts.get("confidentiality", False),
            "nlp_impact_integrity": self.impacts.get("integrity", False),
            "nlp_impact_availability": self.impacts.get("availability", False),
            "nlp_confidence": self.confidence,
        }

    @property
    def primary_attack_type(self) -> AttackType | None:
        """Get the highest confidence attack type."""
        if self.attack_types:
            return self.attack_types[0][0]
        return None


class VulnDescriptionExtractor:
    """
    Extract vulnerability features from CVE descriptions using regex patterns.

    This is a rule-based approach optimized for speed and interpretability.
    """

    def __init__(self):
        """Initialize the extractor with compiled regex patterns."""
        # Compile all patterns for efficiency
        self._attack_patterns: dict[AttackType, list[re.Pattern]] = {}
        for attack_type, patterns in ATTACK_TYPE_PATTERNS.items():
            self._attack_patterns[attack_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        self._context_patterns: dict[str, list[re.Pattern]] = {}
        for context, patterns in CONTEXT_PATTERNS.items():
            self._context_patterns[context] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        self._impact_patterns: dict[str, list[re.Pattern]] = {}
        for impact, patterns in IMPACT_PATTERNS.items():
            self._impact_patterns[impact] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def extract(self, description: str | None) -> NLPVulnFeatures:
        """
        Extract vulnerability features from a CVE description.

        Args:
            description: CVE description text

        Returns:
            NLPVulnFeatures with extracted information
        """
        if not description or not isinstance(description, str):
            return NLPVulnFeatures(confidence=0.0)

        description = description.strip()
        if len(description) < 10:
            return NLPVulnFeatures(confidence=0.0)

        features = NLPVulnFeatures()
        features.raw_matches = {}

        # Extract attack types
        attack_matches: list[tuple[AttackType, float, str]] = []
        for attack_type, patterns in self._attack_patterns.items():
            for pattern in patterns:
                match = pattern.search(description)
                if match:
                    # Higher confidence for longer/more specific matches
                    confidence = min(1.0, 0.7 + len(match.group()) / 100)
                    attack_matches.append((attack_type, confidence, match.group()))
                    break  # One match per attack type is enough

        # Sort by confidence and deduplicate
        attack_matches.sort(key=lambda x: x[1], reverse=True)
        seen_types = set()
        for attack_type, conf, match_text in attack_matches:
            if attack_type not in seen_types:
                features.attack_types.append((attack_type, conf))
                seen_types.add(attack_type)
                if "attack_types" not in features.raw_matches:
                    features.raw_matches["attack_types"] = []
                features.raw_matches["attack_types"].append(
                    f"{attack_type.value}: {match_text}"
                )

        # Extract authentication context
        auth_required = self._check_patterns(
            description, self._context_patterns.get("requires_authentication", [])
        )
        no_auth = self._check_patterns(
            description, self._context_patterns.get("no_authentication_required", [])
        )

        if auth_required and not no_auth:
            features.requires_auth = True
        elif no_auth and not auth_required:
            features.requires_auth = False
        # If both or neither, leave as None (unknown)

        # Extract user interaction context
        ui_required = self._check_patterns(
            description, self._context_patterns.get("requires_user_interaction", [])
        )
        no_ui = self._check_patterns(
            description, self._context_patterns.get("no_user_interaction", [])
        )

        if ui_required and not no_ui:
            features.requires_user_interaction = True
        elif no_ui and not ui_required:
            features.requires_user_interaction = False

        # Extract network accessibility
        network = self._check_patterns(
            description, self._context_patterns.get("network_accessible", [])
        )
        local = self._check_patterns(
            description, self._context_patterns.get("local_access_required", [])
        )

        if network and not local:
            features.is_network_accessible = True
        elif local and not network:
            features.is_network_accessible = False

        # Check default configuration
        features.affects_default_config = self._check_patterns(
            description, self._context_patterns.get("default_configuration", [])
        )

        # Extract impacts
        for impact_type, patterns in self._impact_patterns.items():
            features.impacts[impact_type] = self._check_patterns(description, patterns)

        # Calculate overall confidence
        features.confidence = self._calculate_confidence(features, description)

        return features

    def _check_patterns(self, text: str, patterns: list[re.Pattern]) -> bool:
        """Check if any pattern matches the text."""
        for pattern in patterns:
            if pattern.search(text):
                return True
        return False

    def _calculate_confidence(
        self, features: NLPVulnFeatures, description: str
    ) -> float:
        """
        Calculate overall extraction confidence.

        Higher confidence when:
        - More features extracted
        - Description is longer/more detailed
        - Attack types detected with high confidence
        """
        confidence = 0.0

        # Base confidence from description length
        desc_len = len(description)
        if desc_len > 500:
            confidence += 0.2
        elif desc_len > 200:
            confidence += 0.15
        elif desc_len > 100:
            confidence += 0.1

        # Confidence from attack type detection
        if features.attack_types:
            # Average confidence of detected attack types
            avg_attack_conf = sum(c for _, c in features.attack_types) / len(
                features.attack_types
            )
            confidence += avg_attack_conf * 0.4

        # Confidence from context extraction
        context_count = sum(
            [
                features.requires_auth is not None,
                features.requires_user_interaction is not None,
                features.is_network_accessible is not None,
                features.affects_default_config,
            ]
        )
        confidence += context_count * 0.1

        # Confidence from impact detection
        impact_count = sum(features.impacts.values())
        confidence += impact_count * 0.05

        return min(1.0, confidence)


# Likelihood ratios for NLP-extracted features
class NLPFeatureLR:
    """
    Likelihood ratios for NLP-extracted features.

    These are intentionally conservative (close to 1.0) since NLP extraction
    is less reliable than structured data like CVSS vectors.
    """

    # Attack type LRs - slight adjustments based on severity
    ATTACK_TYPE_LR: dict[AttackType, float] = {
        AttackType.REMOTE_CODE_EXECUTION: 1.3,  # RCE is serious
        AttackType.SQL_INJECTION: 1.2,
        AttackType.COMMAND_INJECTION: 1.25,
        AttackType.BUFFER_OVERFLOW: 1.2,
        AttackType.USE_AFTER_FREE: 1.2,
        AttackType.AUTH_BYPASS: 1.25,
        AttackType.PRIVILEGE_ESCALATION: 1.2,
        AttackType.DESERIALIZATION: 1.2,
        AttackType.XSS: 1.05,  # XSS is common but often lower impact
        AttackType.INFORMATION_DISCLOSURE: 1.0,  # Neutral
        AttackType.DENIAL_OF_SERVICE: 0.95,  # DoS often lower priority
        AttackType.OPEN_REDIRECT: 0.9,
    }

    # Context LRs
    NO_AUTH_REQUIRED = 1.15  # Easier to exploit
    AUTH_REQUIRED = 0.85  # Harder to exploit
    NO_USER_INTERACTION = 1.1  # Automated exploitation
    USER_INTERACTION_REQUIRED = 0.9  # Needs victim action
    NETWORK_ACCESSIBLE = 1.1  # Remote attack surface
    LOCAL_ACCESS_REQUIRED = 0.85  # Limited attack surface
    DEFAULT_CONFIG_AFFECTED = 1.15  # More systems vulnerable

    @classmethod
    def get_attack_type_lr(cls, attack_type: AttackType | None) -> float:
        """Get LR for an attack type."""
        if attack_type is None:
            return 1.0
        return cls.ATTACK_TYPE_LR.get(attack_type, 1.0)


def extract_nlp_features(description: str | None) -> NLPVulnFeatures:
    """
    Convenience function to extract NLP features from a description.

    Args:
        description: CVE description text

    Returns:
        NLPVulnFeatures with extracted information
    """
    extractor = VulnDescriptionExtractor()
    return extractor.extract(description)


def enrich_with_nlp_features(df, description_col: str = "description"):
    """
    Add NLP-extracted features to a DataFrame.

    Args:
        df: DataFrame with vulnerability data
        description_col: Column containing CVE descriptions

    Returns:
        DataFrame with added NLP feature columns
    """
    import pandas as pd

    if df.empty or description_col not in df.columns:
        logger.warning(f"Cannot extract NLP features: missing {description_col} column")
        return df

    logger.info(f"Extracting NLP features from {len(df)} descriptions...")

    extractor = VulnDescriptionExtractor()

    # Extract features for each row
    features_list = []
    for desc in df[description_col]:
        features = extractor.extract(desc)
        features_list.append(features.to_dict())

    # Convert to DataFrame and merge
    features_df = pd.DataFrame(features_list)

    # Add columns to original DataFrame
    for col in features_df.columns:
        df[col] = features_df[col].values

    # Log statistics
    attack_count = df["nlp_primary_attack"].notna().sum()
    auth_known = df["nlp_requires_auth"].notna().sum()
    avg_confidence = df["nlp_confidence"].mean()

    logger.info(
        f"NLP extraction complete: {attack_count} attack types detected, "
        f"{auth_known} auth requirements identified, "
        f"avg confidence: {avg_confidence:.2f}"
    )

    return df
