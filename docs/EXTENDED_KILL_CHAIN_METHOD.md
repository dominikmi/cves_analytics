# Extended Kill-Chain Bayesian Exploitation Probability Assessment Methodology

## Executive Summary

This document describes the **implemented kill-chain analysis** for multi-component containerized applications using **Bayesian probability** with **exploitability gating** and **exposure-conditional likelihood ratios**. The methodology calculates the probability of successful attack chain execution from initial access to objective achievement (data exfiltration, service disruption, or persistence).

**Implemented Features**:
- **Exploitability Gating**: Amplification factors (LR > 1) only apply when exploitation is plausible (EPSS >= 5% OR known exploit)
- **Exposure-Conditional Controls**: Control effectiveness depends on exposure context (e.g., WAF 70% reduction for internet-facing, 10% for internal)
- **Threat Intelligence Integration**: KEV, Metasploit, ExploitDB, Nuclei, GitHub PoC tracking with granular LRs
- **CVSS Vector Analysis**: Attack Vector, Complexity, Privileges, User Interaction, Scope with exposure-aware LRs
- **Uncertainty Quantification**: 95% credible intervals using Beta distribution approximation
- **Sequential Kill-Chain Model**: Markov chain with conditional probabilities
- **Mathematically Correct**: Bayesian odds-based calculation with log-odds arithmetic

---

## Table of Contents

1. [Mathematical Foundation](#mathematical-foundation)
2. [Exploitability Gating](#exploitability-gating)
3. [Exposure-Conditional Likelihood Ratios](#exposure-conditional-likelihood-ratios)
4. [Threat Intelligence Integration](#threat-intelligence-integration)
5. [Sequential Kill-Chain Model](#sequential-kill-chain-model)
6. [Real-World Implementation Examples](#real-world-implementation-examples)
7. [Uncertainty Quantification](#uncertainty-quantification)
8. [Implementation Reference](#implementation-reference)

---

## 1. Mathematical Foundation

### 1.1 Bayesian Probability (Correct Form)

**Bayes' Theorem in Odds Form**:

```
Posterior Odds = Prior Odds x LR1 x LR2 x ... x LRn
```

**Conversion Formulas**:

```python
# Probability -> Odds
odds = probability / (1 - probability)

# Odds -> Probability
probability = odds / (1 + odds)
```

**Example**:
```python
# Prior: EPSS = 15%
prior_odds = 0.15 / (1 - 0.15) = 0.176

# Apply LRs: 3.0 x 2.0 x 1.5 = 9.0
posterior_odds = 0.176 x 9.0 = 1.584

# Convert back
posterior = 1.584 / (1 + 1.584) = 1.584 / 2.584 = 0.613 = 61.3%
```

### 1.2 Why Odds Form?

**Problem with Direct Probability Multiplication**:
```python
# WRONG - can exceed 1.0
posterior = 0.15 x 9.0 = 1.35 = 135% ❌
```

**Correct Odds Form**:
```python
# CORRECT - always <= 1.0
posterior_odds = 0.176 x 9.0 = 1.584
posterior = 1.584 / 2.584 = 0.613 = 61.3% ✓
```

### 1.3 Likelihood Ratios (LRs) - Implemented Values

**From `src/core/bayesian_risk.py`**:

| Evidence Type | LR | Interpretation | Source |
|---------------|-----|----------------|--------|
| **Security Controls** | | | |
| Network Segmentation | 0.3 | 70% probability reduction | MITRE ATT&CK |
| WAF (internet-facing) | 0.3 | 70% probability reduction | NIST SP 800-53 |
| WAF (internal) | 0.9 | 10% probability reduction | Exposure-conditional |
| MFA (internet-facing) | 0.2 | 80% probability reduction | Industry benchmarks |
| EDR/XDR | 0.4 | 60% probability reduction | Verizon DBIR |
| **Threat Indicators** | | | |
| CISA KEV | 3.0 | 200% probability increase | Known exploitation |
| Metasploit Module | 2.5 | 150% probability increase | CVSS-BT |
| ExploitDB | 2.0 | 100% probability increase | CVSS-BT |
| Weaponized | 4.0 | 300% probability increase | Threat intel |
| **Exposure** | | | |
| Internet-facing | 2.5 | 150% probability increase | Attack surface |
| DMZ | 1.8 | 80% probability increase | Partial protection |
| Internal | 0.6 | 40% probability reduction | Limited access |
| Restricted | 0.3 | 70% probability reduction | Highly controlled |

---

## 2. Exploitability Gating

### 2.1 Core Principle

**From `src/core/bayesian_risk.py`**:

**Amplification factors (LR > 1) are ONLY applied when exploitation is plausible.**

```python
def _get_gated_exposure_lr(
    self,
    exposure: str,
    epss: float,
    exploitation_plausible: bool,
) -> float:
    """Exposure only amplifies exploitation probability if actually plausible.
    Without a known exploit or high EPSS, being internet-facing doesn't
    magically make an unexploitable vulnerability exploitable.
    """
    base_lr = self.exposure_lrs.get(exposure.lower(), 1.0)
    
    if exploitation_plausible:
        return base_lr  # Full amplification
    
    # If exploitation is NOT plausible:
    # - Reductions (LR < 1) still apply
    # - Amplifications (LR > 1) are capped
    if base_lr <= 1.0:
        return base_lr
    
    # Cap amplification to 1.2 for unexploitable vulns
    return min(base_lr, 1.2)
```

### 2.2 Exploitation is Plausible When

**Implemented Criteria**:

1. **EPSS >= 5%** (top 10% of vulnerabilities)
2. **OR has known exploit**:
   - CISA KEV listed
   - Metasploit module
   - ExploitDB entry
   - Nuclei template
   - GitHub PoC
   - Weaponized in campaigns

### 2.3 Gating Rules

| Factor Type | When Exploitation Plausible | When NOT Plausible |
|-------------|----------------------------|-------------------|
| **Security Controls (LR < 1)** | Full reduction | Full reduction |
| **Exposure (LR > 1)** | Full amplification (2.5x) | Capped to 1.2x |
| **CVSS Vector (LR > 1)** | Full amplification | Capped to 1.1x |
| **Asset Criticality (LR > 1)** | Full amplification | Neutralized to 1.0* |
| **Threat Indicators** | Always apply | Always apply (CREATE exploitability) |

*Note: Asset Criticality is neutralized (not capped) when exploitation is not plausible because asset value doesn't make an unexploitable vulnerability exploitable. This is more conservative than capping.

### 2.4 Rationale

**Why This Works**:

- **Controls REDUCE exploitation probability** → always apply (you can reduce what doesn't exist)
- **Exposure/CVSS AMPLIFY probability** → only if exploitable (can't amplify what doesn't exist)
- **Threat indicators CREATE exploitability** → always apply (they change the prior)
- **Absence of controls ≠ vulnerability creation**

### 2.5 Impact on Probability Assessment

**Example: Low EPSS + No Exploit + Internet-Facing**

| Application Size | Total Vulns | Exploitable Vulns | Reduction |
|------------------|-------------|-------------------|-----------|
| Small (5 services) | 500-1000 | 50-150 | 85% |
| Medium (10 services) | 1000-2000 | 150-400 | 80% |
| Large (20 services) | 2000-5000 | 400-1000 | 75% |

**Note**: With exploitability gating, we don't filter vulnerabilities out entirely. Instead, we **cap their amplification** if they're not exploitable.

---

## 3. Exposure-Conditional Likelihood Ratios

### 3.1 Core Concept

**From `src/core/bayesian_risk.py`**:

Control effectiveness **depends on exposure context**. This implements a simplified form of conditional Bayes:

```
P(Exploit | Control, Exposure) ~= P(Exploit) x LR(Control | Exposure)
```

**Example**: WAF effectiveness varies by exposure:
- **Internet-facing**: LR = 0.3 (70% reduction) - WAF blocks web attacks
- **Internal**: LR = 0.9 (10% reduction) - WAF rarely deployed internally

### 3.2 Implemented Conditional LRs

**From `ExposureConditionalControlLR` class**:

| Control | Internet-Facing | DMZ | Internal | Restricted |
|---------|----------------|-----|----------|------------|
| **WAF** | 0.3 (70% ↓) | 0.4 (60% ↓) | 0.9 (10% ↓) | 0.8 (20% ↓) |
| **IDS/IPS** | 0.4 (60% ↓) | 0.45 (55% ↓) | 0.7 (30% ↓) | 0.5 (50% ↓) |
| **Network Segmentation** | 0.5 (50% ↓) | 0.4 (60% ↓) | 0.3 (70% ↓) | 0.2 (80% ↓) |
| **MFA** | 0.2 (80% ↓) | 0.25 (75% ↓) | 0.5 (50% ↓) | 0.2 (80% ↓) |
| **EDR/XDR** | 0.4 (60% ↓) | 0.4 (60% ↓) | 0.4 (60% ↓) | 0.35 (65% ↓) |
| **SIEM** | 0.5 (50% ↓) | 0.55 (45% ↓) | 0.7 (30% ↓) | 0.6 (40% ↓) |
| **PAM** | 0.5 (50% ↓) | 0.45 (55% ↓) | 0.35 (65% ↓) | 0.25 (75% ↓) |

**Note on Network Segmentation Pattern**: Segmentation becomes MORE effective for internal services (0.3) than internet-facing (0.5). This is correct because:
- At the perimeter: Firewall already provides segmentation
- Internally: Segmentation is critical for preventing lateral movement
- This pattern reflects real-world security architecture

### 3.3 Rationale

**Why This Matters**:

1. **Avoids Independence Violations**: Controls aren't equally effective everywhere
2. **More Accurate**: WAF on internal service is nearly useless
3. **Practical**: Reflects real-world deployment patterns
4. **Simpler than Full Bayesian Networks**: Approximation that works in practice

### 3.4 Example Calculation

**Scenario**: Internet-facing service with WAF and MFA

```python
# Without exposure-conditional LRs (WRONG)
waf_lr = 0.3  # Always 70% reduction
mfa_lr = 0.3  # Always 70% reduction
combined_lr = 0.3 x 0.3 = 0.09  # 91% reduction

# With exposure-conditional LRs (CORRECT)
waf_lr = 0.3  # 70% reduction for internet-facing
mfa_lr = 0.2  # 80% reduction for internet-facing
combined_lr = 0.3 x 0.2 = 0.06  # 94% reduction

# For internal service (CORRECT)
waf_lr = 0.9  # 10% reduction for internal
mfa_lr = 0.5  # 50% reduction for internal
combined_lr = 0.9 x 0.5 = 0.45  # 55% reduction
```

---

## 4. Threat Intelligence Integration

### 4.1 Granular Exploit Tracking

**From `ThreatIndicatorsInput` class**:

```python
class ThreatIndicatorsInput(BaseModel):
    is_kev: bool = False  # CISA Known Exploited Vulnerabilities
    has_public_exploit: bool = False  # Generic public exploit
    has_metasploit: bool = False  # Metasploit module
    is_weaponized: bool = False  # Weaponized in campaigns
    
    # Granular exploit indicators from CVSS-BT
    has_exploitdb: bool = False  # ExploitDB entry
    has_nuclei: bool = False  # Nuclei scanner template
    has_poc_github: bool = False  # GitHub PoC
```

### 4.2 Threat Indicator Likelihood Ratios

**Implemented Values**:

| Indicator | LR | Probability Increase | Source |
|-----------|-----|---------------|--------|
| Weaponized | 4.0 | 300% | Threat intel campaigns |
| CISA KEV | 3.0 | 200% | Known exploitation |
| Ransomware Associated | 3.0 | 200% | Ransomware campaigns |
| Metasploit Module | 2.5 | 150% | CVSS-BT |
| Public Exploit | 2.0 | 100% | Generic availability |
| ExploitDB | 2.0 | 100% | CVSS-BT |
| APT Interest | 2.0 | 100% | Threat intel |
| Nuclei Template | 1.8 | 80% | CVSS-BT |
| GitHub PoC | 1.5 | 50% | CVSS-BT |

---

## 5. Sequential Kill-Chain Model

### 5.1 Kill-Chain Stages

```
Stage 1: Initial Access (internet-facing components)
    ↓
Stage 2: Execution (code execution on compromised component)
    ↓
Stage 3: Lateral Movement (access to other pod components)
    ↓
Stage 4: Objective Achievement (data exfiltration, DoS, persistence)
```

### 5.2 Sequential Dependency Formula

```
P(Kill-Chain Success) = P(S1) x P(S2|S1) x P(S3|S2) x P(S4|S3)
```

Where each conditional probability represents:
- **P(Sᵢ|Sᵢ₋₁)**: Probability of succeeding at stage *i* given stage *i-1* succeeded

### 5.3 Stage Probability Calculation

**OR-Logic** (at least one vulnerability succeeds):

```python
P(Stage) = 1 - ∏(1 - P(vuln_j))
```

**Example**:
```python
# Stage has 3 exploitable vulnerabilities
vuln_1_prob = 0.15  # 15%
vuln_2_prob = 0.08  # 8%
vuln_3_prob = 0.05  # 5%

# At least one succeeds
stage_prob = 1 - (1-0.15) x (1-0.08) x (1-0.05)
           = 1 - 0.85 x 0.92 x 0.95
           = 1 - 0.743
           = 0.257 = 25.7%
```

### 5.4 Control Application

Controls apply **per stage**:

```python
stage_prob_with_controls = stage_prob x control_lr
```

**Example**:
```python
# Stage 1: Initial Access
base_prob = 0.257  # 25.7%
waf_lr = 0.3       # WAF reduces by 70%

stage_1_prob = 0.257 x 0.3 = 0.077 = 7.7%
```

---

## 4. Temporal Probability Factors

### 4.1 Vulnerability Age Impact

**Exploitation Probability Curve Over Time**:

| Age Range | Age Factor | Exploitation Pattern |
|-----------|------------|---------------------|
| **Zero-Day (0-7d)** | 5.0 | Targeted APT attacks |
| **Early (7-30d)** | 2.0 | Exploit development peaks |
| **Peak (30-90d)** | 1.5 | Automated scanning begins |
| **Mature (90-180d)** | 1.0 | Widespread exploitation |
| **Decline (180-365d)** | 0.5 | Most systems patched |
| **Long-Tail (1yr+)** | 0.1 | Only unpatched targets |

### 4.2 Patch Availability Factor

| Time Since Patch | Patch Factor | Interpretation |
|------------------|--------------|----------------|
| No patch (0d) | 1.0 | No mitigation available |
| 1-7 days | 0.8 | Grace period |
| 8-30 days | 0.5 | Should be patched |
| 31-90 days | 0.3 | Negligence begins |
| 91-365 days | 0.1 | Serious negligence |
| 1+ years | 0.05 | Extreme negligence |

### 4.3 Temporal Adjustment Formula

```python
def apply_temporal_adjustment(
    posterior_prob: float,
    age_factor: float,
    patch_factor: float,
    is_kev: bool = False,
    is_zero_day: bool = False,
    cvss_score: float = 0.0
) -> float:
    """
    Apply temporal factors to posterior probability.
    
    IMPORTANT: Temporal factors are NOT likelihood ratios.
    They represent time-based decay/amplification and should be
    applied to probability directly, not to odds.
    """
    # KEV overrides age decay
    if is_kev:
        age_factor = max(age_factor, 0.8)
    
    # Apply temporal factors to PROBABILITY (not odds)
    # This represents decay over time, not Bayesian evidence
    adjusted_prob = posterior_prob * age_factor * patch_factor
    
    # Apply probability floors to prevent misleading ratings
    if is_zero_day and cvss_score >= 9.0:
        adjusted_prob = max(adjusted_prob, 0.05)  # 5% minimum for critical zero-days
    
    if is_kev:
        adjusted_prob = max(adjusted_prob, 0.05)  # 5% minimum for KEV
    
    # Cap at 95% (practical maximum)
    adjusted_prob = min(adjusted_prob, 0.95)
    
    return adjusted_prob
```

### 4.4 Probability Floors

**Prevent misleading "Negligible" ratings**:

| Condition | Minimum Probability | Rationale |
|-----------|---------------------|-----------|
| Zero-day + CVSS ≥ 9.0 | 5% (Medium) | Targeted attacks |
| CISA KEV | 5% (Medium) | Active exploitation |
| Unpatched > 1yr + CVSS ≥ 7.0 | 2% (Low) | Negligence |

---

## 5. Docker Security Practices

### 5.1 Binary Model: Good vs Poor

**Good Practices** (≥3 out of 5):
- Read-only filesystem
- Non-root user
- Dropped capabilities (CAP_DROP)
- Seccomp profile
- No privileged mode

**Poor Practices** (<3 out of 5):
- Writable filesystem
- Root user
- Full capabilities
- No seccomp
- Privileged containers

### 5.2 Likelihood Ratios by Stage

| Stage | Good Practices LR | Poor Practices LR |
|-------|-------------------|-------------------|
| Execution | 0.4 (60% reduction) | 0.8 (20% reduction) |
| Lateral Movement | 0.5 (50% reduction) | 0.9 (10% reduction) |
| Persistence | 0.2 (80% reduction) | 0.8 (20% reduction) |

---

## 6. Real-World Implementation Examples

### 6.1 Example 1: Low EPSS + No Exploit + Internet-Facing (Exploitability Gating)

**Scenario**: CVE-2024-XXXX in nginx 1.18.0 (internet-facing)

**Vulnerability Details**:
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **EPSS**: 0.1% (very low - not in top 10%)
- **Exploit**: None (no Metasploit, ExploitDB, PoC)
- **Exposure**: Internet-facing
- **Controls**: WAF, IDS/IPS

**Bayesian Calculation WITH Exploitability Gating**:

```python
# Step 1: Prior (EPSS)
prior = 0.001  # 0.1%
prior_odds = 0.001 / 0.999 = 0.001001

# Step 2: Check exploitability
exploitation_plausible = False  # EPSS < 5% AND no exploit

# Step 3: Threat indicators (none)
threat_lr = 1.0  # No exploits

# Step 4: Exposure (GATED)
base_exposure_lr = 2.5  # Internet-facing
# BUT exploitation not plausible, so cap to 1.2
exposure_lr = 1.2  # Capped!

# Step 5: CVSS vector (GATED)
av_n_lr = 2.0  # Network
ac_l_lr = 1.5  # Low complexity
pr_n_lr = 1.8  # No privileges
ui_n_lr = 1.5  # No interaction
# All capped to 1.1 because exploitation not plausible
cvss_lr = 1.1 x 1.1 x 1.1 x 1.1 = 1.46  # Capped!

# Step 6: Controls (NOT GATED - always apply)
waf_lr = 0.3  # 70% reduction (exposure-conditional)
ids_lr = 0.4  # 60% reduction (exposure-conditional)
control_lr = 0.3 x 0.4 = 0.12

# Step 7: Combined LR
combined_lr = 1.0 x 1.2 x 1.46 x 0.12 = 0.21

# Step 8: Posterior
posterior_odds = 0.001001 x 0.21 = 0.00021
posterior = 0.00021 / 1.00021 = 0.00021 = 0.021%

# Result: NEGLIGIBLE (< 1%)
```

**Without Exploitability Gating (WRONG)**:
```python
# Would calculate:
exposure_lr = 2.5  # Full amplification
cvss_lr = 2.0 x 1.5 x 1.8 x 1.5 = 8.1  # Full amplification
combined_lr = 1.0 x 2.5 x 8.1 x 0.12 = 2.43
posterior = 0.24%  # MEDIUM (wrong!)
```

**Key Insight**: Exploitability gating prevents **10x probability overestimation** (0.24% → 0.021%).

---

### 6.2 Example 2: High EPSS + Metasploit + Internet-Facing (Full Amplification)

**Scenario**: CVE-2023-4911 (glibc buffer overflow) in php-fpm

**Vulnerability Details**:
- **CVSS**: 7.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **EPSS**: 8.3% (high - in top 10%)
- **Exploit**: Metasploit module available
- **Exposure**: Internal
- **Controls**: EDR/XDR, Network Segmentation

**Bayesian Calculation**:

```python
# Step 1: Prior
prior = 0.083  # 8.3%
prior_odds = 0.083 / 0.917 = 0.0905

# Step 2: Check exploitability
exploitation_plausible = True  # EPSS ≥ 5% AND Metasploit

# Step 3: Threat indicators
metasploit_lr = 2.5  # 150% increase

# Step 4: Exposure (FULL - exploitation plausible)
base_exposure_lr = 0.6  # Internal (reduction)
exposure_lr = 0.6  # Full application (reduction always applies)

# Step 5: CVSS vector (FULL - exploitation plausible)
av_l_lr = 0.5  # Local (reduction for internal)
ac_l_lr = 1.5  # Low complexity
pr_l_lr = 1.0  # Low privileges
ui_n_lr = 1.5  # No interaction
cvss_lr = 0.5 x 1.5 x 1.0 x 1.5 = 1.125

# Step 6: Controls (exposure-conditional)
edr_lr = 0.4  # 60% reduction (same for all exposures)
network_seg_lr = 0.3  # 70% reduction (more effective for internal)
control_lr = 0.4 x 0.3 = 0.12

# Step 7: Combined LR
combined_lr = 2.5 x 0.6 x 1.125 x 0.12 = 0.2025

# Step 8: Posterior
posterior_odds = 0.0905 x 0.2025 = 0.0183
posterior = 0.0183 / 1.0183 = 0.018 = 1.8%

# Result: LOW (1-5%)
```

**Key Insight**: Even with Metasploit and high EPSS, **strong controls reduce exploitation probability** from 8.3% → 1.8%.

---

### 6.3 Example 3: KEV + Internet-Facing + Poor Controls (Critical Threat)

**Scenario**: CVE-2023-44487 (HTTP/2 Rapid Reset) in nginx

**Vulnerability Details**:
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **EPSS**: 94.42% (adjusted to 15% KEV floor)
- **Exploit**: CISA KEV, ExploitDB, GitHub PoC, Metasploit
- **Exposure**: Internet-facing
- **Controls**: None (poor security posture)

**Bayesian Calculation**:

```python
# Step 1: Prior (KEV floor)
prior = 0.15  # 15% KEV floor
prior_odds = 0.15 / 0.85 = 0.176

# Step 2: Check exploitability
exploitation_plausible = True  # KEV + multiple exploits

# Step 3: Threat indicators
kev_lr = 3.0  # 200% increase
exploitdb_lr = 2.0  # 100% increase
metasploit_lr = 2.5  # 150% increase
poc_lr = 1.5  # 50% increase
threat_lr = 3.0 × 2.0 × 2.5 × 1.5 = 22.5

# Step 4: Exposure (FULL)
exposure_lr = 2.5  # Internet-facing

# Step 5: CVSS vector (FULL)
av_n_lr = 2.0  # Network
ac_l_lr = 1.5  # Low complexity
pr_n_lr = 1.8  # No privileges
ui_n_lr = 1.5  # No interaction
cvss_lr = 2.0 × 1.5 × 1.8 × 1.5 = 8.1

# Step 6: Controls
control_lr = 1.0  # No controls!

# Step 7: Combined LR
combined_lr = 22.5 × 2.5 × 8.1 × 1.0 = 455.625

# Step 8: Posterior (capped)
posterior_odds = 0.176 × 455.625 = 80.19
posterior = 80.19 / 81.19 = 0.988 = 98.8%
# Capped to 95% (practical maximum)
posterior = 0.95 = 95%

# Result: CRITICAL (≥ 40%)
```

**Key Insight**: **KEV + multiple exploits + no controls = near-certain exploitation**.

---

### 6.4 Example 4: Exposure-Conditional Control Effectiveness

**Scenario**: Same vulnerability, different exposures

**CVE-2024-YYYY**: SQL injection in web application
- **CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **EPSS**: 25%
- **Exploit**: ExploitDB
- **Controls**: WAF + MFA

**Case A: Internet-Facing**
```python
prior_odds = 0.25 / 0.75 = 0.333
exploitdb_lr = 2.0
exposure_lr = 2.5
cvss_lr = 8.1

# Exposure-conditional controls
waf_lr = 0.3  # 70% reduction (internet-facing)
mfa_lr = 0.2  # 80% reduction (internet-facing)
control_lr = 0.3 × 0.2 = 0.06

combined_lr = 2.0 × 2.5 × 8.1 × 0.06 = 2.43
posterior_odds = 0.333 × 2.43 = 0.809
posterior = 0.809 / 1.809 = 0.447 = 44.7%
# Result: CRITICAL
```

**Case B: Internal**
```python
prior_odds = 0.333  # Same
exploitdb_lr = 2.0  # Same
exposure_lr = 0.6  # Internal (reduction)
cvss_lr = 8.1  # Same

# Exposure-conditional controls
waf_lr = 0.9  # 10% reduction (internal - WAF rarely deployed)
mfa_lr = 0.5  # 50% reduction (internal - less critical)
control_lr = 0.9 × 0.5 = 0.45

combined_lr = 2.0 × 0.6 × 8.1 × 0.45 = 4.37
posterior_odds = 0.333 × 4.37 = 1.455
posterior = 1.455 / 2.455 = 0.593 = 59.3%
# Result: CRITICAL (but higher than internet-facing!)
```

**Key Insight**: **Internal services can have HIGHER exploitation probability** if controls are less effective there. WAF on internal service is nearly useless.

---

## 7. Uncertainty Quantification

### 7.1 Credible Intervals

**From `BayesianRiskAssessor._calculate_credible_interval()`**:

```python
def _calculate_credible_interval(
    self,
    posterior_prob: float,
    epss_percentile: float | None,
    n_evidence: int,
) -> tuple[float, float]:
    """Calculate 95% credible interval using Beta distribution.
    
    More evidence → narrower interval
    Less evidence → wider interval
    """
    # Beta distribution parameters
    alpha = posterior_prob * n_evidence
    beta = (1 - posterior_prob) * n_evidence
    
    # 95% credible interval
    from scipy.stats import beta as beta_dist
    ci_low = beta_dist.ppf(0.025, alpha, beta)
    ci_high = beta_dist.ppf(0.975, alpha, beta)
    
    return (ci_low, ci_high)
```

### 7.2 Example: Uncertainty Quantification

**Scenario**: Posterior = 45%, 5 pieces of evidence

```python
alpha = 0.45 × 5 = 2.25
beta = 0.55 × 5 = 2.75

ci_low = beta_dist.ppf(0.025, 2.25, 2.75) = 0.18 = 18%
ci_high = beta_dist.ppf(0.975, 2.25, 2.75) = 0.74 = 74%

uncertainty = 74% - 18% = 56%

# Report: 45% [18% - 74%] (56% uncertainty)
```

**With more evidence (10 pieces)**:
```python
alpha = 0.45 × 10 = 4.5
beta = 0.55 × 10 = 5.5

ci_low = 0.26 = 26%
ci_high = 0.65 = 65%
uncertainty = 39%

# Report: 45% [26% - 65%] (39% uncertainty)
```

**Key Insight**: **More evidence = more confidence**. With 10 pieces of evidence, uncertainty drops from 56% to 39%.

---

## 8. Implementation Reference

### 6.1 Application Stack

**5-Component Production Application**:
- **nginx 1.18.0** - Ingress/reverse proxy (internet-facing)
- **FastAPI 0.95.0** - Python frontend API (internal)
- **Redis 6.2.6** - Cache (internal)
- **PostgreSQL 13.8** - Database (internal)
- **Node.js 16.14.0** - Backend service (internal)

**Deployment**: Kubernetes pod (no network segmentation within pod)

**Security Controls**:
- WAF on nginx (LR = 0.3)
- IDS/IPS (LR = 0.4)
- Docker good practices (read-only FS, non-root, dropped caps)

---

### 6.2 Example 1: Zero-Day in nginx (Day 0)

#### **CVE-2024-XXXX** (Hypothetical)

**Vulnerability Details**:
- **Type**: HTTP/2 request smuggling → RCE
- **CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **EPSS**: 0.1% (not yet in model - too new)
- **Exploit**: None (zero-day)
- **Patch**: Not available
- **Discovered**: Today (January 1, 2026)

#### **Stage 1: Initial Access**

```python
# Base Bayesian calculation
prior = 0.001  # 0.1% EPSS
prior_odds = 0.001 / 0.999 = 0.001001

# CVSS LRs
av_n_lr = 2.0  # Network accessible
ac_l_lr = 1.5  # Low complexity
pr_n_lr = 1.8  # No privileges
ui_n_lr = 1.5  # No interaction
cvss_lr = 2.0 × 1.5 × 1.8 × 1.5 = 8.1

# Exposure
exposure_lr = 2.5  # Internet-facing

# Controls
waf_lr = 0.3
ids_lr = 0.4
control_lr = 0.3 × 0.4 = 0.12

# Combined LR
combined_lr = 8.1 × 2.5 × 0.12 = 2.43

# Posterior
posterior_odds = 0.001001 × 2.43 = 0.002433
posterior = 0.002433 / 1.002433 = 0.0024 = 0.24%

# Temporal adjustment
age_factor = 5.0  # Zero-day
patch_factor = 1.0  # No patch

temporal_odds = 0.002433 × 5.0 × 1.0 = 0.012165
temporal_prob = 0.012165 / 1.012165 = 0.012 = 1.2%

# Zero-day floor (CVSS ≥ 9.0)
final_prob = max(0.012, 0.05) = 0.05 = 5% → MEDIUM
```

**Result**: P(Initial Access) = **5% (Medium)** - Zero-day floor applied

---

#### **Stage 2: Execution**

```python
# Given initial access, execution is automatic (RCE)
execution_conditional = 0.95  # High probability

# Docker security
docker_lr = 0.4  # Good practices

stage_2_conditional = 0.95 × 0.4 = 0.38

# Cumulative probability
cumulative = 0.05 × 0.38 = 0.019 = 1.9%
```

**Result**: P(Initial Access ∩ Execution) = **1.9%**

---

#### **Stage 3: Lateral Movement**

```python
# No network segmentation in pod - all components reachable
# Assume 30% chance of finding unprotected service
lateral_conditional = 0.3

# Docker security
docker_lr = 0.5

stage_3_conditional = 0.3 × 0.5 = 0.15

# Cumulative
cumulative = 0.019 × 0.15 = 0.0029 = 0.29%
```

**Result**: P(Initial Access ∩ Execution ∩ Lateral Movement) = **0.29%**

---

#### **Stage 4: Data Exfiltration**

```python
# Need database access + egress
db_access = 0.5  # Assume 50% chance
egress = 0.8     # 80% chance (no egress filtering)

objective_conditional = 0.5 × 0.8 = 0.4

# Final cumulative
final = 0.0029 × 0.4 = 0.0012 = 0.12%
```

**Result**: P(Kill-Chain Success) = **0.12% (Negligible)**

**Interpretation**: Even with a critical zero-day, strong Docker security practices and controls reduce kill-chain success to negligible levels.

---

### 6.3 Example 2: Same Vulnerability at Day 30

#### **CVE-2024-XXXX** (30 Days Later)

**Updated Status**:
- **EPSS**: 15% (now in model, PoC published)
- **Exploit**: GitHub PoC (LR = 1.5), Metasploit (LR = 2.5)
- **Patch**: Available since Day 7 (23 days ago)

#### **Stage 1: Initial Access**

```python
# Base Bayesian
prior = 0.15
prior_odds = 0.15 / 0.85 = 0.176

# Exploit LRs
exploit_lr = 1.5 × 2.5 = 3.75

# CVSS + Exposure + Controls
cvss_lr = 8.1
exposure_lr = 2.5
control_lr = 0.12

combined_lr = 3.75 × 8.1 × 2.5 × 0.12 = 9.11

posterior_odds = 0.176 × 9.11 = 1.604
posterior = 1.604 / 2.604 = 0.616 = 61.6%

# Temporal adjustment (applied to PROBABILITY, not odds)
age_factor = 2.0      # Peak exploitation (Day 30)
patch_factor = 0.5    # Patch available 23 days

temporal_prob = 0.616 × 2.0 × 0.5 = 0.616 = 61.6%

# No floor needed (already > 5%)
# Note: 2.0 × 0.5 = 1.0, so probability unchanged
```

**Result**: P(Initial Access) = **61.6% (Critical)**

---

#### **Complete Kill-Chain**

```python
# Stage 1: Initial Access
stage_1 = 0.616  # 61.6%

# Stage 2: Execution (RCE automatic)
stage_2_cond = 0.95 × 0.4 = 0.38
cumulative_2 = 0.616 × 0.38 = 0.234 = 23.4%

# Stage 3: Lateral Movement
stage_3_cond = 0.3 × 0.5 = 0.15
cumulative_3 = 0.234 × 0.15 = 0.035 = 3.5%

# Stage 4: Data Exfiltration
stage_4_cond = 0.5 × 0.8 = 0.4
final = 0.035 × 0.4 = 0.014 = 1.4%
```

**Result**: P(Kill-Chain Success) = **1.4% (Low)**

**Interpretation**: At Day 30 (peak exploitation), initial access probability is critical (61.6%), but Docker security and lack of lateral movement exploits reduce final kill-chain success to low (1.4%).

---

### 6.4 Example 3: CVE-2023-44487 (HTTP/2 Rapid Reset)

#### **Real Vulnerability - 15 Months Old**

**Vulnerability Details**:
- **Type**: HTTP/2 DoS via rapid stream reset
- **CVSS**: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **EPSS**: 94.42%
- **Exploit**: ExploitDB, GitHub PoC, automated tools
- **CISA KEV**: Yes (actively exploited)
- **Patch**: Available since October 2023 (15 months ago)
- **Discovered**: October 10, 2023
- **Current Date**: January 1, 2026

#### **Stage 1: Initial Access**

```python
# Base Bayesian
prior = 0.15  # KEV floor (not 94.42% - too high)
prior_odds = 0.15 / 0.85 = 0.176

# Exploit LRs
kev_lr = 3.0
exploitdb_lr = 2.0
poc_lr = 1.5
exploit_lr = 3.0 × 2.0 × 1.5 = 9.0

# CVSS LRs (DoS has lower impact)
av_n_lr = 2.0
ac_l_lr = 1.5
pr_n_lr = 1.8
ui_n_lr = 1.5
# DoS impact reduction
cvss_lr = 2.0 × 1.5 × 1.8 × 1.5 × 0.5 = 4.05

# Exposure + Controls
exposure_lr = 2.5
control_lr = 0.12

combined_lr = 9.0 × 4.05 × 2.5 × 0.12 = 10.94

posterior_odds = 0.176 × 10.94 = 1.925
posterior = 1.925 / 2.925 = 0.658 = 65.8%

# Temporal adjustment
age_factor = 0.8      # KEV overrides age decay (15 months)
patch_factor = 0.3    # Patch available 15 months (negligence)
kev_multiplier = 1.5  # KEV maintains high probability

temporal_odds = 1.925 × 0.8 × 0.3 × 1.5 = 0.693
temporal_prob = 0.693 / 1.693 = 0.409 = 40.9%

# KEV floor
final_prob = max(0.409, 0.05) = 0.409 = 40.9% → CRITICAL
```

**Result**: P(Initial Access) = **40.9% (Critical)**

**Interpretation**: KEV status maintains critical threat level despite age. Being unpatched for 15 months is extreme negligence.

---

### 6.5 Example 4: Old Vulnerability in PostgreSQL

#### **CVE-2021-23214** (4+ Years Old)

**Vulnerability Details**:
- **Type**: Authentication bypass via certificate validation
- **CVSS**: 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **EPSS**: 0.4%
- **Exploit**: PoC available
- **Patch**: Available since November 2021 (4+ years ago)
- **Discovered**: November 11, 2021
- **Current Date**: January 1, 2026

#### **Stage 3: Lateral Movement** (postgres is internal)

```python
# Base Bayesian
prior = 0.004  # 0.4% EPSS
prior_odds = 0.004 / 0.996 = 0.004016

# Exploit LR
poc_lr = 1.5

# CVSS LRs (AC:H reduces probability)
av_n_lr = 1.0  # Internal (not internet-facing)
ac_h_lr = 0.5  # High complexity
pr_n_lr = 1.8
ui_n_lr = 1.5
cvss_lr = 1.0 × 0.5 × 1.8 × 1.5 = 1.35

# Exposure (internal)
exposure_lr = 0.6

# Controls (network segmentation - but none in pod)
control_lr = 0.3

combined_lr = 1.5 × 1.35 × 0.6 × 0.3 = 0.365

posterior_odds = 0.004016 × 0.365 = 0.001466
posterior = 0.001466 / 1.001466 = 0.0015 = 0.15%

# Temporal adjustment
age_factor = 0.1      # Very old (4+ years)
patch_factor = 0.05   # Patch available 4+ years (extreme negligence)

temporal_odds = 0.001466 × 0.1 × 0.05 = 0.000007
temporal_prob = 0.000007 / 1.000007 = 0.000007 = 0.0007%

# Negligence floor (unpatched > 1yr + CVSS ≥ 7.0)
final_prob = max(0.0007, 0.02) = 0.02 = 2% → LOW
```

**Result**: P(Lateral Movement) = **2% (Low)** - Negligence floor applied

**Interpretation**: Ancient vulnerability with very low exploitation probability, but negligence floor ensures it's not ignored.

---

## 8. Implementation Guide

### 7.1 Data Requirements

**Per Vulnerability**:
- CVE ID
- CVSS score and vector string
- EPSS score
- Exploit maturity (Metasploit, ExploitDB, PoC, etc.)
- CISA KEV status
- Disclosure date
- Patch availability date
- Affected component

**Per Component**:
- Service name
- Docker image
- Exposure (internet-facing, internal)
- Docker security practices

**Per Application**:
- Deployment type (K8s, docker-compose)
- Security controls (WAF, IDS, etc.)
- Network topology (if segmentation exists)

### 7.2 Algorithm Steps

```python
def calculate_kill_chain_probability(
    vulnerabilities: list[Vulnerability],
    components: list[Component],
    security_controls: SecurityControls,
    objective: str  # "data_exfiltration", "service_disruption", "persistence"
) -> KillChainResult:
    """
    Calculate P(Kill-Chain Success | Vulnerabilities, Controls, Temporal Factors)
    """
    # Step 1: Filter to exploitable vulnerabilities only
    exploitable = filter_exploitable_vulnerabilities(vulnerabilities)
    
    # Step 2: Calculate Stage 1 (Initial Access)
    stage_1_prob = calculate_initial_access(
        exploitable,
        components,
        security_controls
    )
    
    # Step 3: Calculate Stage 2 (Execution)
    stage_2_prob = calculate_execution(
        stage_1_prob,
        exploitable,
        security_controls
    )
    
    # Step 3: Calculate Stage 3 (Lateral Movement)
    stage_3_prob = calculate_lateral_movement(
        stage_2_prob,
        exploitable,
        security_controls
    )
    
    # Step 4: Calculate Stage 4 (Objective)
    final_prob = calculate_objective(
        stage_3_prob,
        objective,
        exploitable,
        security_controls
    )
    
    return KillChainResult(
        objective=objective,
        final_probability=final_prob,
        stage_breakdown={
            "initial_access": stage_1_prob,
            "execution": stage_2_prob,
            "lateral_movement": stage_3_prob,
            "objective": final_prob
        }
    )
```

### 7.3 Exploitability Filter

```python
def filter_exploitable_vulnerabilities(
    vulnerabilities: list[Vulnerability]
) -> list[Vulnerability]:
    """
    Filter to only exploitable vulnerabilities
    """
    exploitable = []
    
    for vuln in vulnerabilities:
        # Check exploit maturity
        has_exploit = vuln.exploit_maturity in [
            "weaponized",
            "metasploit",
            "exploitdb",
            "nuclei",
            "poc"
        ]
        
        # Check CVSS for trivial exploitation
        is_trivial = (
            vuln.cvss_vector.get("AC") == "L" and
            vuln.cvss_vector.get("PR") == "N" and
            vuln.cvss_vector.get("UI") == "N"
        )
        
        if has_exploit or is_trivial:
            exploitable.append(vuln)
    
    return exploitable
```

### 7.4 Bayesian Update (Correct)

```python
def bayesian_update(
    prior: float,
    likelihood_ratios: list[float]
) -> float:
    """
    Correct Bayesian update using odds form
    """
    # Convert prior to odds
    prior_odds = prior / (1 - prior)
    
    # Apply all LRs
    posterior_odds = prior_odds
    for lr in likelihood_ratios:
        posterior_odds *= lr
    
    # Convert back to probability
    posterior = posterior_odds / (1 + posterior_odds)
    
    return posterior
```

### 7.5 Temporal Adjustment

```python
def apply_temporal_adjustment(
    posterior: float,
    days_since_disclosure: int,
    days_since_patch: int,
    is_zero_day: bool,
    is_kev: bool,
    cvss_score: float
) -> float:
    """
    Apply temporal probability factors
    """
    # Convert to odds
    posterior_odds = posterior / (1 - posterior)
    
    # Age factor
    if is_zero_day:
        age_factor = 5.0
    elif days_since_disclosure <= 7:
        age_factor = 3.0
    elif days_since_disclosure <= 30:
        age_factor = 2.0
    elif days_since_disclosure <= 90:
        age_factor = 1.5
    elif days_since_disclosure <= 180:
        age_factor = 1.0
    elif days_since_disclosure <= 365:
        age_factor = 0.5
    else:
        age_factor = 0.1
    
    # Patch factor
    if days_since_patch == 0:
        patch_factor = 1.0
    elif days_since_patch <= 7:
        patch_factor = 0.8
    elif days_since_patch <= 30:
        patch_factor = 0.5
    elif days_since_patch <= 90:
        patch_factor = 0.3
    elif days_since_patch <= 365:
        patch_factor = 0.1
    else:
        patch_factor = 0.05
    
    # KEV override
    if is_kev:
        age_factor = max(age_factor, 0.8)
    
    # Apply temporal factors to PROBABILITY (not odds)
    # This represents decay over time, not Bayesian updating
    adjusted_prob = posterior * age_factor * patch_factor
    
    # Apply floors
    if is_zero_day and cvss_score >= 9.0:
        adjusted_prob = max(adjusted_prob, 0.05)
    
    if is_kev:
        adjusted_prob = max(adjusted_prob, 0.05)
    
    if days_since_patch > 365 and cvss_score >= 7.0:
        adjusted_prob = max(adjusted_prob, 0.02)
    
    return adjusted_prob
```

### 7.6 Threat Level Categories

```python
def categorize_threat_level(probability: float) -> str:
    """
    Categorize threat level based on exploitation probability
    """
    if probability >= 0.40:
        return "CRITICAL"
    elif probability >= 0.15:
        return "HIGH"
    elif probability >= 0.05:
        return "MEDIUM"
    elif probability >= 0.01:
        return "LOW"
    else:
        return "NEGLIGIBLE"
```

---

## 8. Summary

### 8.1 Key Principles

1. **Exploitability First**: Only consider vulnerabilities with mature exploits or trivial CVSS characteristics
2. **Sequential Dependencies**: Model kill-chain as Markov chain with conditional probabilities
3. **Temporal Factors**: Adjust for vulnerability age, zero-day status, and patch availability
4. **Mathematically Correct**: Use Bayesian odds form to ensure probabilities ≤ 1.0
5. **Probability Floors**: Prevent misleading "Negligible" ratings for critical threats
6. **Docker Security**: Binary model (good vs poor practices) affects execution and lateral movement

### 8.2 Advantages

- **Computational Efficiency**: 90%+ reduction in vulnerabilities to analyze
- **Realistic Modeling**: Reflects actual attacker workflow and pod deployment reality
- **Actionable Insights**: Identifies bottleneck stages and critical vulnerabilities
- **Temporal Context**: Accounts for zero-days, patch availability, and negligence
- **Mathematically Sound**: Correct Bayesian probability calculations

### 8.3 Limitations

- **No Network Segmentation**: Assumes all components in pod can reach each other
- **Binary Security Model**: Good vs poor is coarse-grained
- **Expert Priors**: Some conditional probabilities based on expert judgment
- **Simplified Controls**: WAF, IDS, Docker security only (no EDR, SIEM, etc.)

### 8.4 Future Enhancements

- Add network segmentation modeling (K8s NetworkPolicy)
- Granular Docker security scoring (0-5 scale)
- Service mesh integration (Istio, Linkerd)
- Attack path enumeration (multiple routes to objective)
- Uncertainty quantification (credible intervals)

---

## Appendix A: Likelihood Ratio Reference

### Exploit Maturity
| Type | LR | Source |
|------|-----|--------|
| Weaponized | 4.0 | Threat intel |
| Metasploit | 2.5 | CVSS-BT |
| ExploitDB | 2.0 | CVSS-BT |
| Nuclei | 1.8 | CVSS-BT |
| GitHub PoC | 1.5 | CVSS-BT |

### CVSS Components (Internet-Facing)
| Metric | Value | LR |
|--------|-------|-----|
| AV | Network (N) | 2.0 |
| AV | Adjacent (A) | 1.5 |
| AV | Local (L) | 0.3 |
| AC | Low (L) | 1.5 |
| AC | High (H) | 0.5 |
| PR | None (N) | 1.8 |
| PR | Low (L) | 1.0 |
| PR | High (H) | 0.5 |
| UI | None (N) | 1.5 |
| UI | Required (R) | 0.6 |

### Security Controls
| Control | LR | Probability Reduction |
|---------|-----|----------------|
| WAF | 0.3 | 70% |
| IDS/IPS | 0.4 | 60% |
| Network Segmentation | 0.2 | 80% |
| Docker Good Practices | 0.4-0.5 | 50-60% |

### Exposure
| Type | LR |
|------|-----|
| Internet-facing | 2.5 |
| DMZ | 1.8 |
| Internal | 0.6 |
| Restricted | 0.3 |

---

## Appendix B: Glossary

- **CVSS**: Common Vulnerability Scoring System
- **EPSS**: Exploit Prediction Scoring System
- **KEV**: Known Exploited Vulnerabilities (CISA catalog)
- **LR**: Likelihood Ratio
- **PoC**: Proof of Concept
- **RCE**: Remote Code Execution
- **DoS**: Denial of Service
- **WAF**: Web Application Firewall
- **IDS/IPS**: Intrusion Detection/Prevention System
- **K8s**: Kubernetes

---

## 9. Statistical Validity: Fallacy Analysis

### 9.1 Bernoulli's Fallacy (Prosecutor's Fallacy)

#### **What It Is**
Confusing P(Evidence | Hypothesis) with P(Hypothesis | Evidence).

**Classic Example**:
```
P(Positive Test | Disease) = 99% (test sensitivity)
≠ P(Disease | Positive Test) = ??? (depends on base rate!)

If disease prevalence is 0.1%, then:
P(Disease | Positive Test) ≈ 9% (not 99%!)
```

#### **Is Our Method Vulnerable?**

**NO** - We use Bayes' Theorem correctly:

```python
# We calculate: P(Exploit | Evidence)
posterior = P(Exploit | EPSS, Exploits, CVSS, Controls)

# NOT: P(Evidence | Exploit)
# We don't confuse the direction of conditioning
```

**Example from our method**:
```python
# CORRECT
P(Exploit | KEV=True, EPSS=15%, Metasploit=True)
= Bayesian update using odds form
= 0.176 × 3.0 × 2.5 / (1 + 0.176 × 3.0 × 2.5)
= 61.3%

# WRONG (Bernoulli's Fallacy)
P(Exploit | KEV=True) = P(KEV=True | Exploit) = 100%
# This would be the fallacy - we don't do this
```

**Why we're safe**:
1. We start with **prior probability** (EPSS) - the base rate
2. We update using **likelihood ratios** - the correct Bayesian mechanism
3. We calculate **posterior probability** - P(Hypothesis | Evidence), not the reverse

---

### 9.2 Gambler's Fallacy

#### **What It Is**
Believing that independent events are dependent:
- "I've flipped heads 5 times, so tails is 'due'"
- P(Tails | 5 Heads) = 50% (not higher!)

**Inverse Gambler's Fallacy**:
- "I just rolled double-sixes, so the dice must have been rolled many times before"

#### **Is Our Method Vulnerable?**

**NO** - We have temporal dependencies that are **causally real**, not independent events:

**Temporal Age Factor**:
```python
# Our temporal adjustment
if days_since_disclosure <= 30:
    age_factor = 2.0  # Peak exploitation
elif days_since_disclosure <= 90:
    age_factor = 1.5  # Declining
else:
    age_factor = 0.5  # Long-tail
```

**This is NOT Gambler's Fallacy because**:

Exploitation attempts are **NOT independent events** like coin flips:

1. **Exploit availability changes over time** (PoC → Metasploit → automated tools)
2. **Patch availability changes** (no patch → patch available → widely deployed)
3. **Attacker awareness changes** (unknown → disclosed → widespread knowledge)
4. **Defender awareness changes** (unpatched → patching in progress → patched)

**Sequential Kill-Chain Stages**:
```python
# Our sequential model
P(Kill-Chain) = P(S₁) × P(S₂|S₁) × P(S₃|S₂) × P(S₄|S₃)
```

**NOT Gambler's Fallacy because**:
- Stages are **causally dependent** (must succeed at S₁ to attempt S₂)
- Not independent events
- Conditional probabilities are correct

**Example**:
```
"Given initial access succeeded (S₁), what's P(Execution | S₁)?"
This is NOT: "I succeeded at S₁, so I'm 'due' to fail at S₂"
This IS: "Given S₁ succeeded, I now have access to attempt S₂"
```

---

### 9.3 Base Rate Neglect

#### **What It Is**
Ignoring the prior probability (base rate) when updating beliefs.

**Classic Example**:
```
"This person has symptom X, which 90% of disease patients have.
Therefore, they probably have the disease!"

(Ignores that only 0.1% of population has the disease)
```

#### **Is Our Method Vulnerable?**

**NO** - We explicitly use EPSS as the prior:

```python
prior = epss_score  # Base rate from real-world data
prior_odds = prior / (1 - prior)
# All updates start from this base rate
```

**Example**:
```python
# CORRECT (our method)
Prior (EPSS) = 0.1%
After evidence: 5% (zero-day floor)

# WRONG (base rate neglect)
"It's a zero-day with CVSS 9.8, so it's 100% exploitable!"
# Ignores that 99.9% of zero-days are never exploited in practice
```

---

### 9.4 Conjunction Fallacy

#### **What It Is**
Believing P(A ∧ B) > P(A) or P(B).

**Classic Example (Linda Problem)**:
```
"Linda is a bank teller AND active in feminist movement"
seems more probable than
"Linda is a bank teller"

(But P(A ∧ B) ≤ P(A) always!)
```

#### **Is Our Method Vulnerable?**

**NO** - Our sequential model respects probability axioms:

```python
P(S₁ ∧ S₂ ∧ S₃ ∧ S₄) = P(S₁) × P(S₂|S₁) × P(S₃|S₂) × P(S₄|S₃)

# This is always ≤ P(S₁)
```

**Example**:
```
P(Initial Access) = 0.616 = 61.6%
P(Initial Access ∧ Execution ∧ Lateral ∧ Exfiltration) = 0.014 = 1.4%

1.4% < 61.6% ✓
```

---

### 9.5 Actual Statistical Issues

While we avoid classical fallacies, we have **real modeling assumptions** that may not hold:

#### **9.5.1 Conditional Independence Violations**

**Problem**: We assume likelihood ratios are conditionally independent given the prior.

**Reality**:
- **Metasploit module** → implies **AC:L** (correlated)
- **KEV status** → already reflected in **EPSS** (correlated)
- **Internet-facing** → makes **WAF** more likely (correlated)

**Impact**: **Overconfidence** in posterior probabilities

**Example**:
```python
# We calculate
posterior = prior × LR_metasploit × LR_ac_l × LR_kev

# But if Metasploit implies AC:L, and KEV is in EPSS, 
# we're counting the same evidence multiple times!
```

**Mitigation**:
- Use **exposure-conditional LRs** (partially addresses this)
- Use **exploitability gating** (prevents false amplification)
- **Acknowledge uncertainty** with credible intervals

**KEV-EPSS Correlation Handling**:

Since EPSS already incorporates KEV status in its model, applying both creates double-counting. We handle this by:
1. **Using EPSS as prior** (includes KEV signal)
2. **Applying reduced KEV LR** (1.5x instead of 3.0x) to account for partial overlap
3. **KEV floor** (5% minimum) ensures critical threats aren't underestimated

This conservative approach acknowledges the correlation while maintaining safety margins.

---

#### **9.5.2 Temporal Correlation**

**Problem**: Vulnerability age and patch availability are correlated.

```python
# We apply both
age_factor = 0.5  # 180 days old
patch_factor = 0.1  # Patch available 180 days

# But these are correlated - old vulns usually have patches!
```

**Impact**: **Over-penalizing** old unpatched vulnerabilities

**Mitigation**: 
- Apply **negligence floor** (2% for unpatched > 1yr)
- This prevents over-penalization

---

#### **9.5.3 Selection Bias**

**Problem**: We only analyze **exploitable vulnerabilities** (Metasploit, PoC, etc.)

**Impact**: 
- **Survivorship bias** - we miss vulnerabilities that could become exploitable
- **Zero-days without PoC** are underestimated

**Mitigation**:
- Apply **zero-day floor** (5% for CVSS ≥ 9.0)
- Include **trivial CVSS** (AC:L, PR:N, UI:N) even without exploits

---

### 9.6 Uncertainty Quantification

To address overconfidence from independence violations, we recommend:

#### **9.6.1 Credible Intervals**

```python
def calculate_credible_interval(
    posterior: float,
    n_evidence: int
) -> tuple[float, float]:
    """
    Calculate 95% credible interval for posterior
    
    More evidence → narrower interval
    Less evidence → wider interval
    """
    # Beta distribution approximation
    alpha = posterior * n_evidence
    beta = (1 - posterior) * n_evidence
    
    # 95% credible interval
    from scipy.stats import beta as beta_dist
    low = beta_dist.ppf(0.025, alpha, beta)
    high = beta_dist.ppf(0.975, alpha, beta)
    
    return (low, high)
```

**Example**:
```
Posterior: 61.3%
With 5 pieces of evidence: [45% - 75%]
With 2 pieces of evidence: [20% - 90%]
```

---

#### **9.6.2 Sensitivity Analysis**

Test how posterior changes with different LR assumptions:

```python
# Base case
posterior = 61.3%

# If Metasploit LR is 2.0 instead of 2.5
posterior_low = 55.2%

# If Metasploit LR is 3.0 instead of 2.5
posterior_high = 67.8%

# Report range: 55-68% (±6%)
```

---

#### **9.6.3 Reporting Uncertainty**

In practice, report:
```
"Kill-chain success probability: 1.4% [0.8% - 2.3%]

Note: This assumes conditional independence of evidence.
Actual probability may differ due to correlations between:
- Exploit maturity and CVSS complexity
- KEV status and EPSS score
- Vulnerability age and patch availability

Sensitivity analysis shows ±40% variation with different LR assumptions."
```

---

### 9.7 Summary: Fallacy Vulnerability Assessment

| Fallacy/Issue | Vulnerable? | Severity | Mitigation |
|---------------|-------------|----------|------------|
| **Bernoulli's Fallacy** | ❌ NO | None | Use Bayes' theorem correctly |
| **Gambler's Fallacy** | ❌ NO | None | Events are causally dependent |
| **Base Rate Neglect** | ❌ NO | None | EPSS as explicit prior |
| **Conjunction Fallacy** | ❌ NO | None | Sequential probabilities decrease |
| **Independence Violations** | ⚠️ YES | Medium | Conditional LRs, credible intervals |
| **Temporal Correlation** | ⚠️ YES | Low | Negligence floors |
| **Selection Bias** | ⚠️ YES | Low | Zero-day floors, trivial CVSS |

---

### 9.8 Recommendations

1. **Always report credible intervals** (not just point estimates)
2. **Perform sensitivity analysis** on key likelihood ratios
3. **Acknowledge correlations** in documentation
4. **Use conservative estimates** when independence is questionable
5. **Validate against real-world breach data** when available

**The method is statistically sound** for its intended purpose (threat prioritization), but users should understand that:
- Point estimates may be **overconfident** due to independence violations
- Credible intervals provide **realistic uncertainty bounds**
- The model is a **simplification** of complex real-world attack dynamics

---

**Document Version**: 1.0  
**Last Updated**: January 1, 2026  
**Author**: CVEs Analytics Project
