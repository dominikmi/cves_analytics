# Bayesian Risk Assessment

This document explains how the CVEs Analytics pipeline calculates vulnerability risk using a principled Bayesian approach with **exposure-conditional likelihood ratios**.

> **⚠️ Important Note on Likelihood Ratios:**
> All likelihood ratio (LR) values in this framework are **heuristic estimates** based on security principles, industry observations, and conservative assumptions. They are NOT empirically validated through controlled studies. The framework's value lies in **relative risk prioritization** (which vulnerabilities are riskier) rather than **absolute probability prediction** (exact exploitation likelihood). Actual control effectiveness varies significantly based on implementation quality, configuration, and organizational context.

## Overview

Traditional vulnerability scoring (CVSS alone) often leads to "alert fatigue" because it doesn't consider:
- Real-world exploitation probability
- Your specific security controls
- Asset exposure and criticality

Our Bayesian approach addresses this by:
1. Starting with **EPSS** (Exploit Prediction Scoring System) as the prior probability
2. Updating with **exposure-conditional likelihood ratios** based on your environment
3. Applying **exploitability gating** to prevent false risk inflation
4. Applying **floors** to ensure actively exploited vulnerabilities are never rated "Negligible"

## Mathematical Foundation

### Basic Bayes' Theorem

```
Posterior Odds = Prior Odds x LR1 x LR2 x ... x LRn
```

Where:
- **Prior Odds** = EPSS / (1 - EPSS)
- **LR < 1** = Evidence that reduces exploitation probability (security controls)
- **LR > 1** = Evidence that increases exploitation probability (exposure, exploits)
- **LR = 1** = Uninformative evidence

### The Independence Problem

A naive Bayesian approach assumes all factors are **conditionally independent**:

```
P(Exploit | WAF, Internet, Metasploit) = P(Exploit) x LR_WAF x LR_Internet x LR_Metasploit
```

This assumption is often **violated** in practice:

| Scenario | Independence Violation |
|----------|----------------------|
| WAF + Internet-facing | WAF only matters IF internet-facing (WAF on internal service is irrelevant) |
| Metasploit + AC:L | Metasploit module implies low complexity (double-counting) |
| KEV + High EPSS | KEV status is already baked into EPSS (correlation) |
| Network segmentation + Internal | Segmentation matters more for internal lateral movement |

### Our Solution: Exposure-Conditional Likelihood Ratios

Instead of flat LRs, we use **exposure-conditional LRs**:

```
LR(WAF | internet-facing) = 0.3  (70% reduction - very effective)
LR(WAF | internal) = 0.9         (10% reduction - minimal effect)
```

This is a practical approximation of full conditional Bayes:

```
Full conditional: P(Exploit | WAF, Internet) = P(Exploit | Internet) x P(WAF effective | Internet)
Our approach:     P(Exploit | WAF, Internet) ~= P(Exploit) x LR(WAF | Internet) x LR(Internet)
```

### Exploitability Gating

We also implement **gating** for amplification factors:

```python
if exploitation_plausible:  # KEV, exploit, or high EPSS
    exposure_lr = full_lr      # 2.5 for internet-facing
else:
    exposure_lr = capped_lr    # 1.2 max
```

This prevents scenarios like:
- Low EPSS + No exploits + Internet-facing -> falsely elevated risk

### Why Not Full Bayesian Networks?

A full Bayesian network would model all dependencies explicitly:

```
                    ┌─────────────┐
                    │    EPSS     │
                    │   (Prior)   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ Exposure │ │ Exploits │ │   CVSS   │
        └────┬─────┘ └────┬─────┘ └────┬─────┘
             │            │            │
             ▼            │            │
        ┌──────────┐      │            │
        │ Controls │◄─────┘            │
        │(depends  │                   │
        │on expose)│                   │
        └────┬─────┘                   │
             │                         │
             └────────────┬────────────┘
                          ▼
                    ┌──────────┐
                    │ Posterior│
                    └──────────┘
```

**Pros of full Bayesian networks:**
- More accurate modeling of real-world dependencies
- Explicit conditional probability tables (CPTs)

**Cons:**
- Significantly more complex to implement and explain
- Requires data to calibrate all CPTs
- Diminishing returns for added complexity

**Present approach** (exposure-conditional LRs + gating) provides:
- **Reasonable accuracy** with **significantly lower complexity** than full Bayesian networks
- Interpretable factors for security teams
- Easy to calibrate and adjust

**What "reasonable accuracy with lower complexity" means:**

*Complexity Comparison:*
- **Full Bayesian Network**: Requires ~50-100 conditional probability tables (CPTs) to model all dependencies
  - Example: P(WAF_effective | Internet-facing, Attack_type, WAF_config, Patch_level, ...)
  - Each CPT needs empirical data from hundreds of observations, which simply, I don't have
  - Computational cost: O(n^2) or worse for inference with n variables
  - Implementation: 5,000-10,000 lines of code + extensive data collection

- **Present Approach**: Uses ~30 simple likelihood ratios with conditional logic
  - Example: LR(WAF | internet-facing) = 0.3, LR(WAF | internal) = 0.9
  - Each LR is a single heuristic estimate based on security principles
  - Computational cost: O(n) - simple multiplication
  - Implementation: ~500 lines of code + minimal calibration

*Accuracy Trade-off:*
- **Full Bayesian Network**: Could achieve greater prediction accuracy (if properly calibrated with extensive data)
- **Present Approach**: **Unverified estimate** - likely achieves reasonable relative ranking accuracy
  - **No empirical validation**: The "70-85%" figure is speculative, not tested against real breach data
  - Good enough for **prioritization** (which vulns to fix first) based on logical reasoning
  - Not precise enough for **absolute prediction** (exact exploitation probability)
  - **Key insight**: For vulnerability management, relative ranking matters more than absolute accuracy
  - **Validation needed**: Red team exercises or breach analysis required to confirm actual accuracy

---

## Factor 1: EPSS Score (Prior Probability)

**What it is:** EPSS predicts the probability that a vulnerability will be exploited in the wild within the next 30 days, based on real-world threat intelligence.

**How it's used:** As the starting point (prior) for Bayesian updating.

### Example

| CVE | EPSS Score | Interpretation |
|-----|------------|----------------|
| CVE-2021-44228 (Log4Shell) | 97.5% | Extremely likely to be exploited |
| CVE-2023-4039 | 0.1% | Very unlikely to be exploited |
| CVE-1999-0678 | 0.01% | Ancient, rarely targeted |

### Prior Floor Adjustments

When exploit availability data exists, we apply minimum floors to prevent underestimation:

| Condition | Minimum Prior |
|-----------|---------------|
| CISA KEV or Weaponized | 15% |
| Metasploit module | 10% |
| ExploitDB entry | 5% |
| Nuclei template | 3% |
| GitHub PoC | 1% |

**Example:** CVE-1999-0678 has EPSS of 0.01%, but ExploitDB has an exploit. The prior is raised to 5%.

---

## Factor 2: Exploit Availability (Threat Indicators)

**What it is:** Evidence that working exploit code exists, making exploitation more likely.

**Likelihood Ratios:**

| Indicator | LR | Effect | Source |
|-----------|-----|--------|--------|
| CISA KEV (Known Exploited) | 3.0 | +200% | CISA catalog |
| Weaponized in campaigns | 4.0 | +300% | Threat intel |
| Metasploit module | 2.5 | +150% | CVSS-BT |
| ExploitDB entry | 2.0 | +100% | CVSS-BT |
| Nuclei template | 1.8 | +80% | CVSS-BT |
| GitHub PoC | 1.5 | +50% | CVSS-BT |

### Example

**CVE-2023-44487 (HTTP/2 Rapid Reset)**
- EPSS: 0.5%
- CISA KEV: Yes (LR = 3.0)
- ExploitDB: Yes (LR = 2.0)
- GitHub PoC: Yes (LR = 1.5)

```
Prior adjusted: max(0.5%, 15%) = 15% (KEV floor)
Combined exploit LR: 3.0 x 2.0 x 1.5 = 9.0
```

This vulnerability gets a significant risk boost due to active exploitation.

---

## Factor 3: Security Controls (Exposure-Conditional)

**What it is:** Defensive measures that reduce the probability of successful exploitation.

**Key insight:** Control effectiveness depends on exposure context. A WAF is highly effective for internet-facing services but nearly useless for internal services.

### Exposure-Conditional Likelihood Ratios

#### WAF (Web Application Firewall)

| Exposure | LR | Risk Reduction | Rationale |
|----------|-----|----------------|-----------|
| Internet-facing | 0.3 | -70% | WAF blocks web attacks at perimeter |
| DMZ | 0.4 | -60% | Effective for DMZ web services |
| Internal | 0.9 | -10% | WAF rarely deployed internally |
| Restricted | 0.8 | -20% | Limited web traffic in restricted zones |

**Evidence Base:**
- Industry reports suggest WAF effectiveness ranges from 40-85% depending on configuration
- Conservative estimate (70% = LR 0.3) assumes properly configured WAF with updated rules
- Effectiveness highly dependent on: rule quality, false positive tuning, maintenance

#### Network Segmentation

| Exposure | LR | Risk Reduction | Rationale |
|----------|-----|----------------|-----------|
| Internet-facing | 0.5 | -50% | Limits blast radius from perimeter |
| DMZ | 0.4 | -60% | DMZ isolation by definition |
| Internal | 0.3 | -70% | **Most effective** - prevents lateral movement |
| Restricted | 0.2 | -80% | Critical for restricted zone isolation |

**Evidence Base:**
- Effectiveness varies widely: micro-segmentation (70-90%) vs basic VLANs (30-50%)
- Our estimates assume proper micro-segmentation with zero-trust principles
- Breach reports show segmentation significantly reduces lateral movement success rates

#### MFA (Multi-Factor Authentication)

| Exposure | LR | Risk Reduction | Rationale |
|----------|-----|----------------|-----------|
| Internet-facing | 0.2 | -80% | **Most effective** - blocks credential attacks |
| DMZ | 0.25 | -75% | Required for DMZ access |
| Internal | 0.5 | -50% | Internal auth often bypassed |
| Restricted | 0.2 | -80% | Critical for restricted access |

**Evidence Base:**
- Microsoft (2019): MFA blocks >99.9% of automated credential attacks (password spray, credential stuffing)
- **Important:** Does NOT cover phishing, SIM swapping, or push fatigue attacks
- Effectiveness varies by MFA type: FIDO2 (95%+) > Authenticator App (80-90%) > SMS (60-70%)
- Our conservative estimate (80% = LR 0.2) accounts for mixed MFA implementations

#### IDS/IPS

| Exposure | LR | Risk Reduction | Rationale |
|----------|-----|----------------|-----------|
| Internet-facing | 0.4 | -60% | Catches inbound attacks |
| DMZ | 0.45 | -55% | Strong monitoring |
| Internal | 0.7 | -30% | Less visibility internally |
| Restricted | 0.5 | -50% | Enhanced monitoring |

#### Privileged Access Management (PAM)

| Exposure | LR | Risk Reduction | Rationale |
|----------|-----|----------------|-----------|
| Internet-facing | 0.5 | -50% | Controls admin access |
| DMZ | 0.45 | -55% | Important for DMZ |
| Internal | 0.35 | -65% | **More effective** - admin access critical |
| Restricted | 0.25 | -75% | **Most effective** - strict access control |

#### Other Controls (Exposure-Independent)

| Control | LR | Risk Reduction |
|---------|-----|----------------|
| EDR/XDR | 0.4 | -60% |
| Antivirus | 0.7 | -30% |
| Incident Response Plan | 0.7 | -30% |
| Security Training | 0.8 | -20% |
| Air-gapped | 0.05 | -95% |

**Evidence Base:**
- Mandiant M-Trends 2024: Median dwell time decreased to 10 days (2023) from 16 days (2022)
- Improvement attributed to increased EDR/XDR adoption and threat intelligence
- EDR effectiveness ranges 40-80% depending on SOC maturity and configuration

### Patch Management

| Cadence | LR | Risk Reduction |
|---------|-----|----------------|
| Daily | 0.2 | -80% |
| Weekly | 0.4 | -60% |
| Monthly | 0.7 | -30% |
| Quarterly | 0.9 | -10% |

### Example: Same Controls, Different Exposure

**Internet-facing nginx with:**
- Firewall (LR = 0.4 for internet-facing)
- WAF (LR = 0.3 for internet-facing)
- IDS/IPS (LR = 0.4 for internet-facing)
- MFA (LR = 0.2 for internet-facing)

```
Combined control LR: 0.4 x 0.3 x 0.4 x 0.2 = 0.0096
Risk reduction: ~99%
```

**Internal redis with same controls:**
- Firewall (LR = 0.6 for internal)
- WAF (LR = 0.9 for internal)
- IDS/IPS (LR = 0.7 for internal)
- MFA (LR = 0.5 for internal)

```
Combined control LR: 0.6 x 0.9 x 0.7 x 0.5 = 0.189
Risk reduction: ~81%
```

**Result:** The same controls provide **99% reduction for internet-facing** but only **81% for internal** because WAF and MFA are less relevant internally.

---

## Factor 4: Exposure Context

**What it is:** How accessible the vulnerable service is to attackers.

**Likelihood Ratios:**

| Exposure | LR | Effect |
|----------|-----|--------|
| Internet-facing | 2.5 | +150% |
| DMZ | 1.8 | +80% |
| Internal | 0.6 | -40% |
| Restricted | 0.3 | -70% |
| Air-gapped | 0.1 | -90% |

### Exploitability Gating

**Important:** Exposure amplification (LR > 1) is only applied when exploitation is plausible:
- EPSS >= 5%, OR
- Known exploit exists (KEV, Metasploit, ExploitDB, etc.)

This prevents false inflation of risk for unexploitable vulnerabilities.

### Example

**CVE with no known exploits, EPSS 0.1%, internet-facing:**
```
Without gating: 0.1% x 2.5 = 0.25% (inflated)
With gating: 0.1% x 1.2 = 0.12% (capped at 1.2x)
```

**CVE with ExploitDB entry, EPSS 0.1%, internet-facing:**
```
Prior adjusted to 5% (ExploitDB floor)
Full exposure LR applied: 5% x 2.5 = 12.5%
```

---

## Factor 5: CVSS Vector Components

**What it is:** Attack characteristics from the CVSS vector string.

### Attack Vector (AV)

| Value | Internet-Facing LR | Internal LR |
|-------|-------------------|-------------|
| Network (N) | 2.0 | 1.0 |
| Adjacent (A) | 1.5 | 1.2 |
| Local (L) | 0.3 | 0.5 |
| Physical (P) | 0.1 | 0.2 |

### Attack Complexity (AC)

| Value | LR | Meaning |
|-------|-----|---------|
| Low (L) | 1.5 | Easy to exploit |
| High (H) | 0.5 | Requires special conditions |

### Privileges Required (PR)

| Value | LR | Meaning |
|-------|-----|---------|
| None (N) | 1.8 | Unauthenticated attack |
| Low (L) | 1.0 | Basic user privileges |
| High (H) | 0.5 | Admin privileges needed |

### User Interaction (UI)

| Value | LR | Meaning |
|-------|-----|---------|
| None (N) | 1.5 | Automated exploitation |
| Required (R) | 0.6 | Needs user action |

### Example

**CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H**

For an internet-facing service:
```
AV:N -> LR = 2.0 (network accessible)
AC:L -> LR = 1.5 (easy)
PR:N -> LR = 1.8 (no auth needed)
UI:N -> LR = 1.5 (automated)

Combined CVSS LR: 2.0 x 1.5 x 1.8 x 1.5 = 8.1
```

---

## Factor 6: Asset Criticality

**What it is:** Business value of the affected asset.

**Likelihood Ratios:**

| Asset Value | LR | Effect |
|-------------|-----|--------|
| Critical | 1.3 | +30% |
| High | 1.2 | +20% |
| Medium | 1.0 | No change |
| Low | 0.9 | -10% |

**Note:** Asset criticality amplification is also gated by exploitability.

### Example

**Secrets management server (critical asset) vs cache server (medium asset):**

Same vulnerability, same controls:
```
Critical asset: posterior x 1.3
Medium asset: posterior x 1.0
```

---

## Factor 7: Exposure-Based Security Controls

**What it is:** Security controls vary by service exposure type.

### Mandatory Controls by Exposure

| Exposure | Mandatory Controls |
|----------|-------------------|
| Internet-facing | Firewall, WAF, Antivirus |
| DMZ | Firewall, Antivirus, Network Segmentation |
| Internal | Firewall, Antivirus |
| Restricted | Firewall, Antivirus, Network Segmentation, MFA |

### Probability Modifiers

| Control | Internet-Facing | Internal |
|---------|-----------------|----------|
| WAF | 2.5x more likely | 0.3x less likely |
| IDS/IPS | 1.5x more likely | 0.7x less likely |
| MFA | 1.5x more likely | 0.7x less likely |
| SIEM | 1.3x more likely | 0.6x less likely |

### Example

**Same vulnerability on two services:**

| Service | Exposure | Controls | Risk |
|---------|----------|----------|------|
| nginx | internet-facing | WAF, IDS, MFA, SIEM | Medium (5.9%) |
| redis | internal | Firewall, AV only | Medium (7.0%) |

The internal redis has higher risk because it has fewer controls, despite being less exposed.

---

## Posterior Floors

**What it is:** Minimum risk levels to prevent misleading "Negligible" ratings for actively exploited vulnerabilities.

| Condition | Minimum Posterior |
|-----------|-------------------|
| CISA KEV or Weaponized | 5% (Medium) |
| Metasploit module | 3% (Low) |
| ExploitDB entry | 2% (Low) |
| Nuclei template | 1.5% (Low) |
| GitHub PoC | 1% (Low) |

### Example

**CVE-2023-4911 (Looney Tunables)**
- CISA KEV: Yes
- Calculated posterior after controls: 0.5%
- Floor applied: max(0.5%, 5%) = **5% (Medium)**

Without the floor, this actively exploited vulnerability would be rated "Negligible" due to strong security controls. The floor ensures defenders are still alerted.

---

## Risk Categories

| Category | Posterior Probability | Action |
|----------|----------------------|--------|
| **Critical** | >= 40% | Fix immediately |
| **High** | >= 15% | Fix this sprint |
| **Medium** | >= 5% | Plan fix |
| **Low** | >= 1% | Backlog |
| **Negligible** | < 1% | Accept risk |

---

## Complete Example

**CVE-2023-44487 (HTTP/2 Rapid Reset) on internet-facing nginx:**

### Inputs
- EPSS: 0.5%
- CISA KEV: Yes
- ExploitDB: Yes
- GitHub PoC: Yes
- CVSS: 7.5 (AV:N/AC:L/PR:N/UI:N)
- Exposure: internet-facing
- Asset Value: medium
- Controls: Firewall, WAF, IDS/IPS, MFA, Antivirus

### Calculation

```
1. Prior adjustment (KEV floor):
   Prior = max(0.5%, 15%) = 15%

2. Threat indicator LRs:
   KEV: 3.0
   ExploitDB: 2.0
   PoC: 1.5
   Combined: 3.0 x 2.0 x 1.5 = 9.0

3. Security control LRs:
   Firewall: 0.5
   WAF: 0.4
   IDS/IPS: 0.5
   MFA: 0.3
   Antivirus: 0.7
   Combined: 0.5 x 0.4 x 0.5 x 0.3 x 0.7 = 0.021

4. Exposure LR (exploitation plausible):
   Internet-facing: 2.5

5. CVSS vector LRs:
   AV:N x AC:L x PR:N x UI:N = 2.0 x 1.5 x 1.8 x 1.5 = 8.1

6. Total LR:
   9.0 x 0.021 x 2.5 x 8.1 = 3.83

7. Posterior calculation:
   Prior odds = 0.15 / 0.85 = 0.176
   Posterior odds = 0.176 x 3.83 = 0.674
   Posterior = 0.674 / 1.674 = 40.3%

8. Floor check:
   KEV floor = 5%
   Posterior (40.3%) > floor (5%) ✓

9. Final: Critical (40.3%)
```

### Result

| Metric | Value |
|--------|-------|
| Prior (EPSS) | 0.5% |
| Adjusted Prior | 15% |
| Posterior | 40.3% |
| Risk Category | **Critical** |
| Credible Interval | [28%-52%] |

---

## Summary

The Bayesian risk assessment considers:

1. **EPSS** - Real-world exploitation probability (prior)
2. **Exploit Availability** - KEV, Metasploit, ExploitDB, Nuclei, PoC
3. **Security Controls** - Network, endpoint, access, patch management
4. **Exposure** - Internet-facing, DMZ, internal, restricted
5. **CVSS Vector** - Attack characteristics
6. **Asset Criticality** - Business value
7. **Exposure-Based Controls** - Per-service control generation

Key features:
- **Exploitability gating** prevents false inflation
- **Prior floors** ensure exploited vulns aren't underestimated
- **Posterior floors** prevent misleading "Negligible" ratings
- **Per-service controls** reflect realistic security postures

This approach provides actionable risk prioritization that considers your specific environment, not just theoretical CVSS scores.

---

## Methodology Limitations and Validation

### What This Framework Provides
- ✅ **Relative risk prioritization**: Rank vulnerabilities by actual threat level
- ✅ **Context-aware assessment**: Considers your security controls and exposure
- ✅ **Principled approach**: Bayesian inference with likelihood ratios
- ✅ **Transparency**: Clear rationale for each risk decision

### What This Framework Does NOT Provide
- ❌ **Absolute probability prediction**: Exact exploitation likelihood percentages
- ❌ **Empirically validated LR values**: Values are heuristic estimates
- ❌ **Guaranteed accuracy**: Actual outcomes depend on many unmeasured factors
- ❌ **Replacement for expert judgment**: Framework assists, not replaces, security decisions

### Validation Recommendations
1. **Red Team Testing**: Validate kill-chain probabilities against actual penetration tests
2. **Breach Analysis**: Compare model predictions to observed breach patterns
3. **Calibration**: Adjust LR values based on your organization's historical data
4. **Continuous Improvement**: Update estimates as new threat intelligence emerges

### References
- Microsoft (2019). "One simple action you can take to prevent 99.9 percent of attacks on your accounts". Microsoft Security Blog. https://www.microsoft.com/en-us/security/blog/2019/08/20/one-simple-action-you-can-take-to-prevent-99-9-percent-of-account-attacks/
- Mandiant (2024). "M-Trends 2024: A Deep Dive into Evolving Cyber Threats and Effective Defenses". https://services.google.com/fh/files/misc/m-trends-2024.pdf
