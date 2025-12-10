# Bayesian Risk Assessment

This document explains how the CVEs Analytics pipeline calculates vulnerability risk using a principled Bayesian approach.

## Overview

Traditional vulnerability scoring (CVSS alone) often leads to "alert fatigue" because it doesn't consider:
- Real-world exploitation probability
- Your specific security controls
- Asset exposure and criticality

Our Bayesian approach addresses this by:
1. Starting with **EPSS** (Exploit Prediction Scoring System) as the prior probability
2. Updating with **likelihood ratios** based on your environment
3. Applying **floors** to ensure actively exploited vulnerabilities are never rated "Negligible"

## Mathematical Foundation

```
Posterior Odds = Prior Odds × LR₁ × LR₂ × ... × LRₙ
```

Where:
- **Prior Odds** = EPSS / (1 - EPSS)
- **LR < 1** = Evidence that reduces exploitation probability (security controls)
- **LR > 1** = Evidence that increases exploitation probability (exposure, exploits)
- **LR = 1** = Uninformative evidence

The posterior probability is then converted back from odds and categorized into risk levels.

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
Combined exploit LR: 3.0 × 2.0 × 1.5 = 9.0
```

This vulnerability gets a significant risk boost due to active exploitation.

---

## Factor 3: Security Controls

**What it is:** Defensive measures that reduce the probability of successful exploitation.

**Likelihood Ratios (all < 1.0, reducing risk):**

### Network Controls

| Control | LR | Risk Reduction |
|---------|-----|----------------|
| Network Segmentation | 0.3 | -70% |
| Firewall | 0.5 | -50% |
| WAF (Web Application Firewall) | 0.4 | -60% |
| IDS/IPS | 0.5 | -50% |

### Endpoint Controls

| Control | LR | Risk Reduction |
|---------|-----|----------------|
| EDR/XDR | 0.4 | -60% |
| Antivirus | 0.7 | -30% |

### Access Controls

| Control | LR | Risk Reduction |
|---------|-----|----------------|
| MFA | 0.3 | -70% |
| Privileged Access Management | 0.4 | -60% |

### Patch Management

| Cadence | LR | Risk Reduction |
|---------|-----|----------------|
| Daily | 0.2 | -80% |
| Weekly | 0.4 | -60% |
| Monthly | 0.7 | -30% |
| Quarterly | 0.9 | -10% |

### Example

**Internal database server with:**
- Firewall (LR = 0.5)
- Network Segmentation (LR = 0.3)
- MFA (LR = 0.3)
- Monthly patching (LR = 0.7)

```
Combined control LR: 0.5 × 0.3 × 0.3 × 0.7 = 0.0315
Risk reduction: ~97%
```

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
- EPSS ≥ 5%, OR
- Known exploit exists (KEV, Metasploit, ExploitDB, etc.)

This prevents false inflation of risk for unexploitable vulnerabilities.

### Example

**CVE with no known exploits, EPSS 0.1%, internet-facing:**
```
Without gating: 0.1% × 2.5 = 0.25% (inflated)
With gating: 0.1% × 1.2 = 0.12% (capped at 1.2x)
```

**CVE with ExploitDB entry, EPSS 0.1%, internet-facing:**
```
Prior adjusted to 5% (ExploitDB floor)
Full exposure LR applied: 5% × 2.5 = 12.5%
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
AV:N → LR = 2.0 (network accessible)
AC:L → LR = 1.5 (easy)
PR:N → LR = 1.8 (no auth needed)
UI:N → LR = 1.5 (automated)

Combined CVSS LR: 2.0 × 1.5 × 1.8 × 1.5 = 8.1
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
Critical asset: posterior × 1.3
Medium asset: posterior × 1.0
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
| **Critical** | ≥ 40% | Fix immediately |
| **High** | ≥ 15% | Fix this sprint |
| **Medium** | ≥ 5% | Plan fix |
| **Low** | ≥ 1% | Backlog |
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
   Combined: 3.0 × 2.0 × 1.5 = 9.0

3. Security control LRs:
   Firewall: 0.5
   WAF: 0.4
   IDS/IPS: 0.5
   MFA: 0.3
   Antivirus: 0.7
   Combined: 0.5 × 0.4 × 0.5 × 0.3 × 0.7 = 0.021

4. Exposure LR (exploitation plausible):
   Internet-facing: 2.5

5. CVSS vector LRs:
   AV:N: 2.0
   AC:L: 1.5
   PR:N: 1.8
   UI:N: 1.5
   Combined: 8.1

6. Total LR:
   9.0 × 0.021 × 2.5 × 8.1 = 3.83

7. Posterior calculation:
   Prior odds = 0.15 / 0.85 = 0.176
   Posterior odds = 0.176 × 3.83 = 0.674
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
