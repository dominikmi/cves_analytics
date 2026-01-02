# Security Controls Configuration Guide

**Version:** 2.0  
**Last Updated:** January 2, 2026  
**Audience:** Security analysts, risk assessors, configuration managers

---

## Table of Contents

1. [Introduction](#introduction)
2. [Environment Generation Process](#environment-generation-process)
3. [Control Types System](#control-types-system)
4. [Understanding Likelihood Ratios](#understanding-likelihood-ratios)
5. [Control Categories](#control-categories)
6. [Control Correlations](#control-correlations)
7. [Maturity Levels](#maturity-levels)
8. [Sector-Specific Adjustments](#sector-specific-adjustments)
9. [How to Adjust Values](#how-to-adjust-values)
10. [Common Scenarios](#common-scenarios)
11. [References](#references)

---

## Introduction

This guide explains the security controls configuration system used in the CVE Analytics platform. The configuration defines how security controls affect vulnerability exploitation probability using Bayesian inference.

> **WARNING - Important Note on Default Values:**
> All likelihood ratio (LR) default values in this guide are **heuristic estimates** based on security principles, industry observations, and conservative assumptions. They are NOT empirically validated through controlled studies. Actual control effectiveness varies significantly based on:
> - Implementation quality and configuration
> - Organizational maturity and processes
> - Threat actor sophistication
> - Exposure context (internet-facing vs internal)
> 
> These defaults provide a reasonable starting point for relative risk assessment. Organizations should calibrate values based on their own red team exercises, breach analysis, and security testing.

### What This Configuration Controls

- **Exploitation Probability**: How likely a vulnerability is to be successfully exploited
- **Control Effectiveness**: How much each security control reduces risk
- **Organizational Realism**: How controls appear together based on maturity and sector
- **Risk Assessment Accuracy**: More realistic scenarios = better risk predictions

### Who Should Modify These Values

- Security architects validating control effectiveness
- Risk analysts calibrating for specific organizations
- Researchers studying security control efficacy
- Compliance teams aligning with regulatory requirements

---

## Environment Generation Process

### Overview

The system generates realistic security environments using a **probabilistic control types approach**. Instead of simple boolean controls (present/absent), each control has multiple implementation types with varying effectiveness levels.

### Generation Flow Diagram

```
+------------------+
|  Input Parameters|
|  - Maturity      |
|  - Industry      |
|  - Size          |
|  - Environment   |
+--------+---------+
         |
         v
+------------------+
| Step 1: Select   |
| Base Probability |
| Distribution     |
| (by maturity)    |
+--------+---------+
         |
         v
+------------------+
| Step 2: Apply    |
| Industry         |
| Modifiers        |
| (e.g., finance   |
|  -> stronger MFA)|
+--------+---------+
         |
         v
+------------------+
| Step 3: Apply    |
| Exposure         |
| Modifiers        |
| (internet-facing |
|  -> stronger WAF)|
+--------+---------+
         |
         v
+------------------+
| Step 4: Normalize|
| Probabilities    |
| (sum to 1.0)     |
+--------+---------+
         |
         v
+------------------+
| Step 5: Random   |
| Selection        |
| (weighted choice)|
+--------+---------+
         |
         v
+------------------+
| Output: Control  |
| Types with       |
| Effectiveness    |
| Values (LR)      |
+------------------+
```

### Step-by-Step Process

#### Step 1: Select Base Probability Distribution

Each control has probability distributions based on security maturity level:

**Example: MFA Type Distribution**
```
Initial (Level 1):
  - None: 70%
  - SMS: 25%
  - Authenticator App: 5%
  - Push Notification: 0%
  - FIDO2: 0%

Managed (Level 4):
  - None: 5%
  - SMS: 15%
  - Authenticator App: 30%
  - Push Notification: 35%
  - FIDO2: 15%

Optimizing (Level 5):
  - None: 0%
  - SMS: 5%
  - Authenticator App: 20%
  - Push Notification: 35%
  - FIDO2: 40%
```

#### Step 2: Apply Industry Modifiers

Industry characteristics adjust probabilities:

**Example: Financial Services**
```
Modifiers:
  - FIDO2: x1.8 (80% more likely)
  - Push Notification: x1.3 (30% more likely)
  - SMS: x0.6 (40% less likely)

Result for Managed Financial Services:
  - None: 5%
  - SMS: 9% (15% x 0.6)
  - Authenticator App: 30%
  - Push Notification: 45.5% (35% x 1.3)
  - FIDO2: 27% (15% x 1.8)
  (then normalized to sum to 100%)
```

**Example: Small Business**
```
Modifiers:
  - SMS: x1.5 (50% more likely)
  - FIDO2: x0.3 (70% less likely)

Result for Managed Small Business:
  - None: 5%
  - SMS: 22.5% (15% x 1.5)
  - Authenticator App: 30%
  - Push Notification: 35%
  - FIDO2: 4.5% (15% x 0.3)
  (then normalized to sum to 100%)
```

#### Step 3: Apply Exposure Modifiers

Service exposure adjusts probabilities for certain controls:

**Example: Internet-Facing Service**
```
Modifiers:
  - FIDO2: x1.4 (40% more likely)
  - Push Notification: x1.3 (30% more likely)
  - SMS: x0.7 (30% less likely)

Applied to financial services result:
  - FIDO2: 37.8% (27% x 1.4)
  - Push Notification: 59.15% (45.5% x 1.3)
  - SMS: 6.3% (9% x 0.7)
  (then normalized)
```

#### Step 4: Normalize Probabilities

Ensure all probabilities sum to exactly 1.0:

```python
total = sum(all_probabilities)
normalized = {type: prob / total for type, prob in probabilities.items()}
```

#### Step 5: Random Selection

Use weighted random selection to choose control type:

```python
import random
control_type = random.choices(
    population=list(probabilities.keys()),
    weights=list(probabilities.values()),
    k=1
)[0]
```

### Realistic Variability

This approach creates realistic variability:

**Scenario 1: Optimizing Financial Services**
- 10 environments generated
- MFA types: 6x FIDO2, 3x Push, 1x Authenticator App
- Result: Mostly strong MFA, but some legacy systems remain

**Scenario 2: Initial Small Business**
- 10 environments generated
- MFA types: 7x None, 2x SMS, 1x Authenticator App
- Result: Mostly no MFA, reflecting resource constraints

### Why This Matters

1. **Realistic Risk Assessment**: Organizations don't have uniform controls
2. **Better Predictions**: Accounts for implementation quality variations
3. **Industry Patterns**: Financial services really do have better MFA
4. **Maturity Progression**: Clear evolution path from basic to advanced

---

## Control Types System

### Overview

Each major security control now has **multiple implementation types** with varying effectiveness levels. This replaces the previous boolean (present/absent) model.

### Control Type Categories

#### 1. Multi-Factor Authentication (MFA)

**Types:**
```
None:                LR = 1.0  (0% reduction)
SMS:                 LR = 0.35 (65% reduction)
Authenticator App:   LR = 0.15 (85% reduction)
Push Notification:   LR = 0.15 (85% reduction)
FIDO2:               LR = 0.05 (95% reduction)
```

**Effectiveness Rationale:**
- **FIDO2/Hardware Tokens**: Strongest - phishing-resistant, cryptographic
- **Authenticator Apps/Push**: Strong - time-based or push approval
- **SMS**: Weak - vulnerable to SIM swapping, interception
- **Evidence**: Microsoft (2019) - MFA blocks >99.9% of automated attacks

**When to Use:**
- FIDO2: High-security environments, compliance requirements
- Authenticator App: Standard enterprise deployment
- SMS: Legacy systems, user convenience priority

#### 2. Firewall

**Types:**
```
None:                LR = 1.0  (0% reduction)
Basic:               LR = 0.7  (30% reduction)
Stateful:            LR = 0.5  (50% reduction)
Next-Gen (NGFW):     LR = 0.4  (60% reduction)
NGFW Advanced:       LR = 0.3  (70% reduction)
```

**Effectiveness Rationale:**
- **NGFW Advanced**: Deep packet inspection + threat intelligence
- **NGFW**: Application awareness, IPS integration
- **Stateful**: Connection tracking, basic filtering
- **Basic**: Simple packet filtering only

#### 3. Web Application Firewall (WAF)

**Types:**
```
None:                LR = 1.0  (0% reduction)
Basic:               LR = 0.6  (40% reduction)
Managed:             LR = 0.4  (60% reduction)
OWASP CRS:           LR = 0.3  (70% reduction)
Custom Tuned:        LR = 0.25 (75% reduction)
```

**Effectiveness Rationale:**
- **Custom Tuned**: ML/behavioral analysis, application-specific rules
- **OWASP CRS**: Comprehensive rule set, regularly updated
- **Managed**: Cloud-based, vendor-managed rules
- **Basic**: Minimal rule set, limited coverage

#### 4. Endpoint Protection

**Types:**
```
None:                LR = 1.0  (0% reduction)
Traditional AV:      LR = 0.7  (30% reduction)
Basic EDR:           LR = 0.5  (50% reduction)
Advanced EDR:        LR = 0.4  (60% reduction)
XDR:                 LR = 0.3  (70% reduction)
```

**Effectiveness Rationale:**
- **XDR**: Extended detection across endpoints, network, cloud
- **Advanced EDR**: Behavioral analysis, threat hunting
- **Basic EDR**: Endpoint detection and response
- **Traditional AV**: Signature-based only
- **Evidence**: Mandiant M-Trends 2024 - EDR adoption reduced dwell time

#### 5. Network Segmentation

**Types:**
```
None:                LR = 1.0  (0% reduction)
Basic VLAN:          LR = 0.7  (30% reduction)
VLAN + ACL:          LR = 0.5  (50% reduction)
Micro-Segmentation:  LR = 0.3  (70% reduction)
Zero Trust:          LR = 0.2  (80% reduction)
```

**Effectiveness Rationale:**
- **Zero Trust**: Continuous verification, least privilege
- **Micro-Segmentation**: Granular workload isolation
- **VLAN + ACL**: Network zones with access controls
- **Basic VLAN**: Simple network separation

#### 6. IDS/IPS

**Types:**
```
None:                LR = 1.0  (0% reduction)
IDS Only:            LR = 0.8  (20% reduction)
IPS Signature:       LR = 0.5  (50% reduction)
IPS Behavioral:      LR = 0.4  (60% reduction)
IPS ML:              LR = 0.35 (65% reduction)
```

**Effectiveness Rationale:**
- **IPS ML**: Machine learning-based detection
- **IPS Behavioral**: Anomaly detection
- **IPS Signature**: Pattern matching with blocking
- **IDS Only**: Detection without prevention

#### 7. SIEM Maturity

**Types:**
```
None:                LR = 1.0  (0% reduction)
Log Collection:      LR = 0.8  (20% reduction)
Basic Correlation:   LR = 0.6  (40% reduction)
Advanced Analytics:  LR = 0.5  (50% reduction)
Threat Hunting:      LR = 0.4  (60% reduction)
```

**Effectiveness Rationale:**
- **Threat Hunting**: Active hunting + SOAR automation
- **Advanced Analytics**: ML-based detection, correlation
- **Basic Correlation**: Rule-based alerting
- **Log Collection**: Visibility only, no analysis

#### 8. Patch Management Quality

**Types:**
```
None:                LR = 1.0  (0% reduction)
Reactive:            LR = 0.9  (10% reduction)
Quarterly:           LR = 0.7  (30% reduction)
Monthly:             LR = 0.4  (60% reduction)
Weekly:              LR = 0.3  (70% reduction)
Automated:           LR = 0.2  (80% reduction)
```

**Effectiveness Rationale:**
- **Automated**: Continuous patching with testing
- **Weekly**: Critical patches within 7 days
- **Monthly**: Patch Tuesday cycle
- **Quarterly**: Scheduled maintenance windows
- **Reactive**: Only after incidents

### Control Type Selection Algorithm

```python
def select_control_type(maturity, industry, exposure=None):
    # 1. Get base probabilities for maturity level
    base_probs = BASE_PROBABILITIES[control][maturity]
    
    # 2. Apply industry modifiers
    if industry in INDUSTRY_MODIFIERS:
        for control_type, multiplier in INDUSTRY_MODIFIERS[industry][control].items():
            base_probs[control_type] *= multiplier
    
    # 3. Apply exposure modifiers (if applicable)
    if exposure and exposure in EXPOSURE_MODIFIERS:
        for control_type, multiplier in EXPOSURE_MODIFIERS[exposure][control].items():
            base_probs[control_type] *= multiplier
    
    # 4. Normalize to sum to 1.0
    total = sum(base_probs.values())
    normalized = {k: v/total for k, v in base_probs.items()}
    
    # 5. Random weighted selection
    return random.choices(
        population=list(normalized.keys()),
        weights=list(normalized.values()),
        k=1
    )[0]
```

---

## Understanding Likelihood Ratios

### What is a Likelihood Ratio (LR)?

A **Likelihood Ratio** represents how much a security control changes the probability of successful exploitation.

**Formula:**
```
LR = P(Exploitation | Control Present) / P(Exploitation | Control Absent)
```

### Interpretation

| LR Value | Meaning | Example |
|----------|---------|---------|
| **0.1** | 90% reduction | Control blocks 9 out of 10 attacks |
| **0.3** | 70% reduction | Control blocks 7 out of 10 attacks |
| **0.5** | 50% reduction | Control blocks half of attacks |
| **0.7** | 30% reduction | Control blocks 3 out of 10 attacks |
| **0.9** | 10% reduction | Control blocks 1 out of 10 attacks |
| **1.0** | No effect | Control doesn't help |
| **2.0** | 100% increase | Factor doubles exploitation risk |
| **3.0** | 200% increase | Factor triples exploitation risk |

### Example: Web Application Firewall (WAF)

```yaml
waf:
  default: 0.4  # 60% reduction
  description: "Blocks SQL injection, XSS, and other web attacks"
```

**What this means:**
- Without WAF: 100% of web attacks reach the application
- With WAF: Only 40% of web attacks reach the application
- **Effectiveness: 60% of attacks blocked**

**Basis:**
- **Heuristic estimate**: Industry observations suggest WAF effectiveness ranges from 40-85%
- Conservative default (60% = LR 0.4) assumes properly configured WAF
- Effectiveness highly dependent on: rule quality, tuning, maintenance
- See BAYESIAN_RISK_ASSESSMENT.md for exposure-conditional values

---

## Control Categories

### 1. Network Controls

**Purpose:** Protect network perimeter and internal traffic

#### Firewall
```yaml
firewall:
  default: 0.5  # 50% reduction
```
- **What it does:** Blocks unauthorized network connections
- **Effectiveness:** Moderate - blocks known bad IPs/ports
- **Limitations:** Doesn't inspect application-layer attacks
- **When to adjust:** 
  - Increase (0.3-0.4) if next-gen firewall with deep packet inspection
  - Decrease (0.6-0.7) if legacy firewall with basic rules

#### Web Application Firewall (WAF)
```yaml
waf:
  default: 0.4  # 60% reduction (exposure-independent baseline)
  # Exposure-conditional: 0.3 (internet), 0.4 (DMZ), 0.9 (internal)
```
- **What it does:** Blocks OWASP Top 10 attacks (SQLi, XSS, etc.)
- **Effectiveness:** High for web attacks (40-85% range)
- **Limitations:** Requires tuning, can have false positives
- **Note:** Effectiveness is **exposure-conditional** - see BAYESIAN_RISK_ASSESSMENT.md
- **When to adjust:**
  - Use 0.3 for well-tuned WAF with OWASP Core Rule Set
  - Use 0.5-0.6 for basic WAF with minimal rules

#### IDS/IPS (Intrusion Detection/Prevention)
```yaml
ids_ips:
  default: 0.5  # 50% reduction (baseline)
  # Exposure-conditional: 0.4 (internet), 0.45 (DMZ), 0.7 (internal), 0.5 (restricted)
```
- **What it does:** Detects and blocks known attack patterns
- **Effectiveness:** Moderate - signature-based detection (30-60% range)
- **Limitations:** Misses zero-days, requires signature updates
- **Note:** Most effective at perimeter (internet-facing), less effective internally
- **When to adjust:**
  - Use 0.4 for IPS with behavioral analysis at perimeter
  - Use 0.6 for IDS only (detection, no prevention)
  - Use 0.7 for internal deployment (less visibility)

#### Network Segmentation
```yaml
network_segmentation:
  default: 0.3  # 70% reduction (baseline for internal)
  # Exposure-conditional: 0.5 (internet), 0.4 (DMZ), 0.3 (internal), 0.2 (restricted)
```
- **What it does:** Isolates network zones to prevent lateral movement
- **Effectiveness:** Very high - strongest network control (30-90% range)
- **Evidence:** Effectiveness varies: micro-segmentation (70-90%) vs basic VLANs (30-50%)
- **Limitations:** Complex to implement, requires architecture changes
- **Note:** Most effective for **internal** lateral movement prevention
- **When to adjust:**
  - Use 0.2-0.3 for proper micro-segmentation with zero-trust
  - Use 0.5 for basic VLAN separation only
  - **Critical:** This is the most effective network control for internal threats

#### Zero Trust Network Access (ZTNA)
```yaml
zero_trust:
  default: 0.3  # 70% reduction
```
- **What it does:** Verify every access request, never trust by default
- **Effectiveness:** Very high - modern security architecture
- **Limitations:** Requires complete infrastructure overhaul
- **When to adjust:**
  - Keep at 0.3 for full zero trust implementation
  - Increase to 0.5 if partial zero trust (hybrid)

---

### 2. Endpoint Controls

**Purpose:** Protect individual devices (laptops, servers, workstations)

#### EDR/XDR (Endpoint Detection & Response)
```yaml
edr_xdr:
  default: 0.4  # 60% reduction
```
- **What it does:** Behavioral detection, blocks malicious execution
- **Effectiveness:** High - catches unknown malware (40-80% range)
- **Evidence:** Mandiant M-Trends 2024 - Median dwell time decreased to 10 days (2023) from 16 days (2022), attributed to increased EDR/XDR adoption
- **Limitations:** Requires tuning, can impact performance
- **Note:** Effectiveness depends heavily on SOC maturity and configuration
- **When to adjust:**
  - Use 0.4 for mature EDR/XDR (CrowdStrike, SentinelOne) with active SOC
  - Use 0.5 for basic endpoint protection without SOC
  - Use 0.3 for elite EDR with 24/7 threat hunting

#### Traditional Antivirus
```yaml
antivirus:
  default: 0.7  # 30% reduction
```
- **What it does:** Signature-based malware detection
- **Effectiveness:** Low - misses modern threats
- **Limitations:** Only catches known malware
- **When to adjust:**
  - Keep at 0.7 (legacy control, limited effectiveness)
  - **Note:** EDR replaces antivirus in modern environments

#### Application Whitelisting
```yaml
application_whitelisting:
  default: 0.3  # 70% reduction
```
- **What it does:** Only approved applications can execute
- **Effectiveness:** Very high - blocks all unauthorized execution
- **Limitations:** High management overhead, can break workflows
- **When to adjust:**
  - Keep at 0.3 for strict whitelisting
  - Increase to 0.5 if blacklisting mode (blocks known bad)

#### Device Encryption
```yaml
device_encryption:
  default: 0.5  # 50% reduction
```
- **What it does:** Full disk encryption (BitLocker, FileVault)
- **Effectiveness:** Moderate - protects data at rest
- **Limitations:** Doesn't prevent exploitation, only data theft
- **When to adjust:**
  - Keep at 0.5 (standard effectiveness)
  - **Note:** Reduces impact, not exploitation likelihood

---

### 3. Access Controls

**Purpose:** Control who can access what resources

#### Multi-Factor Authentication (MFA)
```yaml
mfa:
  default: 0.3  # 70% reduction (exposure-independent baseline)
  # Exposure-conditional: 0.2 (internet), 0.25 (DMZ), 0.5 (internal)
```
- **What it does:** Requires 2+ authentication factors
- **Effectiveness:** Very high for automated credential attacks (80-99%+ range)
- **Evidence:** Microsoft (2019) - MFA blocks >99.9% of automated credential attacks
- **Limitations:** Does NOT cover phishing, SIM swapping, or push fatigue attacks
- **Note:** Effectiveness is **exposure-conditional** and **MFA-type dependent**
  - FIDO2/hardware tokens: 95%+ effectiveness (LR 0.05-0.2)
  - Authenticator apps: 80-90% effectiveness (LR 0.1-0.2)
  - SMS-based: 60-70% effectiveness (LR 0.3-0.4)
- **When to adjust:**
  - Use 0.2 for strong MFA (FIDO2, hardware tokens) on internet-facing
  - Use 0.4 for SMS-based MFA (weaker)
  - **Critical:** One of the most effective controls

#### Privileged Access Management (PAM)
```yaml
privileged_access_mgmt:
  default: 0.4  # 60% reduction
```
- **What it does:** Manages and monitors admin account access
- **Effectiveness:** High - prevents privilege escalation
- **Limitations:** Requires process changes, can slow workflows
- **When to adjust:**
  - Keep at 0.4 for full PAM solution (CyberArk, BeyondTrust)
  - Increase to 0.6 for basic privileged account management

#### Just-In-Time (JIT) Access
```yaml
jit_access:
  default: 0.4  # 60% reduction
```
- **What it does:** Temporary elevated privileges, expires automatically
- **Effectiveness:** High - reduces standing privileges
- **Limitations:** Requires automation, workflow integration
- **When to adjust:**
  - Keep at 0.4 for automated JIT
  - Increase to 0.5 if manual approval process

#### Role-Based Access Control (RBAC)
```yaml
rbac:
  default: 0.6  # 40% reduction
```
- **What it does:** Assigns permissions based on job roles
- **Effectiveness:** Moderate - reduces attack surface
- **Limitations:** Role creep, over-privileged roles common
- **When to adjust:**
  - Keep at 0.6 for standard RBAC
  - Increase to 0.7 if poorly maintained (role creep)

---

### 4. Security Operations

**Purpose:** Detect, respond to, and recover from security incidents

#### SIEM (Security Information & Event Management)
```yaml
siem:
  default: 0.6  # 40% reduction
```
- **What it does:** Aggregates and analyzes security logs
- **Effectiveness:** Moderate - detection capability
- **Limitations:** Requires tuning, skilled analysts
- **When to adjust:**
  - Keep at 0.6 for standard SIEM (Splunk, QRadar)
  - Increase to 0.5 if SIEM with advanced analytics
  - Increase to 0.7 if SIEM with poor coverage

#### SOC 24x7 (Security Operations Center)
```yaml
soc_24x7:
  default: 0.5  # 50% reduction
```
- **What it does:** Continuous security monitoring and response
- **Effectiveness:** High - human analysis and response
- **Limitations:** Expensive, requires skilled staff
- **When to adjust:**
  - Keep at 0.5 for mature SOC with skilled analysts
  - Increase to 0.6 for basic SOC or outsourced SOC
  - Decrease to 0.4 for elite SOC (FAANG-level)

#### SOAR (Security Orchestration, Automation & Response)
```yaml
soar:
  default: 0.5  # 50% reduction
```
- **What it does:** Automates incident response workflows
- **Effectiveness:** High - faster response than manual
- **Limitations:** Requires SIEM, complex to implement
- **When to adjust:**
  - Keep at 0.5 for mature SOAR implementation
  - Increase to 0.6 if basic automation only

#### Threat Intelligence
```yaml
threat_intelligence:
  default: 0.6  # 40% reduction
```
- **What it does:** Threat feeds, IOCs, adversary TTPs
- **Effectiveness:** Moderate - proactive threat awareness
- **Limitations:** Requires integration, actionable intel rare
- **When to adjust:**
  - Keep at 0.6 for commercial threat intel feeds
  - Increase to 0.5 if threat intel with automated blocking

#### Vulnerability Management
```yaml
vulnerability_management:
  default: 0.5  # 50% reduction
```
- **What it does:** Regular vulnerability scanning and remediation
- **Effectiveness:** High - reduces attack surface
- **Limitations:** Requires patching discipline
- **When to adjust:**
  - Keep at 0.5 for mature vuln mgmt program
  - Increase to 0.7 if ad-hoc scanning only

---

### 5. Data Protection

**Purpose:** Protect sensitive data from theft or destruction

#### Data Loss Prevention (DLP)
```yaml
data_loss_prevention:
  default: 0.3  # 70% reduction
```
- **What it does:** Monitors and blocks unauthorized data transfers
- **Effectiveness:** Very high - prevents exfiltration
- **Limitations:** High false positive rate, requires tuning
- **When to adjust:**
  - Keep at 0.3 for enterprise DLP (Symantec, Forcepoint)
  - Increase to 0.5 for basic DLP (email only)

#### Encryption at Rest
```yaml
encryption_at_rest:
  default: 0.5  # 50% reduction
```
- **What it does:** Encrypts stored data (databases, files)
- **Effectiveness:** Moderate - data less useful if stolen
- **Limitations:** Doesn't prevent access, only protects stolen data
- **When to adjust:**
  - Keep at 0.5 (standard effectiveness)
  - **Note:** Reduces impact, not exploitation

#### Backup & Recovery
```yaml
backup_recovery:
  default: 0.6  # 40% reduction
```
- **What it does:** Regular backups enable recovery from ransomware
- **Effectiveness:** Moderate - reduces ransomware impact
- **Limitations:** Doesn't prevent attack, only enables recovery
- **When to adjust:**
  - Keep at 0.6 for regular backups
  - Increase to 0.7 if infrequent backups
  - **Note:** Reduces impact, not exploitation

---

### 6. Application Security

**Purpose:** Secure applications during development and runtime

#### Secure SDLC
```yaml
secure_sdlc:
  default: 0.6  # 40% reduction
```
- **What it does:** Security integrated into development process
- **Effectiveness:** Moderate - prevents vulnerabilities
- **Limitations:** Requires culture change, slows development
- **When to adjust:**
  - Keep at 0.6 for mature secure SDLC
  - Increase to 0.8 if minimal security in SDLC

#### SAST/DAST (Static/Dynamic Application Security Testing)
```yaml
sast_dast:
  default: 0.6  # 40% reduction
```
- **What it does:** Automated security testing of applications
- **Effectiveness:** Moderate - catches common vulnerabilities
- **Limitations:** High false positives, misses business logic flaws
- **When to adjust:**
  - Keep at 0.6 for both SAST and DAST
  - Increase to 0.7 if SAST only (no runtime testing)

#### Software Composition Analysis (SCA)
```yaml
software_composition_analysis:
  default: 0.6  # 40% reduction
```
- **What it does:** Scans for vulnerable third-party components
- **Effectiveness:** Moderate - identifies known vulnerable libraries
- **Limitations:** Requires remediation discipline
- **When to adjust:**
  - Keep at 0.6 for automated SCA with remediation
  - Increase to 0.7 if scanning only (no remediation)

---

## Control Correlations

### What Are Control Correlations?

Control correlations model realistic organizational behavior where certain controls are implemented together (or not at all).

### Types of Correlations

#### Positive Correlations
**If Control A exists, Control B is more likely to exist**

Example:
```yaml
mfa:
  positive_correlations:
    - control: sso_with_mfa
      probability: 0.75  # 75% chance SSO+MFA also exists
```

**What this means:**
- Organizations that implement MFA usually also implement SSO+MFA
- 75% of orgs with MFA also have SSO+MFA
- This reflects real-world behavior (defense in depth)

#### Negative Correlations
**If Control A is missing, Control B is less likely to exist**

Example:
```yaml
mfa:
  negative_correlations:
    - control: jit_access
      probability: 0.20  # Only 20% chance JIT exists without MFA
```

**What this means:**
- JIT access requires strong authentication (MFA)
- Without MFA, only 20% of orgs have JIT
- This reflects prerequisites and dependencies

### Common Control Suites

#### Access Control Suite
- MFA -> SSO+MFA (75%)
- MFA -> PAM (70%)
- MFA -> IAM Platform (65%)
- PAM -> MFA (85%)
- PAM -> JIT Access (60%)

#### Security Operations Suite
- SIEM -> SOC 24x7 (80%)
- SIEM -> EDR/XDR (70%)
- SOC -> SIEM (90%)
- SOAR -> SIEM (95%)

#### Endpoint Security Suite
- EDR/XDR -> SIEM (75%)
- EDR/XDR -> Endpoint Patching (70%)
- EDR/XDR -> Device Encryption (65%)
- EDR/XDR -> !Antivirus (30%) - EDR replaces AV

### When to Adjust Correlations

**Increase correlation probability** when:
- Controls are tightly integrated (e.g., SOAR requires SIEM)
- Regulatory requirements mandate both (e.g., PCI-DSS)
- Vendor bundles controls together

**Decrease correlation probability** when:
- Controls are from different vendors
- Budget constraints limit control adoption
- Organizational silos prevent coordination

---

## Maturity Levels

### NIST Cybersecurity Framework Maturity Levels

Organizations implement controls in stages based on security maturity:

#### Level 1: Initial (Ad-hoc, Reactive)
```yaml
level_1_initial:
  typical_controls:
    - firewall
    - antivirus
    - password_policy
  probability: 0.40  # Only 40% have even basics
```

**Characteristics:**
- No formal security program
- Reactive to incidents
- Minimal investment
- **Typical sectors:** Small business, education, nonprofits

**When to adjust:**
- Keep at 0.40 (many orgs lack basics)
- Decrease to 0.30 for extremely underinvested sectors
- Increase to 0.50 if minimum compliance required

#### Level 2: Managed (Risk-Informed)
```yaml
level_2_managed:
  typical_controls:
    - mfa
    - backup_recovery
    - endpoint_patching
    - ids_ips
    - security_awareness_training
  probability: 0.55  # 55% have these controls
```

**Characteristics:**
- Some security policies exist
- Risk-aware but inconsistent
- Starting to invest
- **Typical sectors:** Healthcare, retail, manufacturing

**When to adjust:**
- Keep at 0.55 (inconsistent implementation)
- Increase to 0.65 if compliance-driven (HIPAA, PCI-DSS)

#### Level 3: Defined (Formal Program)
```yaml
level_3_defined:
  typical_controls:
    - edr_xdr
    - siem
    - vulnerability_management
    - network_segmentation
    - incident_response_plan
    - rbac
    - encryption_at_rest
    - waf
  probability: 0.70  # 70% have these controls
```

**Characteristics:**
- Formal security program
- Dedicated security team
- Repeatable processes
- **Typical sectors:** Energy, telecommunications, mid-size enterprises

**When to adjust:**
- Keep at 0.70 (formal program needed)
- Increase to 0.80 for mature programs

#### Level 4: Quantitatively Managed (Metrics-Driven)
```yaml
level_4_quantitatively_managed:
  typical_controls:
    - soc_24x7
    - privileged_access_mgmt
    - data_loss_prevention
    - threat_intelligence
    - penetration_testing
    - secure_sdlc
    - sast_dast
    - ngfw
    - network_access_control
  probability: 0.75  # 75% have these controls
```

**Characteristics:**
- Measured and controlled
- Metrics-driven decisions
- Well-funded program
- **Typical sectors:** Financial services, technology, large enterprises

**When to adjust:**
- Keep at 0.75 (well-resourced programs)
- Increase to 0.85 for heavily regulated sectors

#### Level 5: Optimizing (Continuous Improvement)
```yaml
level_5_optimizing:
  typical_controls:
    - soar
    - zero_trust
    - jit_access
    - application_whitelisting
    - software_composition_analysis
    - api_gateway
    - privileged_session_mgmt
  probability: 0.65  # 65% have these controls
```

**Characteristics:**
- Continuous improvement
- Cutting-edge security
- Industry-leading
- **Typical sectors:** Defense, FAANG, top financial institutions

**When to adjust:**
- Keep at 0.65 (even mature orgs don't have everything)
- Decrease to 0.55 if cutting-edge controls rare

---

## Sector-Specific Adjustments

### How Sector Multipliers Work

**Formula:**
```
Effective Probability = Base Probability x Sector Multiplier
```

**Example:**
- Healthcare at Level 2
- Base probability: 55%
- Healthcare multiplier: 0.9
- **Effective: 55% x 0.9 = 49.5%**

### Sector Categories

#### Well-Invested Sectors (Multiplier >1.0)

##### Defense & Government (1.4x)
```yaml
defense_government:
  multiplier: 1.4  # 40% increase
  typical_maturity: 5
```
- **Why:** National security requirements, unlimited budget
- **Examples:** DoD contractors, intelligence agencies, military
- **Controls:** All controls at highest levels
- **When to adjust:** Keep at 1.4 (highest security requirements)

##### Financial Services (1.3x)
```yaml
financial_services:
  multiplier: 1.3  # 30% increase
  typical_maturity: 4
```
- **Why:** Heavily regulated (SOX, PCI-DSS, GLBA), high-value targets
- **Examples:** Banks, insurance, fintech, payment processors
- **Controls:** Comprehensive security programs
- **When to adjust:**
  - Keep at 1.3 for large banks
  - Decrease to 1.2 for small credit unions

##### Technology (1.2x)
```yaml
technology:
  multiplier: 1.2  # 20% increase
  typical_maturity: 4
```
- **Why:** Security-aware culture, technical expertise
- **Examples:** SaaS providers, cloud platforms, tech companies
- **Controls:** Modern security stack
- **When to adjust:**
  - Keep at 1.2 for security-focused tech companies
  - Decrease to 1.1 for general software companies

#### Underinvested Sectors (Multiplier <1.0)

##### Small Business (0.5x)
```yaml
small_business:
  multiplier: 0.5  # 50% decrease
  typical_maturity: 1
```
- **Why:** No dedicated security staff, limited budget
- **Examples:** SMBs <500 employees, local businesses
- **Controls:** Minimal or none
- **When to adjust:**
  - Keep at 0.5 (realistic for most SMBs)
  - Decrease to 0.4 for micro-businesses (<50 employees)
  - **Critical:** Most breaches target SMBs due to weak security

##### Nonprofit (0.55x)
```yaml
nonprofit:
  multiplier: 0.55  # 45% decrease
  typical_maturity: 1
```
- **Why:** Severely underfunded, mission-focused not security-focused
- **Examples:** Charities, NGOs, advocacy groups
- **Controls:** Minimal, often donated/free tools
- **When to adjust:**
  - Keep at 0.55 (realistic for most nonprofits)
  - Increase to 0.7 for large international NGOs

##### Education (0.6x)
```yaml
education:
  multiplier: 0.6  # 40% decrease
  typical_maturity: 1
```
- **Why:** Chronically underfunded, open network culture
- **Examples:** K-12 schools, universities, research institutions
- **Controls:** Basic at best, often outdated
- **When to adjust:**
  - Keep at 0.6 for most schools
  - Increase to 0.8 for elite universities (MIT, Stanford)
  - Decrease to 0.5 for K-12 schools

##### Retail & Hospitality (0.7x)
```yaml
retail_hospitality:
  multiplier: 0.7  # 30% decrease
  typical_maturity: 2
```
- **Why:** PCI-DSS compliance only, minimal beyond that
- **Examples:** Retail stores, restaurants, hotels
- **Controls:** Payment security focused, weak elsewhere
- **When to adjust:**
  - Keep at 0.7 for most retail
  - Increase to 0.9 for large retailers (Target, Walmart)

##### Healthcare (0.9x)
```yaml
healthcare_pharma:
  multiplier: 0.9  # 10% decrease
  typical_maturity: 2
```
- **Why:** HIPAA required but chronically underinvested
- **Examples:** Hospitals, clinics, pharma companies
- **Controls:** Compliance-focused, legacy systems
- **When to adjust:**
  - Keep at 0.9 for most healthcare
  - Increase to 1.1 for large hospital systems
  - Decrease to 0.7 for small clinics

##### Manufacturing (0.8x)
```yaml
manufacturing:
  multiplier: 0.8  # 20% decrease
  typical_maturity: 2
```
- **Why:** OT/IT convergence challenges, legacy systems
- **Examples:** Factories, industrial plants, supply chain
- **Controls:** OT security weak, IT security moderate
- **When to adjust:**
  - Keep at 0.8 for most manufacturing
  - Increase to 1.0 for critical manufacturing (aerospace)

#### Moderate Investment Sectors (Multiplier ~1.0)

##### Energy & Utilities (1.0x)
```yaml
energy_utilities:
  multiplier: 1.0  # No change
  typical_maturity: 3
```
- **Why:** NERC CIP regulated but legacy infrastructure
- **Examples:** Power plants, oil & gas, water utilities
- **Controls:** Compliance-driven, OT security challenges
- **When to adjust:**
  - Keep at 1.0 (balanced: regulated but legacy)
  - Increase to 1.2 for nuclear power (highest security)

##### Telecommunications (1.1x)
```yaml
telecommunications:
  multiplier: 1.1  # 10% increase
  typical_maturity: 3
```
- **Why:** Critical infrastructure, moderate investment
- **Examples:** ISPs, mobile carriers, telecom equipment
- **Controls:** Network security focused
- **When to adjust:**
  - Keep at 1.1 for major carriers
  - Decrease to 0.9 for small ISPs

---

## How to Adjust Values

### Step-by-Step Process

#### 1. Identify What You're Adjusting

**Control Effectiveness (LR values):**
- Location: `network_controls`, `endpoint_controls`, etc.
- Format: `default: 0.X`
- Impact: Changes how much control reduces risk

**Control Correlations:**
- Location: `control_correlations`
- Format: `probability: 0.X`
- Impact: Changes how controls appear together

**Maturity Levels:**
- Location: `control_maturity_levels`
- Format: `probability: 0.X`
- Impact: Changes control presence by maturity

**Sector Adjustments:**
- Location: `sector_maturity_adjustments`
- Format: `multiplier: X.X`
- Impact: Changes control presence by sector

#### 2. Understand Current Value

**For Control Effectiveness:**
```yaml
waf:
  default: 0.4  # Current: 60% reduction
```
- Current: WAF blocks 60% of attacks (heuristic estimate)
- Basis: Industry observations, conservative assumption
- Range: 40-85% depending on configuration and threat type

**For Correlations:**
```yaml
mfa:
  positive_correlations:
    - control: sso_with_mfa
      probability: 0.75  # Current: 75% correlation
```
- Current: 75% of orgs with MFA also have SSO+MFA
- Source: Observed organizational behavior
- Basis: Defense in depth patterns

#### 3. Determine New Value

**Questions to ask:**
1. Do I have empirical data supporting a different value?
2. Is my organization different from industry average?
3. Am I adjusting for a specific sector or use case?
4. What is the confidence level in my new value?

**Example adjustment:**
```yaml
# Before: Industry average
waf:
  default: 0.4  # 60% reduction

# After: Your organization has well-tuned WAF
waf:
  default: 0.3  # 70% reduction (more effective)
```

#### 4. Document Your Change

**Add comments explaining:**
- Why you changed it
- What data supports the change
- When to review the change

```yaml
waf:
  default: 0.3  # 70% reduction
  # Adjusted from 0.4 based on internal testing
  # Our well-tuned WAF blocks 70% of attacks
  # Source: 6-month red team assessment (2025-Q4)
  # Review: Annually or after WAF changes
  description: "Blocks SQL injection, XSS, and other web attacks"
```

#### 5. Test Your Changes

**Run correlation tests:**
```bash
python -m pytest tests/test_control_correlation.py -v
```

**Run kill-chain tests:**
```bash
python -m pytest tests/test_kill_chain_calculator.py -v
```

**Generate sample scenarios:**
```python
from src.utils.control_correlation import generate_correlated_controls

# Test your sector adjustment
controls = generate_correlated_controls(
    maturity_level=3,
    seed_controls={"mfa": True},
    randomness=0.2
)
print(f"Generated {sum(controls.values())} controls")
```

#### 6. Validate Results

**Check for:**
- Realistic control counts (not too many or too few)
- Logical correlations (related controls appear together)
- Sector-appropriate security postures
- Maturity-appropriate control sophistication

---

## Common Scenarios

### Scenario 1: Adjusting for Your Organization

**Situation:** Your organization has better-than-average security

**Steps:**
1. Identify your maturity level (1-5)
2. Identify your sector
3. Adjust sector multiplier upward

```yaml
# Example: Healthcare organization with strong security program
healthcare_pharma:
  multiplier: 1.1  # Increased from 0.9
  typical_maturity: 3  # Increased from 2
  description: "Large hospital system with dedicated security team"
```

### Scenario 2: Modeling a Specific Threat Actor

**Situation:** Assessing risk from advanced persistent threat (APT)

**Steps:**
1. Reduce control effectiveness (APTs bypass controls)
2. Increase threat indicator multipliers

```yaml
# APTs are more sophisticated
waf:
  default: 0.6  # Reduced from 0.4 (APTs bypass WAF)

ids_ips:
  default: 0.7  # Reduced from 0.5 (APTs use zero-days)

# Increase threat indicators
apt_interest:
  default: 3.0  # Increased from 2.0 (higher risk)
```

### Scenario 3: Compliance-Driven Organization

**Situation:** Organization focuses on compliance, not security

**Steps:**
1. Increase basic control presence
2. Decrease advanced control presence
3. Adjust effectiveness downward (checkbox compliance)

```yaml
# Compliance-focused adjustments
level_2_managed:
  probability: 0.70  # Increased (compliance requires basics)

level_4_quantitatively_managed:
  probability: 0.50  # Decreased (no investment beyond compliance)

# Controls present but not effective
mfa:
  default: 0.4  # Increased from 0.3 (SMS-based MFA, weaker)
```

### Scenario 4: Startup vs Enterprise

**Startup:**
```python
controls = generate_correlated_controls(
    maturity_level=1,
    seed_controls={"firewall": True},
    randomness=0.3
)
# Result: 2-5 controls (minimal security)
```

**Enterprise:**
```python
controls = generate_correlated_controls(
    maturity_level=4,
    seed_controls={"mfa": True, "siem": True},
    randomness=0.1
)
# Result: 15-25 controls (comprehensive security)
```

### Scenario 5: Sector-Specific Assessment

**Financial Services:**
```python
# Apply sector multiplier
base_probability = 0.75  # Level 4
sector_multiplier = 1.3  # Financial services
effective_probability = min(0.95, base_probability * sector_multiplier)
# Result: 97.5% -> capped at 95%
```

**Small Business:**
```python
# Apply sector multiplier
base_probability = 0.40  # Level 1
sector_multiplier = 0.5  # Small business
effective_probability = base_probability * sector_multiplier
# Result: 20% (only 1 in 5 have basic controls)
```

---

## References

### Academic Sources

1. **Verizon (2024)**. "Data Breach Investigations Report"
   - https://www.verizon.com/business/resources/reports/dbir/
   - Source for control effectiveness data and sector-specific breach statistics
   - Released May 2024, covers 2023 breach data

2. **IBM Security (2024)**. "Cost of a Data Breach Report"
   - https://www.ibm.com/reports/data-breach
   - Security investment by sector, breach costs by industry
   - Released July 2024, covers global breach cost data

3. **NIST Cybersecurity Framework**
   - https://www.nist.gov/cyberframework
   - Source for maturity levels and industry resources

4. **MITRE ATT&CK**
   - https://attack.mitre.org/mitigations/enterprise/
   - Source for control mitigations and enterprise security

5. **Downey, A. B. (2021)**. "Think Bayes: Bayesian Statistics in Python"
   - https://allendowney.github.io/ThinkBayes2/
   - Source for Bayesian inference methodology

### Industry Reports (All Publicly Accessible)

- **CISA Critical Infrastructure**: https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience
- **SANS Institute Surveys**: https://www.sans.org/white-papers/
- **CIS Controls**: https://www.cisecurity.org/controls
- **ENISA Threat Landscape**: https://www.enisa.europa.eu/topics/threat-risk-management

### Standards & Frameworks

- **NIST SP 800-53**: Security and Privacy Controls
- **NIST SP 800-190**: Container Security Guide
- **ISO 27001**: Information Security Management
- **CIS Controls v8**: Critical Security Controls
- **OWASP Top 10**: Web Application Security Risks

---

## Appendix: Quick Reference Tables

### Control Effectiveness Quick Reference

| Control | LR | Reduction | Strength | When to Use |
|---------|----|-----------| ---------|-------------|
| Network Segmentation | 0.3 | 70% | Very High | Always (strongest network control) |
| Zero Trust | 0.3 | 70% | Very High | Modern architectures |
| MFA | 0.3 | 70% | Very High | Always (strongest access control) |
| DLP | 0.3 | 70% | Very High | Data protection required |
| App Whitelisting | 0.3 | 70% | Very High | High-security environments |
| WAF | 0.4 | 60% | High | Web applications |
| EDR/XDR | 0.4 | 60% | High | All endpoints |
| PAM | 0.4 | 60% | High | Privileged accounts |
| Firewall | 0.5 | 50% | Moderate | Basic network protection |
| IDS/IPS | 0.5 | 50% | Moderate | Network monitoring |
| SIEM | 0.6 | 40% | Moderate | Log aggregation |
| Antivirus | 0.7 | 30% | Low | Legacy (replaced by EDR) |

### Maturity Level Quick Reference

| Level | Probability | Typical Controls | Typical Sectors |
|-------|-------------|------------------|-----------------|
| 1 (Initial) | 40% | Firewall, AV, Passwords | SMB, Education, Nonprofit |
| 2 (Managed) | 55% | MFA, Backup, Patching | Healthcare, Retail, Manufacturing |
| 3 (Defined) | 70% | EDR, SIEM, Segmentation | Energy, Telecom, Mid-size Enterprise |
| 4 (Quantitative) | 75% | SOC, PAM, DLP | Financial, Technology, Large Enterprise |
| 5 (Optimizing) | 65% | SOAR, Zero Trust, JIT | Defense, FAANG, Top Finance |

### Sector Multiplier Quick Reference

| Sector | Multiplier | Typical Maturity | Investment Level |
|--------|------------|------------------|------------------|
| Defense/Government | 1.4x | 5 | Highest |
| Financial Services | 1.3x | 4 | Very High |
| Technology | 1.2x | 4 | High |
| Telecommunications | 1.1x | 3 | Moderate-High |
| Energy/Utilities | 1.0x | 3 | Moderate |
| Healthcare | 0.9x | 2 | Moderate-Low |
| Manufacturing | 0.8x | 2 | Low-Moderate |
| Media/Entertainment | 0.75x | 2 | Low |
| Retail/Hospitality | 0.7x | 2 | Low |
| Education | 0.6x | 1 | Very Low |
| Nonprofit | 0.55x | 1 | Very Low |
| Small Business | 0.5x | 1 | Lowest |

---

**End of Guide**

For questions or clarifications, refer to:
- Configuration file: `config/security_controls.yaml`
- Mathematical review: `docs/MATHEMATICAL_REVIEW.md`
- Test suite: `tests/test_control_correlation.py`
