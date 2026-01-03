# CVEs Analytics - Demo Report

**Version:** 2.2 (EPSS Trajectory Analysis)  
**Generated:** January 3, 2026  
**Document Type:** Examples & Demonstrations  
**Estimated Reading Time:** 20-30 minutes

## Intended Audience

**Primary:** All users - security analysts, managers, developers, decision-makers  
**Secondary:** Prospective users evaluating the tool

**Prerequisites:**
- None - this is an introductory document
- Basic understanding of vulnerability management (helpful)

**What You'll Learn:**
- Real-world vulnerability assessment examples across three maturity levels
- How security controls impact exploitation probability
- Kill-chain analysis results and interpretations
- Practical insights from different organizational scenarios

---

This is a demonstration report showcasing the CVEs Analytics tool's capabilities across **multiple security scenarios**. The tool performs Bayesian risk assessment with **probabilistic control types modeling**, multi-component kill-chain probability analysis, and security control effectiveness evaluation.

**⚠️ Version 2.2 Update:** Added EPSS trajectory analysis to track exploitation trends over time. Replaced static patch availability factors with dynamic EPSS trajectory tracking based on the Work-Averse Cyberattacker Model (Allodi et al., 2021).

---

## 🎯 Multi-Scenario Showcase

This demo includes **three different security scenarios** to demonstrate how the tool adapts to different security maturity levels and provides actionable insights:

1. **[Initial Maturity (Small Business)](#scenario-1-initial-maturity)** - Small consulting firm, minimal controls
2. **[Managed Maturity (Mid-Size)](#scenario-2-managed-maturity)** - Mid-size financial services, documented & measured
3. **[Optimizing Maturity (Large Enterprise)](#scenario-3-optimizing-maturity)** - Large financial services, advanced controls

**📊 [View Detailed Scenario Comparison](SCENARIO_COMPARISON.md)** - Complete side-by-side analysis of all three scenarios

**🔧 New in Version 2.2:**
- **EPSS Trajectory Analysis**: Tracks exploitation trends over 90 days (rising/declining/stable)
- **Dynamic Risk Adjustment**: Rising EPSS trends get 1.2x amplification factor
- **Historical Context**: Shows EPSS values from 30 and 90 days ago
- **Patch Adoption Visibility**: Declining EPSS indicates successful patching
- Based on Work-Averse Cyberattacker Model (Allodi et al., 2021)

**Previous Features (v2.0-2.1):**
- Probabilistic control types (8 control categories with varying effectiveness)
- Realistic control type distributions based on maturity and industry
- Granular likelihood ratios (LR) for each control implementation level
- Enhanced kill-chain analysis with stage-by-stage probability breakdown

---

## Scenario 1: Initial Maturity (Small Business)

This scenario shows a **small consulting firm** with **initial security maturity** (8 active security controls) - representing an organization with ad-hoc, reactive security practices and minimal investment in advanced controls.

```
================================================================================
VULNERABILITY ASSESSMENT REPORT
================================================================================
Generated: 2026-01-02 07:53:01 UTC

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities Scanned: 2398
Average Exploitation Probability: 0.34%
Average Uncertainty: ±6.64%
Business Risk Level: LOW

Original Severity Distribution (Scanner Output):
  Critical: 55 (2.3%)
  High: 328 (13.7%)
  Medium: 1021 (42.6%)
  Low: 465 (19.4%)
  Negligible: 520 (21.7%)
  Unknown: 9 (0.4%)

Bayesian Risk Assessment (After Analysis):
  Critical: 72 (3.0%)
  High: 72 (3.0%)
  Medium: 53 (2.2%)
  Low: 94 (3.9%)
  Negligible: 2107 (87.9%)

Actionable Vulnerabilities (Critical+High+Medium): 197
Critical/High Requiring Immediate Action: 144 (6.0%)

Estimated Remediation Effort: 485 person-hours
Recommended Timeline: 13 weeks

Known Exploited Vulnerabilities (KEV): 17
Public Exploits Available: 0
Metasploit Modules: 0
High Exploitation Probability (EPSS>=0.5): 40

RISK-BASED PRIORITIZATION (Bayesian)
--------------------------------------------------------------------------------
CRITICAL (Fix ASAP): 24 vulnerabilities
  1. CVE-2023-44487 - P(Exploit): 99.9% [94.9%-100.0%] in nginx-web
      CVSS: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H), EPSS: 94.40%
      EPSS Trajectory: ↓ DECLINING (factor: 1.00x, patch adoption reducing risk) [90d ago: 94.44%, 30d ago: 94.39%]
  2. CVE-2018-25032 - P(Exploit): 50.6% [38.1%-63.1%] in nginx-web
      CVSS: 7.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P), EPSS: 0.09%
      EPSS Trajectory: → STABLE (factor: 1.00x, sustained threat level) [90d ago: 0.09%, 30d ago: 0.09%]
  3. CVE-2025-27363 - P(Exploit): 98.5% [93.0%-100.0%] in nginx-web
      CVSS: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H), EPSS: 92.74%
      EPSS Trajectory: ↓ DECLINING (factor: 1.00x, patch adoption reducing risk) [90d ago: 93.12%, 30d ago: 92.89%]
  4. CVE-2023-44487 - P(Exploit): 99.9% [94.9%-100.0%] in traefik
      CVSS: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H), EPSS: 94.40%
      EPSS Trajectory: ↓ DECLINING (factor: 1.00x, patch adoption reducing risk) [90d ago: 94.44%, 30d ago: 94.39%]

SCANNED ENVIRONMENT (Simulated)
--------------------------------------------------------------------------------
Organization Size: small
Geographic Reach: local
Industry: consulting
Environment Type: dev
Security Maturity: initial

Services Scanned: 7
  - reverse-proxy (ingress): traefik:v2.5 [internet-facing]
  - web-app (frontend): nginx:alpine [internet-facing]
  - api-server (backend): eclipse-temurin:17-jre [internal]
  - project-database (database): memcached:1.5 [internal]
  - message-queue (messaging): rabbitmq:3.8-management [internal]
  - ci-cd-pipeline (cicd): drone/drone:2 [internal]
  - monitoring-stack (monitoring): elasticsearch:7.17.0 [internal]

Active Security Controls: 8
  segmentation_type: none
  firewall_type: basic
  waf_type: none
  ids_ips_type: none
  endpoint_protection_type: traditional_av
  mfa_type: none
  patch_management_quality: quarterly
  incident_response_plan: True

KILL-CHAIN PROBABILITY ANALYSIS
--------------------------------------------------------------------------------
Overall Probability: 0.9%
Threat Level: Negligible
Bottleneck Stage: Initial Access (1.0%)

Stage-by-Stage:
  Initial Access:        1.0% (strong perimeter)
  Execution:             100.0% conditional (poor Docker practices)
  Lateral Movement:      100.0% conditional (flat network)
  Objective Achievement: 90.0% conditional

⚠️  WARNING: Poor Docker practices detected - RCE vulnerability with NO protection (root access)
⚠️  WARNING: Flat network topology enables 100% lateral movement probability

================================================================================
```

**Key Observations for Scenario 1**:
- ⚠️ **Minimal security controls**: Only 8 basic controls (no MFA, no WAF, no segmentation)
- ⚠️ **Poor Docker practices**: Root containers with no hardening (30% risk increase)
- ⚠️ **Quarterly patching**: Long exposure window (LR=0.7, only 30% reduction)
- ⚠️ **High exploitation probability**: 40 vulnerabilities with EPSS>=0.5
- ⚠️ **72 critical vulnerabilities** requiring immediate attention (3.0% of total)
- ⚠️ **Flat network**: 100% lateral movement probability if perimeter breached

---

## Scenario 2: Managed Maturity (Mid-Size)

This scenario shows a **mid-size financial services organization** with **managed security maturity** (11 active security controls) - representing an organization with documented policies, measured controls, and proactive security practices.

```
================================================================================
VULNERABILITY ASSESSMENT REPORT
================================================================================
Generated: 2026-01-02 07:56:35 UTC

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities Scanned: 4365
Average Exploitation Probability: 0.37%
Average Uncertainty: ±6.72%
Business Risk Level: LOW

Original Severity Distribution (Scanner Output):
  Critical: 96 (2.2%)
  High: 825 (18.9%)
  Medium: 2046 (46.9%)
  Low: 912 (20.9%)
  Negligible: 486 (11.1%)
  Unknown: 8 (0.2%)

Bayesian Risk Assessment (After Analysis):
  Critical: 167 (3.8%)
  High: 108 (2.5%)
  Medium: 112 (2.6%)
  Low: 263 (6.0%)
  Negligible: 3715 (85.1%)

Actionable Vulnerabilities (Critical+High+Medium): 387
Critical/High Requiring Immediate Action: 275 (6.3%)

Estimated Remediation Effort: 875 person-hours
Recommended Timeline: 22 weeks

Known Exploited Vulnerabilities (KEV): 42
Public Exploits Available: 0
Metasploit Modules: 0
High Exploitation Probability (EPSS>=0.5): 81

KILL-CHAIN PROBABILITY ANALYSIS
--------------------------------------------------------------------------------
Application: Financial Services Platform
Type: financial_services
Description: Banking/trading platform with high security requirements
Components: 7

KILL-CHAIN SUCCESS PROBABILITY
Overall Probability: 0.9%
Threat Level: Negligible
Bottleneck Stage: Initial Access (1.0%)

Stage-by-Stage:
  Initial Access:        1.0% (strong perimeter)
  Execution:             100.0% conditional (poor Docker practices)
  Lateral Movement:      100.0% conditional (flat network)
  Objective Achievement: 90.0% conditional

SCANNED ENVIRONMENT
--------------------------------------------------------------------------------
Organization Size: mid
Geographic Reach: regional
Industry: financial-services
Environment Type: prod
Security Maturity: managed

Active Security Controls: 11
  segmentation_type: basic_vlan
  firewall_type: stateful
  waf_type: managed
  ids_ips_type: ips_signature
  endpoint_protection_type: basic_edr
  mfa_type: authenticator_app
  patch_management_quality: monthly
  siem_maturity: basic_correlation
  privileged_access_mgmt: True
  incident_response_plan: True
  security_training: True

================================================================================
```

**Key Observations for Scenario 2**:
- ✅ **Moderate security controls**: 11 controls with varying quality levels
- ✅ **Basic EDR deployed**: 50% risk reduction (LR=0.5)
- ✅ **Authenticator App MFA**: 85% reduction in credential attacks (LR=0.15)
- ✅ **Monthly patching**: 60% reduction (LR=0.4) vs quarterly
- ✅ **Basic VLAN segmentation**: 30% reduction in lateral movement (LR=0.7)
- ⚠️ **167 critical vulnerabilities** (3.8% of total) - higher than initial due to more services
- ⚠️ **Still using poor Docker practices**: 30% risk increase in execution stage

---

## Scenario 3: Optimizing Maturity (Large Enterprise)

This scenario shows a **large financial services organization** with **optimizing security maturity** (12 active security controls) - representing an enterprise with advanced controls, continuous improvement, and strong security culture.

```
================================================================================
VULNERABILITY ASSESSMENT REPORT
================================================================================
Generated: 2026-01-02 07:58:37 UTC

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities Scanned: 4301
Average Exploitation Probability: 0.27%
Average Uncertainty: ±6.35%
Business Risk Level: LOW

Original Severity Distribution (Scanner Output):
  Critical: 139 (3.2%)
  High: 837 (19.5%)
  Medium: 2049 (47.6%)
  Low: 862 (20.0%)
  Negligible: 406 (9.4%)
  Unknown: 8 (0.2%)

Bayesian Risk Assessment (After Analysis):
  Critical: 101 (2.3%)
  High: 69 (1.6%)
  Medium: 92 (2.1%)
  Low: 164 (3.8%)
  Negligible: 3875 (90.1%)

Actionable Vulnerabilities (Critical+High+Medium): 262
Critical/High Requiring Immediate Action: 170 (4.0%)

Estimated Remediation Effort: 620 person-hours
Recommended Timeline: 16 weeks

Known Exploited Vulnerabilities (KEV): 42
Public Exploits Available: 0
Metasploit Modules: 0
High Exploitation Probability (EPSS>=0.5): 81

KILL-CHAIN PROBABILITY ANALYSIS
--------------------------------------------------------------------------------
Application: Financial Services Platform
Type: financial_services
Description: Banking/trading platform with high security requirements
Components: 7

KILL-CHAIN SUCCESS PROBABILITY
Overall Probability: 0.9%
Threat Level: Negligible
Bottleneck Stage: Initial Access

STAGE-BY-STAGE ANALYSIS:

Initial Access:
  Base Probability: 1.0%
  Conditional Probability: 1.0%
  Contributing Factors:
    - no_vulnerabilities: 0.01 (99% reduction)

Execution:
  Base Probability: 1.0%
  Conditional Probability: 100.0%
  Affected Components: backend
  Contributing Factors:
    - base_execution: 0.80 (20% reduction)
    - docker_poor_rce_no_protection: 1.30 (30% increase)

Lateral Movement:
  Base Probability: 100.0%
  Conditional Probability: 100.0%
  Affected Components: auth, backend, database, messaging
  Contributing Factors:
    - base_lateral: 0.70 (30% reduction)
    - flat_network: 1.30 (30% increase)
    - docker_poor_network_isolation: 1.20 (20% increase)

Objective Achievement:
  Base Probability: 90.0%
  Conditional Probability: 90.0%
  Affected Components: database, messaging
  Contributing Factors:
    - base_objective: 0.90 (10% reduction)

SCANNED ENVIRONMENT
--------------------------------------------------------------------------------
Organization Size: large
Geographic Reach: global
Industry: financial-services
Environment Type: prod
Security Maturity: optimizing

Active Security Controls: 12
  segmentation_type: basic_vlan
  firewall_type: ngfw
  waf_type: owasp_crs
  ids_ips_type: ips_signature
  endpoint_protection_type: advanced_edr
  mfa_type: fido2
  patch_management_quality: weekly
  siem_maturity: advanced_analytics
  privileged_access_mgmt: True
  soc_24x7: True
  incident_response_plan: True
  security_training: True       

================================================================================
```

**Key Observations for Scenario 3**:
- ✅ **Advanced security controls**: 12 controls with high-quality implementations
- ✅ **FIDO2 MFA**: 95% reduction in credential attacks (LR=0.05) - strongest MFA
- ✅ **Advanced EDR**: 60% risk reduction (LR=0.4) vs 50% for basic EDR
- ✅ **OWASP CRS WAF**: 70% reduction (LR=0.3) - comprehensive rule set
- ✅ **Weekly patching**: 70% reduction (LR=0.3) - aggressive patch cycle
- ✅ **24x7 SOC**: 50% reduction (LR=0.5) - continuous monitoring
- ⚠️ **101 critical vulnerabilities** (2.3% of total) - lowest percentage across scenarios
- ⚠️ **Still 90.1% negligible**: Strong controls reduce actionable vulnerabilities significantly

---

## Key Features Demonstrated

### 1. Multi-Scenario Analysis ✨ NEW
The tool generates **realistic scenarios** based on:
- **Organization size** (small, mid, large)
- **Industry** (financial services, consulting, e-commerce)
- **Environment** (dev, test, prod)
- **Security maturity** (initial, developing, defined, managed, optimizing)

**Security Maturity Levels**:
- **Initial** (Poor): 5 controls - Ad-hoc, reactive security
- **Defined** (Average): 8 controls - Documented policies, some automation
- **Managed** (Good): 12 controls - Measured and controlled security

### 2. Multi-Component Application Analysis
The kill-chain analysis evaluates a complete **7-component Financial Services Platform**:
- **Load balancer** (internet-facing entry point)
- **API gateway** (DMZ layer)
- **Authentication service** (critical internal)
- **Transaction processor** (critical internal)
- **Financial database** (critical internal)
- **Reporting service** (internal)
- **Audit log messaging** (internal)

### 3. Stage-by-Stage Attack Modeling
Each kill-chain stage shows which components are affected:
- **Initial Access**: Targets ingress components (1.0% probability)
- **Execution**: Affects backend components with Docker security considerations (5.8% conditional)
- **Lateral Movement**: Spans auth, backend, database, and messaging tiers (3.1% conditional)
- **Objective Achievement**: Focuses on database and messaging exfiltration (63.0% conditional)

### 4. Security Control Penalty Modeling ✨ NEW
The analysis now **penalizes bad security practices** (LR > 1.0):

**Good Practices (Protection - LR < 1.0)**:
- Docker good practices: **0.3** (70% reduction in execution)
- Network segmentation: **0.3** (70% reduction in lateral movement)
- EDR/XDR: **0.4-0.5** (40-60% reduction)
- SIEM: **0.6-0.7** (30-40% reduction)

**Bad Practices (Penalties - LR > 1.0)**:
- Poor Docker practices: **1.2-1.3** (20-30% **INCREASE** in risk)
- Flat network: **1.3** (30% **INCREASE** in lateral movement)
- No patching: **1.5** (50% **INCREASE** in exploitation probability)

### 5. Dynamic Security Control Modeling
The analysis incorporates actual security controls with realistic impact:
- **Network segmentation**: 70% reduction in lateral movement
- **Docker security practices**: 60-70% reduction in execution/lateral movement
- **EDR/XDR**: 40-60% reduction across stages
- **WAF**: 40-70% reduction in initial access and execution
- **SIEM**: 30-40% reduction in lateral movement and objective achievement

### 6. Bayesian Risk Assessment
- **EPSS-based prior probability**: Real-world exploitation likelihood
- **Environmental context integration**: Exposure, asset value, security controls
- **Uncertainty quantification**: 95% credible intervals
- **Exploitability gating**: Prevents false risk inflation

---

## 📊 Scenario Comparison Summary

| Metric | Poor Security | Average Security | Good Security |
|--------|---------------|------------------|---------------|
| **Security Maturity** | Initial | Defined | Managed |
| **Active Controls** | 5 | 8 | 12 |
| **Services Scanned** | 9 | 18 | 21 |
| **Total Vulnerabilities** | 1,363 | 6,806 | 3,783 |
| **Critical (Bayesian)** | 18 (1.3%) | 23 (0.3%) | 18 (0.5%) |
| **Actionable Vulns** | 41 | 134 | 75 |
| **KEV Count** | 10 | 60 | 40 |
| **Lateral Movement** | N/A | 5.2% | 3.1% |
| **Remediation Effort** | 101 hours | 236 hours | 146 hours |

**Key Insight**: Good security maturity with 12 controls achieves **40% lower lateral movement probability** (3.1% vs 5.2%) compared to average security, demonstrating the value of comprehensive security controls.

---

## 🎯 Tool Capabilities Showcased

### ✅ Adaptive Scenario Generation
- Automatically adjusts security controls based on maturity level
- Industry-specific application templates
- Realistic control correlation (e.g., SIEM requires network_segmentation)

### ✅ Multi-Component Kill-Chain Analysis
- Analyzes complete applications (7+ components)
- Component-level vulnerability assessment
- Stage-specific attack probabilities

### ✅ Security Control Impact Modeling
- **Protective controls** reduce risk (LR < 1.0)
- **Bad practices** increase risk (LR > 1.0)
- Realistic effectiveness based on industry standards

### ✅ Bayesian Risk Prioritization
- EPSS-based exploitation probability
- Environmental context (exposure, asset value)
- Uncertainty quantification

### ✅ Actionable Recommendations
- Stage-specific remediation guidance
- Phased remediation roadmap
- Team-based risk heatmap

---

## 📖 Additional Resources

- **[SCENARIO_COMPARISON.md](SCENARIO_COMPARISON.md)** - Detailed side-by-side comparison of all three scenarios
- **[README.md](README.md)** - Full feature documentation and setup instructions
- **Individual Reports**:
  - [Poor Security Report](examples/poor_security/report_2026-01-03_09-05-56.txt)
  - [Average Security Report](examples/average_security/report_2026-01-03_09-06-36.txt)
  - [Good Security Report](examples/good_security/report_2026-01-03_09-07-41.txt)

---

## Control Value Interpretation

- **LR < 1.0**: Security control **reduces** risk (protection)
  - `0.3` = 70% reduction (strong protection)
  - `0.5` = 50% reduction (moderate protection)
  - `0.7` = 30% reduction (weak protection)

- **LR = 1.0**: **Baseline** (no protection, no penalty)

- **LR > 1.0**: Bad practice **increases** risk (penalty)
  - `1.2` = 20% increase (moderate penalty)
  - `1.3` = 30% increase (strong penalty)
  - `1.5` = 50% increase (severe penalty)
