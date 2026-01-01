# CVEs Analytics - Demo Report

This is a demonstration report showcasing the CVEs Analytics tool's capabilities across **multiple security scenarios**. The tool performs Bayesian risk assessment with multi-component kill-chain probability analysis and security control penalty modeling.

---

## 🎯 Multi-Scenario Showcase

This demo includes **three different security scenarios** to demonstrate how the tool adapts to different security maturity levels and provides actionable insights:

1. **[Poor Security (Initial Maturity)](#scenario-1-poor-security)** - Small organization, minimal controls
2. **[Average Security (Defined Maturity)](#scenario-2-average-security)** - Mid-size organization, documented policies
3. **[Good Security (Managed Maturity)](#scenario-3-good-security)** - Mid-size organization, measured & controlled

**📊 [View Detailed Scenario Comparison](SCENARIO_COMPARISON.md)** - Complete side-by-side analysis of all three scenarios

---

## Scenario 1: Poor Security (Initial Maturity)

This scenario shows a **small on-line store** with **initial security maturity** (5 active security controls) - representing an organization with ad-hoc, reactive security practices.

```
================================================================================
VULNERABILITY ASSESSMENT REPORT
================================================================================
Generated: 2026-01-01 15:53:17 UTC

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities Scanned: 1363
Average Exploitation Probability: 0.13%
Average Uncertainty: ±5.48%
Business Risk Level: LOW

Original Severity Distribution (Scanner Output):
  Critical: 27 (2.0%)
  High: 147 (10.8%)
  Medium: 302 (22.2%)
  Low: 125 (9.2%)
  Negligible: 755 (55.4%)
  Unknown: 7 (0.5%)

Bayesian Risk Assessment (After Analysis):
  Critical: 18 (1.3%)
  High: 6 (0.4%)
  Medium: 17 (1.2%)
  Low: 34 (2.5%)
  Negligible: 1288 (94.5%)

Actionable Vulnerabilities (Critical+High+Medium): 41
Critical/High Requiring Immediate Action: 24 (1.8%)

Estimated Remediation Effort: 101 person-hours
Recommended Timeline: 3 weeks

Known Exploited Vulnerabilities (KEV): 10
Public Exploits Available: 0
Metasploit Modules: 0
High Exploitation Probability (EPSS>=0.5): 16

RISK-BASED PRIORITIZATION (Bayesian)
--------------------------------------------------------------------------------
CRITICAL (Fix ASAP): 8 vulnerabilities
  1. CVE-2023-44487 - P(Exploit): 98.6% [93.3%-100.0%] in php-fpm
      CVSS: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:H), EPSS: 94.40%
  2. CVE-2024-2961 - P(Exploit): 96.5% [90.8%-100.0%] in php-fpm
      CVSS: 7.3 (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H/E:H), EPSS: 92.86%
  3. CVE-2023-2650 - P(Exploit): 75.9% [65.5%-86.4%] in php-fpm
      CVSS: 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H/E:H), EPSS: 91.70%
  4. CVE-2023-4911 - P(Exploit): 71.5% [61.4%-81.6%] in php-fpm
      CVSS: 7.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:H), EPSS: 67.81%

SCANNED ENVIRONMENT (Simulated)
--------------------------------------------------------------------------------
Organization Size: small
Geographic Reach: local
Industry: on-line-store
Environment Type: dev
Security Maturity: initial

Services Scanned: 9
  - nginx-proxy (load_balancer): nginx:latest [internet-facing]
  - nginx-web (web_server): nginx:alpine [internet-facing]
  - php-fpm (app_server): php:7.4-fpm [internal]
  - postgres-db (database): postgres:14 [internal]
  - killbill (billing): killbill/killbill:latest [internal]
  - kafka (message_broker): confluentinc/cp-kafka:5.5 [internal]
  - git-repository (vcs): gitea/gitea:latest [internal]
  - ci-runner (ci): gitlab-runner:latest [internal]
  - artifact-registry (registry): registry:2.8 [internal]

Active Security Controls: 5
  network_segmentation, firewall, antivirus, patch_quarterly, incident_response_plan

⚠️  WARNING: Poor Docker practices detected - RCE vulnerability with NO protection (root access)

================================================================================
```

**Key Observations for Scenario 1**:
- ⚠️ **Minimal security controls**: Only 5 basic controls active
- ⚠️ **Poor Docker practices**: Root containers with no hardening
- ⚠️ **Quarterly patching**: Long exposure window for vulnerabilities
- ⚠️ **High exploitation probability**: Multiple vulnerabilities with >90% EPSS scores
- ⚠️ **18 critical vulnerabilities** requiring immediate attention (1.3% of total)

---

## Scenario 2: Average Security (Defined Maturity)

This scenario shows a **mid-size consulting firm** with **defined security maturity** (8 active security controls) - representing an organization with documented policies and some automation.

```
================================================================================
VULNERABILITY ASSESSMENT REPORT
================================================================================
Generated: 2026-01-01 15:55:11 UTC

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities Scanned: 6806
Average Exploitation Probability: 0.06%
Average Uncertainty: ±5.37%
Business Risk Level: LOW

Original Severity Distribution (Scanner Output):
  Critical: 249 (3.7%)
  High: 1453 (21.3%)
  Medium: 3272 (48.1%)
  Low: 1317 (19.4%)
  Negligible: 500 (7.3%)
  Unknown: 15 (0.2%)

Bayesian Risk Assessment (After Analysis):
  Critical: 23 (0.3%)
  High: 33 (0.5%)
  Medium: 78 (1.1%)
  Low: 500 (7.3%)
  Negligible: 6172 (90.7%)

Actionable Vulnerabilities (Critical+High+Medium): 134
Critical/High Requiring Immediate Action: 56 (0.8%)

Estimated Remediation Effort: 236 person-hours
Recommended Timeline: 6 weeks

Known Exploited Vulnerabilities (KEV): 60
Public Exploits Available: 0
Metasploit Modules: 0
High Exploitation Probability (EPSS>=0.5): 138

KILL-CHAIN PROBABILITY ANALYSIS
--------------------------------------------------------------------------------
Application: Consulting Services Platform
Type: consulting
Description: Project management and collaboration platform
Components: 7

Application Components:
  - reverse-proxy (ingress): sameersbn/squid:3.5.27 [internet-facing, medium value]
  - web-app (frontend): nginx:1.18-alpine [internet-facing, medium value]
  - api-server (backend): php:7.4-fpm [internal, high value]
  - project-database (database): redis:6.2 [internal, high value]
  - message-queue (messaging): rabbitmq:3.8-management [internal, medium value]
  - ci-cd-pipeline (cicd): jenkins/jenkins:lts [internal, high value]
  - monitoring-stack (monitoring): grafana/grafana:9.0.0 [internal, low value]

KILL-CHAIN SUCCESS PROBABILITY
Overall Probability: 0.0%
Threat Level: Negligible
Bottleneck Stage: Initial Access

STAGE-BY-STAGE ANALYSIS:

Initial Access:
  Base Probability: 1.0%
  Conditional Probability: 1.0%
  Contributing Factors:
    - no_vulnerabilities: 0.01 (99% reduction)

Execution:
  Base Probability: 0.1%
  Conditional Probability: 5.8%
  Affected Components: frontend, backend, cicd
  Contributing Factors:
    - base_execution: 0.80 (20% reduction)
    - docker_good_rce_protection: 0.30 (70% reduction)
    - edr_xdr: 0.40 (60% reduction)
    - waf: 0.60 (40% reduction)

Lateral Movement:
  Base Probability: 0.3%
  Conditional Probability: 5.2%
  Affected Components: backend, database, messaging, cicd
  Contributing Factors:
    - base_lateral: 0.70 (30% reduction)
    - network_segmentation: 0.30 (70% reduction)
    - docker_good_network_isolation: 0.50 (50% reduction)
    - edr_xdr: 0.50 (50% reduction)

Objective Achievement:
  Base Probability: 4.7%
  Conditional Probability: 90.0%
  Affected Components: database, cicd
  Contributing Factors:
    - base_objective: 0.90 (10% reduction)

DOCKER SECURITY POSTURE:
  Good Practices: Yes
  Impact: 60% reduction in execution/lateral movement

KEY INSIGHTS:
  • Bottleneck Stage: Initial Access (1.0%) - hardest stage to breach, strong defensive position
  • Security Impact: Good Docker security practices reduce execution risk
  • Network Isolation: Low lateral movement probability (5.2%) shows effective network segmentation
  • Threat Level: Negligible overall risk despite individual stage vulnerabilities

SCANNED ENVIRONMENT
--------------------------------------------------------------------------------
Organization Size: mid
Geographic Reach: regional
Industry: consulting
Environment Type: prod
Security Maturity: defined

Active Security Controls: 8
  network_segmentation, firewall, waf, ids_ips, edr_xdr, antivirus, mfa, patch_weekly

================================================================================
```

**Key Observations for Scenario 2**:
- ✅ **Good Docker security practices**: 70% reduction in RCE risk
- ✅ **Network segmentation**: 70% reduction in lateral movement
- ✅ **EDR/XDR deployed**: 40-60% reduction across stages
- ⚠️ **Objective Achievement high**: 90% - needs data encryption and DLP
- ⚠️ **23 critical vulnerabilities** (0.3% of total) - better than poor security

---

## Scenario 3: Good Security (Managed Maturity)

This is the primary demo report showing a **mid-size financial services organization** with **managed security maturity** (12 active security controls).

```
================================================================================
VULNERABILITY ASSESSMENT REPORT
================================================================================
Generated: 2026-01-01 15:56:52 UTC

EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Vulnerabilities Scanned: 3783
Average Exploitation Probability: 0.07%
Average Uncertainty: ±5.39%
Business Risk Level: LOW

Original Severity Distribution (Scanner Output):
  Critical: 159 (4.2%)
  High: 876 (23.2%)
  Medium: 1678 (44.4%)
  Low: 669 (17.7%)
  Negligible: 390 (10.3%)
  Unknown: 11 (0.3%)

Bayesian Risk Assessment (After Analysis):
  Critical: 18 (0.5%)
  High: 17 (0.4%)
  Medium: 40 (1.1%)
  Low: 318 (8.4%)
  Negligible: 3390 (89.6%)

Actionable Vulnerabilities (Critical+High+Medium): 75
Critical/High Requiring Immediate Action: 35 (0.9%)

Estimated Remediation Effort: 146 person-hours
Recommended Timeline: 4 weeks

Known Exploited Vulnerabilities (KEV): 40
Public Exploits Available: 0
Metasploit Modules: 0
High Exploitation Probability (EPSS>=0.5): 80

KILL-CHAIN PROBABILITY ANALYSIS
--------------------------------------------------------------------------------
Application: Financial Services Platform
Type: financial_services
Description: Banking/trading platform with high security requirements
Components: 7

Application Components:
  - load-balancer (ingress): varnish:7.0 [internet-facing, high value]
  - api-gateway (backend): tomcat:9.0 [dmz, high value]
  - auth-service (auth): authelia/authelia:v4.36 [internal, critical value]
  - transaction-processor (backend): python:3.9-slim [internal, critical value]
  - financial-database (database): mongo:5.0 [internal, critical value]
  - reporting-service (backend): metabase/metabase:v0.44.0 [internal, high value]
  - audit-log (messaging): rabbitmq:3.8-management [internal, high value]

KILL-CHAIN SUCCESS PROBABILITY
Overall Probability: 0.0%
Threat Level: Negligible
Bottleneck Stage: Initial Access

STAGE-BY-STAGE ANALYSIS:

Initial Access:
  Base Probability: 1.0%
  Conditional Probability: 1.0%
  Contributing Factors:
    - no_vulnerabilities: 0.01 (99% reduction)

Execution:
  Base Probability: 0.1%
  Conditional Probability: 5.8%
  Affected Components: backend
  Contributing Factors:
    - base_execution: 0.80 (20% reduction)
    - docker_good_rce_protection: 0.30 (70% reduction)
    - edr_xdr: 0.40 (60% reduction)
    - waf: 0.60 (40% reduction)

Lateral Movement:
  Base Probability: 0.2%
  Conditional Probability: 3.1%
  Affected Components: auth, backend, database, messaging
  Contributing Factors:
    - base_lateral: 0.70 (30% reduction)
    - network_segmentation: 0.30 (70% reduction)
    - docker_good_network_isolation: 0.50 (50% reduction)
    - edr_xdr: 0.50 (50% reduction)
    - siem: 0.60 (40% reduction)

Objective Achievement:
  Base Probability: 2.0%
  Conditional Probability: 63.0%
  Affected Components: database, messaging
  Contributing Factors:
    - base_objective: 0.90 (10% reduction)
    - siem: 0.70 (30% reduction)

DOCKER SECURITY POSTURE:
  Good Practices: Yes
  Impact: 60% reduction in execution/lateral movement

KEY INSIGHTS:
  • Bottleneck Stage: Initial Access (1.0%) - hardest stage to breach, strong defensive position
  • Security Impact: Good Docker security practices reduce execution risk
  • Network Isolation: Low lateral movement probability (3.1%) shows effective network segmentation
  • Threat Level: Negligible overall risk despite individual stage vulnerabilities
  • Initial Access: Strong perimeter defenses (1.0%) effectively prevent unauthorized entry

INTERPRETATION:
  ✓  LOW: Low probability of successful kill-chain execution.
  However, individual stages require attention:

SCANNED ENVIRONMENT
--------------------------------------------------------------------------------
Organization Size: mid
Geographic Reach: regional
Industry: financial-services
Environment Type: prod
Security Maturity: managed

Active Security Controls: 12
  network_segmentation, firewall, waf, ids_ips, edr_xdr, antivirus, mfa, 
  privileged_access_mgmt, patch_weekly, siem, soc_24x7, incident_response_plan

TEAM-BASED BAYESIAN RISK HEATMAP
--------------------------------------------------------------------------------
Ownership\Risk      Critical   High       Medium     Low        Negligible
DEV                 13         14         28         252        2893      
DBTEAM              3          2          8          42         545       
DEVOPS              1          1          3          18         201       
SECURITY            1          0          1          6          141       

================================================================================
```

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
  - [Poor Security Report](output/scenarios/poor_security/report_2026-01-01_15-53-17.txt)
  - [Average Security Report](output/scenarios/average_security/report_2026-01-01_15-55-11.txt)
  - [Good Security Report](output/scenarios/good_security/report_2026-01-01_15-56-52.txt)

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
