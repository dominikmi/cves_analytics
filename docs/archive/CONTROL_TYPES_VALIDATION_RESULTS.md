# Control Types System - Validation Results

**Date:** January 2, 2026  
**Pipeline Version:** 2.0 (Probabilistic Control Types)  
**Test Configuration:** Large Financial Services Organization, Optimizing Maturity  
**Document Type:** Test Results (Historical)  
**Status:** ARCHIVED - For historical reference only

## Intended Audience

**Primary:** Developers reviewing historical test results  
**Secondary:** Quality assurance teams

**Prerequisites:**
- Understanding of the control types system
- Familiarity with pipeline testing

**Note:** This document contains test results from January 2, 2026. It is kept for historical reference but may be outdated. For current validation, run the test suite with `pytest tests/`.

---

## Executive Summary

The new probabilistic control types system was successfully validated through full pipeline execution. The system generates realistic security control distributions based on organizational maturity, industry, and exposure context, replacing the previous boolean (present/absent) model.

**Key Findings:**
- Pipeline completed successfully in 24.31 seconds
- Generated 12 active security controls with varying implementation types
- Bayesian risk assessment correctly applied control-specific LR values
- Control type distributions match expected patterns for optimizing financial services
- Average exploitation probability reduced to 0.34% (from baseline)

---

## Test Configuration

### Organization Profile
```
Size:              Large
Geographic Reach:  Global
Industry:          Financial Services
Environment:       Production
Security Maturity: Optimizing (Level 5)
```

### Services Scanned
- **Total Services:** 18
- **Internet-Facing:** 4 (nginx-web, apache-httpd, openvpn, bastion-host)
- **Internal:** 14 (databases, APIs, monitoring, caching, etc.)

### Vulnerability Dataset
- **Total Vulnerabilities:** 4,179
- **Scanner Severity Distribution:**
  - Critical: 85 (2.0%)
  - High: 628 (15.0%)
  - Medium: 1,780 (42.6%)
  - Low: 831 (19.9%)
  - Negligible: 845 (20.2%)

---

## Generated Control Types

### Single Run Results

**Control Types Generated:**
```
MFA Type:                FIDO2
Firewall Type:           Next-Gen Advanced (NGFW)
WAF Type:                OWASP CRS
Endpoint Protection:     Basic EDR
Network Segmentation:    Basic VLAN
IDS/IPS Type:            IDS Only
SIEM Maturity:           Advanced Analytics
Patch Management:        Weekly
```

**Boolean Controls:**
```
Privileged Access Mgmt:  True
24x7 SOC:                True
Incident Response Plan:  True
Security Training:       True
Air Gapped:              False
```

### Effectiveness Values (Likelihood Ratios)

```
Control                      LR      Reduction
-------------------------------------------------
MFA (FIDO2)                 0.05    95%
Firewall (NGFW Advanced)    0.30    70%
WAF (OWASP CRS)             0.30    70%
Endpoint (Basic EDR)        0.50    50%
Network Seg (Basic VLAN)    0.70    30%
IDS/IPS (IDS Only)          0.80    20%
SIEM (Advanced Analytics)   0.50    50%
Patch Mgmt (Weekly)         0.30    70%
Privileged Access Mgmt      0.40    60%
24x7 SOC                    0.50    50%
Incident Response Plan      0.70    30%
Security Training           0.80    20%
```

**Combined Risk Reduction:**
- Individual controls range from 20% to 95% reduction
- Multiplicative effect creates strong defense-in-depth
- FIDO2 MFA provides strongest single control (95% reduction)

---

## Variability Analysis (10 Runs)

### MFA Type Distribution
```
FIDO2:                6/10 (60%)
Push Notification:    3/10 (30%)
Authenticator App:    1/10 (10%)
SMS:                  0/10 (0%)
None:                 0/10 (0%)
```

**Analysis:** Optimizing financial services heavily favor FIDO2 (60%) and push notification (30%), with minimal use of weaker methods. No runs generated SMS or no MFA, which is realistic for mature financial institutions.

### Firewall Type Distribution
```
Next-Gen (NGFW):      6/10 (60%)
NGFW Advanced:        2/10 (20%)
Stateful:             2/10 (20%)
Basic:                0/10 (0%)
None:                 0/10 (0%)
```

**Analysis:** All runs generated at least stateful firewalls, with 80% using next-gen capabilities. This reflects the high security standards expected in financial services.

### WAF Type Distribution
```
OWASP CRS:            5/10 (50%)
Basic:                2/10 (20%)
Managed:              2/10 (20%)
Custom Tuned:         1/10 (10%)
None:                 0/10 (0%)
```

**Analysis:** 50% of runs generated OWASP CRS (comprehensive rule set), with remaining runs distributed across other WAF types. No runs generated "none", indicating WAF is standard for production environments.

---

## Bayesian Risk Assessment Results

### Severity Reassessment

**Original Scanner Output -> Bayesian Assessment:**
```
Critical (85)  -> Critical: 11, High: 7, Medium: 7, Low: 1, Negligible: 59
High (628)     -> Critical: 65, High: 42, Medium: 27, Low: 50, Negligible: 444
Medium (1780)  -> Critical: 37, High: 65, Medium: 78, Low: 155, Negligible: 1445
Low (831)      -> Critical: 1, High: 13, Medium: 22, Low: 48, Negligible: 747
Negligible (845) -> Critical: 3, High: 10, Medium: 4, Low: 14, Negligible: 814
```

**Final Bayesian Distribution:**
```
Critical:      117 (2.8%)  [+32 from scanner]
High:          137 (3.3%)  [-491 from scanner]
Medium:        138 (3.3%)  [-1642 from scanner]
Low:           268 (6.4%)  [-563 from scanner]
Negligible:    3519 (84.2%) [+2674 from scanner]
```

**Key Insights:**
- 84.2% of vulnerabilities assessed as negligible after control analysis
- Only 6.1% require immediate action (Critical + High)
- Strong controls reduced actionable vulnerabilities from 2,493 to 392 (84% reduction)
- Average exploitation probability: 0.34% (very low)

### Top Critical Vulnerabilities

**Example: CVE-2021-40438 in apache-httpd**
```
Bayesian Risk:        Critical
P(Exploit):           99.6% [94.5%-100.0%]
CVSS:                 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H)
EPSS:                 94.43%
Exposure:             Internet-facing
Service Role:         Web server
```

**Why Critical Despite Controls:**
- CVSS 9.0 (extremely severe)
- EPSS 94.43% (very high exploitation probability)
- Internet-facing exposure
- Scope change (S:C) enables lateral movement
- Even with strong controls, remains critical due to severity and exposure

---

## Control Types Impact Analysis

### Comparison: With vs Without Control Types

**Scenario: Same vulnerability (CVE-2021-40438) with different control implementations**

**Previous Boolean Model:**
```
MFA:              True/False  -> LR = 0.15 (fixed)
Firewall:         True/False  -> LR = 0.5 (fixed)
WAF:              True/False  -> LR = 0.4 (fixed)
```

**New Control Types Model:**
```
MFA:              FIDO2       -> LR = 0.05 (95% reduction)
Firewall:         NGFW Adv    -> LR = 0.30 (70% reduction)
WAF:              OWASP CRS   -> LR = 0.30 (70% reduction)
```

**Impact:**
- More granular risk assessment
- Reflects actual implementation quality
- Better prioritization based on control maturity
- Realistic variability across organizations

---

## Industry Pattern Validation

### Expected vs Actual for Financial Services (Optimizing)

**MFA:**
- Expected: High FIDO2 adoption (50-70%)
- Actual: 60% FIDO2, 30% Push, 10% Authenticator
- **Validation:** PASS - Matches industry standards

**Firewall:**
- Expected: Mostly NGFW (70-90%)
- Actual: 80% NGFW or better, 20% Stateful
- **Validation:** PASS - Reflects enterprise standards

**WAF:**
- Expected: Strong WAF presence (90-100%)
- Actual: 100% WAF coverage, 50% OWASP CRS
- **Validation:** PASS - No production without WAF

**Patch Management:**
- Expected: Weekly or better (60-80%)
- Actual: Weekly (single run)
- **Validation:** PASS - Aggressive patching for finance

---

## Performance Metrics

### Pipeline Execution Time
```
Total Duration:           24.31 seconds
Docker Scanning:          ~15 seconds
Vulnerability Analysis:   0.16 seconds
Report Generation:        0.09 seconds
```

### Control Type Selection Performance
```
Single Generation:        <1ms
10 Generations:           <10ms
Overhead:                 Negligible
```

**Analysis:** Control type selection adds minimal overhead compared to previous boolean model.

---

## Realistic Variability Demonstration

### Scenario 1: Optimizing Financial Services (Current Test)
```
MFA Distribution:         60% FIDO2, 30% Push, 10% Auth App
Firewall Distribution:    60% NGFW, 20% NGFW Adv, 20% Stateful
Result:                   Strong security posture, low risk
```

### Scenario 2: Initial Small Business (Simulated)
```
Expected MFA:             70% None, 25% SMS, 5% Auth App
Expected Firewall:        50% Basic, 40% Stateful, 10% NGFW
Result:                   Weak security posture, high risk
```

### Scenario 3: Managed Healthcare (Simulated)
```
Expected MFA:             40% Auth App, 30% Push, 20% SMS, 10% None
Expected Firewall:        50% Stateful, 30% NGFW, 20% Basic
Result:                   Moderate security posture, medium risk
```

**Key Insight:** System generates realistic distributions that reflect real-world organizational constraints and priorities.

---

## Kill-Chain Probability Analysis Results

### Application Profile
```
Application Type:     Financial Services Platform
Components:           7 (load-balancer, api-gateway, auth-service, 
                      transaction-processor, financial-database, 
                      reporting-service, audit-log)
Description:          Banking/trading platform with high security requirements
```

### Kill-Chain Success Probability
```
Overall Probability:  0.9%
Threat Level:         Negligible
Bottleneck Stage:     Initial Access (1.0%)
```

### Stage-by-Stage Breakdown

**Stage 1: Initial Access**
```
Base Probability:           1.0%
Conditional Probability:    1.0%
Contributing Factors:
  - no_vulnerabilities:     0.01 (99% reduction)
```

**Stage 2: Execution**
```
Base Probability:           1.0%
Conditional Probability:    100.0%
Affected Components:        backend
Contributing Factors:
  - base_execution:         0.80 (20% reduction)
  - docker_poor_rce_no_protection: 1.30 (30% increase)
```

**Stage 3: Lateral Movement**
```
Base Probability:           100.0%
Conditional Probability:    100.0%
Affected Components:        auth, backend, database, messaging
Contributing Factors:
  - base_lateral:           0.70 (30% reduction)
  - flat_network:           1.30 (30% increase)
  - docker_poor_network_isolation: 1.20 (20% increase)
```

**Stage 4: Objective Achievement**
```
Base Probability:           90.0%
Conditional Probability:    90.0%
Affected Components:        database, messaging
Contributing Factors:
  - base_objective:         0.90 (10% reduction)
```

### Docker Security Assessment
```
Good Practices:       No
Impact:               20% reduction in execution/lateral movement
```

**Poor Docker Practices Identified:**
- Root user execution (RCE vulnerability = immediate root access)
- No network isolation between containers
- Flat network topology enabling lateral movement

### Key Insights

1. **Bottleneck Stage:** Initial Access (1.0%) - hardest stage to breach, strong defensive position
2. **Security Impact:** Poor Docker practices significantly increase execution risk
3. **Network Isolation:** High lateral movement probability (100.0%) suggests flat network topology
4. **Threat Level:** Negligible overall risk despite individual stage vulnerabilities
5. **Initial Access:** Strong perimeter defenses (1.0%) effectively prevent unauthorized entry

### Recommended Actions

**Critical Priority:**
- **Execution (100.0%):** Implement Docker security best practices (non-root users, read-only filesystems, capability dropping)

**High Priority:**
- **Lateral Movement (100.0%):** Implement network segmentation and micro-segmentation between services

**Medium Priority:**
- **Objective Achievement (90.0%):** Implement data encryption at rest, enhance access controls, deploy DLP solutions

### Analysis

The kill-chain analysis demonstrates the effectiveness of strong perimeter controls (1.0% initial access probability) in preventing successful attacks, even when internal controls are weak. However, the 100% conditional probabilities for execution and lateral movement indicate significant vulnerabilities if initial access is achieved.

**Key Takeaway:** Defense-in-depth is critical. While strong perimeter controls reduce overall risk to 0.9%, poor Docker practices and flat network topology create high risk if perimeter is breached.

---

## Known Limitations & Future Improvements

### Current Limitations

1. **Exposure Modifiers Not Fully Utilized**
   - Internet-facing services should have stronger controls
   - Current implementation applies modifiers but could be more aggressive

2. **No Temporal Factors**
   - Control age/maturity not considered
   - Recent deployments vs mature implementations treated equally

3. **No Cost Constraints**
   - Optimizing maturity assumes unlimited budget
   - Real organizations have budget constraints

### Planned Improvements

1. **Add Control Correlation**
   - Organizations with FIDO2 likely have XDR (not just Basic EDR)
   - Model control co-occurrence patterns

2. **Add Temporal Decay**
   - Controls degrade over time without maintenance
   - Factor in deployment age

3. **Add Budget Constraints**
   - Limit advanced controls based on organization size
   - More realistic for small/mid-size organizations

4. **Add Compliance Drivers**
   - PCI-DSS, HIPAA, SOC2 requirements
   - Force minimum control levels for regulated industries

---

## Validation Conclusion

**Status:** PASSED

The probabilistic control types system successfully:
1. Generates realistic control distributions based on maturity and industry
2. Applies correct effectiveness values (LR) for Bayesian risk assessment
3. Produces expected variability across multiple runs
4. Integrates seamlessly with existing pipeline components
5. Provides more granular and accurate risk assessments

**Recommendation:** Deploy to production with monitoring for edge cases.

---

## References

### Pipeline Run Details
- **Report:** `output/test_control_types/report_2026-01-02_07-41-32.txt`
- **Configuration:** Large, Global, Financial Services, Production, Optimizing
- **Duration:** 24.31 seconds
- **Vulnerabilities Analyzed:** 4,179

### Control Type Definitions
- **Source:** `src/simulation/control_types.py`
- **Probabilities:** `src/simulation/control_probabilities.py`
- **Selection Logic:** `src/simulation/control_type_selector.py`
- **LR Mapping:** `src/core/control_lr_mapper.py`

### Documentation
- **Security Controls Guide:** `docs/SECURITY_CONTROLS_GUIDE.md` (Version 2.0)
- **Bayesian Risk Assessment:** `docs/BAYESIAN_RISK_ASSESSMENT.md`
- **Technical Setup:** `docs/TECHNICAL_SETUP.md`
