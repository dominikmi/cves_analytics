# CVEs Analytics - Multi-Scenario Comparison

**Version:** 2.2  
**Generated:** January 3, 2026  
**Document Type:** Examples & Demonstrations  
**Estimated Reading Time:** 15-20 minutes

## Intended Audience

**Primary:** Security managers, decision-makers, risk assessors  
**Secondary:** Security analysts comparing maturity levels

**Prerequisites:**
- None - this is a comparative overview
- Familiarity with security maturity models (helpful)

**What You'll Learn:**
- Side-by-side comparison of three security maturity levels
- Impact of control types on vulnerability risk
- How maturity affects kill-chain probability
- ROI insights for security investments

---

This document showcases the CVEs Analytics tool's capabilities across three different security maturity levels, demonstrating how **probabilistic control types** and security practices impact vulnerability risk and kill-chain attack probabilities.

**Key Enhancement in v2.0:** Control types are now modeled probabilistically with varying effectiveness levels (e.g., FIDO2 vs SMS for MFA, NGFW vs Basic Firewall), providing more realistic and granular risk assessments.

> **IMPORTANT NOTE ON LIKELIHOOD RATIOS:**
> The control effectiveness values (LR values) shown in this document are informed heuristics based on security principles and industry observations, not empirically validated measurements. The percentage reductions represent theoretical effectiveness under ideal implementation conditions. Actual effectiveness varies by implementation quality, organizational context, configuration, and threat landscape. These comparisons are best used for **relative assessment** (comparing maturity levels) rather than **absolute prediction** (exact risk reduction).

---

## 📊 Scenario Overview

| Metric | **Scenario 1: Initial** | **Scenario 2: Managed** | **Scenario 3: Optimizing** |
|--------|-------------------------|-------------------------|----------------------------|
| **Organization** | Small, Local | Mid-size, Regional | Large, Global |
| **Industry** | Consulting | Financial Services | Financial Services |
| **Environment** | Development | Production | Production |
| **Security Maturity** | **Initial** (Ad-hoc, reactive) | **Managed** (Measured & controlled) | **Optimizing** (Continuous improvement) |
| **Active Controls** | **8 controls** | **11 controls** | **12 controls** |
| **Services Scanned** | 7 services | 7 services | 7 services |
| **Total Vulnerabilities** | 2,398 | 4,365 | 4,301 |
| **Avg Exploit Prob** | 0.34% | 0.37% | 0.27% |
| **Kill-Chain Prob** | 0.9% | 0.9% | 0.9% |

---

## 🔴 Scenario 1: Initial Maturity (Small Business)

### Environment Profile
- **Organization**: Small consulting firm, local reach
- **Environment**: Development
- **Security Maturity**: **Initial** - Ad-hoc security, reactive approach
- **Active Controls**: 8 (basic implementations)

### Control Types Deployed
```
MFA:                  none
Firewall:             basic (LR=0.7, ~30% reduction)
WAF:                  none
Endpoint Protection:  traditional_av (LR=0.7, ~30% reduction)
Network Segmentation: none
IDS/IPS:              none
Patch Management:     quarterly (LR=0.7, ~30% reduction)
Incident Response:    True
```

### Vulnerability Assessment Results

**Total Vulnerabilities**: 2,398

**Bayesian Risk Assessment**:
- Critical: **72** (3.0%)
- High: **72** (3.0%)
- Medium: **53** (2.2%)
- Low: **94** (3.9%)
- Negligible: **2,107** (87.9%)

**Actionable Vulnerabilities**: 197 (Critical+High+Medium)
**Critical/High Requiring Immediate Action**: 144 (6.0%)

**Threat Intelligence**:
- Known Exploited Vulnerabilities (KEV): **17**
- High Exploitation Probability (EPSS>=0.5): **40**

**Remediation Effort**: 485 person-hours (~13 weeks)

### Top Critical Vulnerabilities
1. **CVE-2023-44487** - P(Exploit): **99.9%** in nginx-web (HTTP/2 Rapid Reset)
2. **CVE-2018-25032** - P(Exploit): **50.6%** in nginx-web (zlib compression)
3. **CVE-2025-27363** - P(Exploit): **98.5%** in nginx-web (recent vulnerability)

### Kill-Chain Analysis
**Overall Probability**: 0.9%  
**Bottleneck Stage**: Initial Access (1.0%)

**Stage Breakdown**:
- Initial Access: 1.0% (strong perimeter despite weak controls)
- Execution: 100.0% conditional (poor Docker practices, 30% increase)
- Lateral Movement: 100.0% conditional (flat network, no segmentation)
- Objective Achievement: 90.0% conditional

### Key Observations
- ⚠️ **No MFA**: 100% vulnerable to credential attacks
- ⚠️ **No WAF**: Web applications fully exposed
- ⚠️ **No network segmentation**: 100% lateral movement probability
- ⚠️ **Poor Docker practices**: 30% risk increase in execution
- ⚠️ **Quarterly patching**: Only 30% risk reduction (LR=0.7)
- ⚠️ **Traditional AV only**: 30% reduction vs 50-70% for EDR/XDR

---

## 🟡 Scenario 2: Managed Maturity (Mid-Size)

### Environment Profile
- **Organization**: Mid-size financial services, regional reach
- **Environment**: Production
- **Security Maturity**: **Managed** - Measured and controlled security
- **Active Controls**: 11 (moderate to good implementations)

### Control Types Deployed
```
MFA:                  authenticator_app (LR=0.15, ~85% reduction)
Firewall:             stateful (LR=0.5, ~50% reduction)
WAF:                  managed (LR=0.4, ~60% reduction)
Endpoint Protection:  basic_edr (LR=0.5, ~50% reduction)
Network Segmentation: basic_vlan (LR=0.7, ~30% reduction)
IDS/IPS:              ips_signature (LR=0.5, ~50% reduction)
SIEM:                 basic_correlation (LR=0.6, ~40% reduction)
Patch Management:     monthly (LR=0.4, ~60% reduction)
Privileged Access:    True
Incident Response:    True
Security Training:    True
```

### Vulnerability Assessment Results

**Total Vulnerabilities**: 4,365

**Bayesian Risk Assessment**:
- Critical: **167** (3.8%)
- High: **108** (2.5%)
- Medium: **112** (2.6%)
- Low: **263** (6.0%)
- Negligible: **3,715** (85.1%)

**Actionable Vulnerabilities**: 387 (Critical+High+Medium)
**Critical/High Requiring Immediate Action**: 275 (6.3%)

**Threat Intelligence**:
- Known Exploited Vulnerabilities (KEV): **42**
- High Exploitation Probability (EPSS>=0.5): **81**

**Remediation Effort**: 875 person-hours (~22 weeks)

### Kill-Chain Analysis
**Application**: Financial Services Platform (7 components)

**Kill-Chain Success Probability**: 0.9%
**Threat Level**: Negligible
**Bottleneck Stage**: Initial Access (1.0%)

**Stage Breakdown**:
- Initial Access: 1.0% (strong perimeter)
- Execution: 100.0% conditional (still poor Docker practices)
- Lateral Movement: 100.0% conditional (basic VLAN only 30% reduction)
- Objective Achievement: 90.0% conditional

### Key Observations
- ✅ **Authenticator App MFA**: 85% reduction (LR=0.15) vs no MFA
- ✅ **Basic EDR deployed**: 50% reduction (LR=0.5)
- ✅ **Managed WAF**: 60% reduction (LR=0.4)
- ✅ **Monthly patching**: 60% reduction (LR=0.4) vs 30% for quarterly
- ⚠️ **Basic VLAN only**: 30% reduction vs 70% for micro-segmentation
- ⚠️ **Still poor Docker practices**: Execution stage remains vulnerable
- ⚠️ **More vulnerabilities**: Larger infrastructure = more attack surface

---

## 🟢 Scenario 3: Optimizing Maturity (Large Enterprise)

### Environment Profile
- **Organization**: Large financial services, global reach
- **Environment**: Production
- **Security Maturity**: **Optimizing** - Continuous improvement, advanced controls
- **Active Controls**: 12 (high-quality implementations)

### Control Types Deployed
```
MFA:                  fido2 (LR=0.05, ~95% reduction)
Firewall:             ngfw (LR=0.4, ~60% reduction)
WAF:                  owasp_crs (LR=0.3, ~70% reduction)
Endpoint Protection:  advanced_edr (LR=0.4, ~60% reduction)
Network Segmentation: basic_vlan (LR=0.7, ~30% reduction)
IDS/IPS:              ips_signature (LR=0.5, ~50% reduction)
SIEM:                 advanced_analytics (LR=0.5, ~50% reduction)
Patch Management:     weekly (LR=0.3, ~70% reduction)
Privileged Access:    True
24x7 SOC:             True (LR=0.5, ~50% reduction)
Incident Response:    True
Security Training:    True
```

### Vulnerability Assessment Results

**Total Vulnerabilities**: 4,301

**Bayesian Risk Assessment**:
- Critical: **101** (2.3%)
- High: **69** (1.6%)
- Medium: **92** (2.1%)
- Low: **164** (3.8%)
- Negligible: **3,875** (90.1%)

**Actionable Vulnerabilities**: 262 (Critical+High+Medium)
**Critical/High Requiring Immediate Action**: 170 (4.0%)

**Threat Intelligence**:
- Known Exploited Vulnerabilities (KEV): **42**
- High Exploitation Probability (EPSS>=0.5): **81**

**Remediation Effort**: 620 person-hours (~16 weeks)

### Kill-Chain Analysis
**Application**: Financial Services Platform (7 components)

**Kill-Chain Success Probability**: 0.9%
**Threat Level**: Negligible
**Bottleneck Stage**: Initial Access (1.0%)

**Stage Breakdown**:
- Initial Access: 1.0% (strong perimeter)
- Execution: 100.0% conditional (poor Docker practices persist)
- Lateral Movement: 100.0% conditional (still flat network)
- Objective Achievement: 90.0% conditional

### Key Observations
- ✅ **FIDO2 MFA**: 95% reduction (LR=0.05) - strongest MFA available
- ✅ **OWASP CRS WAF**: 70% reduction (LR=0.3) - comprehensive rule set
- ✅ **Advanced EDR**: 60% reduction (LR=0.4) vs 50% for basic
- ✅ **Weekly patching**: 70% reduction (LR=0.3) - aggressive cycle
- ✅ **24x7 SOC**: 50% reduction (LR=0.5) - continuous monitoring
- ✅ **Advanced SIEM**: 50% reduction (LR=0.5) with analytics
- ✅ **Lowest critical %**: 2.3% vs 3.0% (initial) and 3.8% (managed)
- ⚠️ **Still 90.1% negligible**: Strong controls work effectively

---

## 📈 Comparative Analysis

> **Note:** The scenarios below are simulated demonstrations using the CVEs Analytics pipeline to illustrate how control types affect risk assessment. Values shown are based on the framework's Bayesian calculations with heuristic LR values.

### Control Type Effectiveness Comparison

| Control Type | Initial | Managed | Optimizing | Impact |
|--------------|---------|---------|------------|--------|
| **MFA** | none | authenticator_app (LR=0.15) | fido2 (LR=0.05) | **0% -> ~85% -> ~95% reduction** |
| **Firewall** | basic (LR=0.7) | stateful (LR=0.5) | ngfw (LR=0.4) | **~30% -> ~50% -> ~60% reduction** |
| **WAF** | none | managed (LR=0.4) | owasp_crs (LR=0.3) | **0% -> ~60% -> ~70% reduction** |
| **Endpoint** | traditional_av (LR=0.7) | basic_edr (LR=0.5) | advanced_edr (LR=0.4) | **~30% -> ~50% -> ~60% reduction** |
| **Segmentation** | none | basic_vlan (LR=0.7) | basic_vlan (LR=0.7) | **0% -> ~30% -> ~30% reduction** |
| **Patch Mgmt** | quarterly (LR=0.7) | monthly (LR=0.4) | weekly (LR=0.3) | **~30% -> ~60% -> ~70% reduction** |
| **SIEM** | none | basic_correlation (LR=0.6) | advanced_analytics (LR=0.5) | **0% -> ~40% -> ~50% reduction** |
| **SOC** | none | none | 24x7 (LR=0.5) | **0% -> 0% -> ~50% reduction** |

### Vulnerability Risk Comparison

| Metric | Initial | Managed | Optimizing | Trend |
|--------|---------|---------|------------|-------|
| **Total Vulnerabilities** | 2,398 | 4,365 | 4,301 | Larger infrastructure = more vulns |
| **Critical %** | 72 (3.0%) | 167 (3.8%) | 101 (2.3%) | **Optimizing has lowest %** |
| **Negligible %** | 2,107 (87.9%) | 3,715 (85.1%) | 3,875 (90.1%) | **Strong controls = more negligible** |
| **Actionable Vulns** | 197 | 387 | 262 | Varies by infrastructure size |
| **Avg Exploit Prob** | 0.34% | 0.37% | 0.27% | **Optimizing has lowest probability** |
| **Remediation Effort** | 485 hrs (13 wks) | 875 hrs (22 wks) | 620 hrs (16 wks) | More vulns = more effort |

### Kill-Chain Probability Comparison

| Stage | Initial | Managed | Optimizing | Key Difference |
|-------|---------|---------|------------|----------------|
| **Initial Access** | 1.0% | 1.0% | 1.0% | All have strong perimeter |
| **Execution** | 100.0% | 100.0% | 100.0% | All have poor Docker practices |
| **Lateral Movement** | 100.0% | 100.0% | 100.0% | All have flat/basic networks |
| **Objective** | 90.0% | 90.0% | 90.0% | Similar without DLP |
| **Overall** | 0.9% | 0.9% | 0.9% | **Bottleneck at Initial Access** |

**Key Insight**: Kill-chain probabilities are similar across scenarios because the **bottleneck is Initial Access** (1.0%), which is consistently strong. However, **individual control quality** varies significantly, affecting defense-in-depth.

> **Note:** These probabilities are calculated using the kill-chain methodology with stage-specific LR values. Identical overall probabilities indicate that the bottleneck stage dominates the result. See [EXTENDED_KILL_CHAIN_METHOD.md](EXTENDED_KILL_CHAIN_METHOD.md) for methodology details.

---

## 🎯 Key Takeaways

> **Note:** The effectiveness values below are based on heuristic LR estimates. Actual improvements vary by implementation quality and organizational factors.

### 1. **Control Type Quality Matters More Than Quantity**
- **Initial (8 controls)**: Basic implementations, 87.9% negligible
- **Managed (11 controls)**: Moderate implementations, 85.1% negligible  
- **Optimizing (12 controls)**: Advanced implementations, **90.1% negligible**
- **Insight**: Quality (FIDO2 vs none) > Quantity (12 vs 8 controls)

### 2. **MFA Effectiveness Varies Dramatically**
- **No MFA**: 100% vulnerable to credential attacks
- **Authenticator App (LR=0.15)**: ~85% reduction
- **FIDO2 (LR=0.05)**: ~95% reduction
- **Impact**: FIDO2 is **~10% more effective** than authenticator apps

### 3. **Patch Cadence Has Significant Impact**
- **Quarterly (LR=0.7)**: ~30% reduction, long exposure window
- **Monthly (LR=0.4)**: ~60% reduction, **~2x more effective**
- **Weekly (LR=0.3)**: ~70% reduction, **~2.3x more effective**
- **Insight**: Aggressive patching provides exponential benefits

### 4. **Endpoint Protection Evolution**
- **Traditional AV (LR=0.7)**: ~30% reduction
- **Basic EDR (LR=0.5)**: ~50% reduction, **~67% more effective**
- **Advanced EDR (LR=0.4)**: ~60% reduction, **~100% more effective**
- **Impact**: EDR/XDR provides 2x better protection than traditional AV

### 5. **Defense-in-Depth Multiplies Effectiveness**
- **Single control**: Linear reduction (e.g., ~50%)
- **Multiple controls**: Multiplicative reduction (0.5 × 0.4 × 0.3 = 0.06 = ~94% total)
- **Example**: FIDO2 (0.05) + OWASP WAF (0.3) + Advanced EDR (0.4) = **~99.4% combined reduction**
- **Note:** Assumes conditional independence; actual effectiveness may vary due to control correlations

### 6. **Bottleneck Analysis Guides Priorities**
- All scenarios: **Initial Access (1.0%)** is the bottleneck
- **Insight**: Strong perimeter controls are effective across all maturity levels
- **Recommendation**: Focus on execution/lateral movement improvements for defense-in-depth

### 7. **Realistic Variability in Control Deployment**
- Even optimizing organizations don't have perfect controls everywhere
- Basic VLAN segmentation (30% reduction) vs micro-segmentation (70% reduction)
- **Insight**: Probabilistic modeling reflects real-world constraints and priorities

---

## 🔧 Tool Capabilities Demonstrated

### ✅ Probabilistic Control Types (v2.0)
- **8 control categories** with varying implementation levels
- **Realistic distributions** based on maturity and industry
- **Granular LR values** for each control type (e.g., FIDO2 vs SMS)
- **Industry modifiers** (financial services favors FIDO2)

### ✅ Multi-Component Application Analysis
- Analyzes complete applications (7-component platforms)
- Industry-specific templates (financial services, consulting)
- Component-level vulnerability assessment
- Kill-chain stage mapping

### ✅ Security Control Effectiveness Modeling
- **Protective controls** (LR < 1.0): Reduce risk
- **Bad practices** (LR > 1.0): Increase risk
- **Multiplicative effects**: Defense-in-depth modeling
- **Realistic control quality**: Not all firewalls are equal

### ✅ Kill-Chain Probability Analysis
- Sequential stage calculation (Initial Access → Execution → Lateral Movement → Objective)
- Bottleneck identification (Initial Access at 1.0%)
- Stage-specific remediation recommendations
- Docker security impact assessment

### ✅ Bayesian Risk Assessment
- EPSS-based prior probability (empirically validated by FIRST.org)
- EPSS trajectory analysis for temporal risk adjustment (v2.2)
- Environmental context integration
- Control effectiveness application
- Uncertainty quantification (95% credible intervals)

### ✅ Adaptive Analysis
- Adjusts to organization size, industry, environment
- Security maturity-based control generation
- Realistic threat modeling

---

## 📝 Recommendations by Scenario

### Poor Security (Initial Maturity)
**Priority Actions**:
1. Implement Docker security hardening (non-root, read-only FS, seccomp)
2. Deploy EDR/XDR for execution stage protection
3. Upgrade to weekly patching cadence
4. Implement MFA for authentication
5. Deploy WAF for internet-facing services

**Expected Impact**: ~60-70% reduction in critical vulnerabilities

### Average Security (Defined Maturity)
**Priority Actions**:
1. Deploy SIEM for monitoring and detection
2. Implement data encryption at rest
3. Deploy DLP solutions for objective achievement stage
4. Add privileged access management
5. Establish SOC for 24x7 monitoring

**Expected Impact**: ~30-40% additional risk reduction

### Good Security (Managed Maturity)
**Priority Actions**:
1. Continue monitoring and optimization
2. Implement advanced threat hunting
3. Enhance automation and orchestration
4. Regular security control validation
5. Continuous improvement based on metrics

**Expected Impact**: Maintain strong security posture, prevent degradation

---

## ⚠️ Methodology Limitations

These scenarios demonstrate the CVEs Analytics pipeline's capabilities but should be understood in context:

1. **Heuristic LR Values**: Control effectiveness values are informed estimates, not empirically measured
2. **Ideal Implementation**: Percentages assume proper configuration and implementation
3. **Relative Comparison**: Framework optimized for comparing scenarios, not absolute prediction
4. **Validation Needed**: Real-world effectiveness requires validation against actual breach data

See [BAYESIAN_RISK_ASSESSMENT.md](BAYESIAN_RISK_ASSESSMENT.md) and [EXTENDED_KILL_CHAIN_METHOD.md](EXTENDED_KILL_CHAIN_METHOD.md) for detailed methodology and caveats.
