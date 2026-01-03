# CVEs Analytics: Comprehensive Vulnerability Assessment Framework

## Introduction

A few years ago, I worked at a company where I experienced firsthand the absurdity of (so called)traditional vulnerability management. One day, they sat me down at a desk, handed me an Excel spreadsheet with a list of CRITICAL, HIGH, MEDIUM, and LOW vulnerabilities across servers in different locations, and told me to call local security leaders asking why they hadn't patched their systems yet.

The whole situation was ridiculous. I had no context about which vulnerabilities actually mattered. I didn't know if a CRITICAL vulnerability on an internal development server was more urgent than a MEDIUM one on an internet-facing production system. I had no information about whether security controls were in place that might mitigate the risks. I couldn't tell security leaders anything useful beyond "this CVE has a high CVSS score" - which they already knew from their own scanners.

The conversations were predictably frustrating. Security leaders would ask reasonable questions: "Is this actually exploitable in our environment?" "Do we have compensating controls?" "Is this being actively exploited in the wild?" And I had no answers. The Excel spreadsheet only had CVE IDs, CVSS scores, and server names. No context, no prioritization beyond severity labels.

This experience highlighted a fundamental problem in how many organizations approach vulnerability management. We generate massive lists of vulnerabilities, categorize them by CVSS scores, and then expect security teams to somehow figure out what to fix first. It's inefficient, demotivating, and often leads to the wrong priorities. Critical vulnerabilities on isolated systems get immediate attention while actively exploited vulnerabilities on exposed systems wait in the queue because they're labeled "MEDIUM."

This project was born from that frustration, but also from reading great books about probability, quantitative risk, and Bayesian calculus - ["Superforecasting"](https://www.penguinrandomhouse.com/books/227815/superforecasting-by-philip-e-tetlock-and-dan-gardner/) by Philip Tetlock and Dan Gardner, ["How to Measure Anything in Cybersecurity Risk"](https://www.howtomeasureanything.com/cybersecurity/) by Douglas Hubbard and Richard Seiersen, ["Metrics Manifesto"](https://www.themetricsmanifesto.com/) by Richard Seiersen, ["Bernoulli's Fallacy"](https://cup.columbia.edu/book/bernoullis-fallacy/9780231199940) by Aubrey Clayton, ["Think Python"](https://allendowney.github.io/ThinkPython/) by Allen Downey, and ["Think Bayes"](https://allendowney.github.io/ThinkBayes2/) by Allen Downey. Then I spent hours, days, and months practicing basic data management techniques using pandas and polars, working through [Professor Allen Downey's Bayesian statistics exercises on Github](https://github.com/AllenDowney/ThinkBayes2), and watching [Aubrey Clayton's excellent lecture series on Bayesian probability](https://www.youtube.com/watch?v=rfKS69cIwHc&list=PL9v9IXDsJkktefQzX39wC2YG07vw7DsQ_).

My goal was to build a framework that provides the context and intelligence that was missing from that Excel spreadsheet. A system that could answer the questions those security leaders were asking: Which vulnerabilities are actually exploitable in specific environment? What is the real-world probability of exploitation? How do security controls affect the risk? Where should limited resources be focused for maximum impact?

The result is a framework that goes beyond CVSS scores and severity labels. It combines Bayesian risk assessment, kill-chain probability modeling, and environmental context to answer the questions security leaders actually ask. Instead of calling them with a list of CVEs, I can now say: "These three vulnerabilities have a combined 85% exploitation probability in your environment, they are part of an attack chain that could lead to data exfiltration, and here is exactly why they matter more than the other 500 vulnerabilities in your backlog."

## Project Overview

The framework evaluates exploitation probability using Bayesian statistics, models complete attack chains through multi-component applications, and provides prioritized recommendations based on your specific environment.

The main goal: answer the question "Which vulnerabilities actually matter in my specific environment?" by combining multiple data sources with environmental context.

## Core Philosophy

Traditional vulnerability scanners operate on a simple principle: scan, report severity, and let security teams figure out priorities. This approach treats vulnerability metrics as absolute truths rather than what they actually are - signals to be interpreted and inferred from.

**The fundamental insight:** CVSS scores, CVSS vectors, EPSS predictions, severity labels, and other standardized metrics are not final answers. They are starting points or signals that require interpretation within specific environmental contexts. A CVSS score of 9.8 is not an objective measure of risk - it is a signal about the vulnerability's theoretical maximum impact under worst-case conditions. Similarly, an EPSS score of 85% is not a guarantee of exploitation - it is a probabilistic signal based on historical patterns and threat intelligence.

This distinction matters because it changes how I approach vulnerability assessment:

1. **Signals require interpretation** - A vulnerability with CVSS 9.8 might be less dangerous than one with CVSS 7.5 if the former has no known exploits and sits on an internal system, while the latter is actively exploited and exposed to the internet. Or what about multiple vulnerabilities with CVSS less than 7.5 but are actively exploited and exposed to the internet? The CVSS scores are signals - the actual risk requires inference from environmental context.

2. **Context transforms signals into actionable intelligence** - The same vulnerability poses different risks depending on the environment, security controls, network architecture, and business criticality. I do not just collect these signals - I use them as inputs for probabilistic inference (let's not shy away from this scary word).

3. **Attack chains reveal signal relationships** - Attackers don't exploit single vulnerabilities in isolation; they chain multiple weaknesses to achieve their objectives. Understanding how signals relate to each other in attack sequences provides deeper insight than treating them independently.

The proposed framework treats all vulnerability data as signals to work with, interpret, and infer from. It combines multiple signals through Bayesian inference to produce probabilistic (sort of - because I do not assess losses) risk assessments that reflect real-world conditions, not just theoretical severity scores.

The framework addresses these principles through three main pillars:

### 1. Bayesian Risk Assessment

Instead of relying solely on CVSS scores, I use Bayesian inference to calculate exploitation probability. This approach combines:

- **EPSS (Exploit Prediction Scoring System)** as the prior probability - representing real-world exploitation likelihood based on threat intelligence
- **EPSS Trajectory Analysis** (v2.2) - tracks exploitation trends over 90 days to identify rising threats and validate patch adoption effectiveness
- **Environmental factors** as evidence that updates the probability - including security controls, network exposure, asset criticality
- **Uncertainty quantification** - providing 95% credible intervals to express confidence in risk estimates - I am 95% confident that the true exploitation probability lies between ci_low and ci_high. It directly expresses the degree of a given belief about this parameter given the available evidence. (I cannot believe I was able to write it down myself)

**How credible intervals quantify uncertainty:**

The 95% credible interval expresses confidence in the risk estimate. Wider intervals indicate higher uncertainty, which occurs when:

1. **EPSS score is less reliable** (low percentile) - If a vulnerability is in the 20th percentile of EPSS scores, I am less confident in the prediction than if it is in the 95th percentile
2. **Limited evidence** (few contributing factors) - More evidence from security controls, threat indicators, and CVSS components reduces uncertainty
3. **Probability near 50%** (maximum entropy) - When exploitation probability is around 50%, I am maximally uncertain - when it is 5% or 95%, I am more certain

The framework uses a beta distribution approximation to calculate these intervals, combining three uncertainty factors:
- **Percentile factor**: Higher EPSS percentile = more confidence (lower uncertainty)
- **Evidence factor**: More contributing factors = more confidence (each factor reduces uncertainty by ~5%)
- **Entropy factor**: Probabilities near 0.5 have maximum uncertainty, near 0 or 1 have minimum uncertainty

Typical uncertainty ranges from 5% (high confidence with strong evidence) to 30% (low confidence with weak evidence). This provides transparency about the confidence in each assessment, helping security teams understand not just the risk level, but how certain I am about that assessment.

**Key innovation: Exploitability gating**

Through numerous experiments and computations I discovered (quite logically) that amplification factors (like internet exposure) should only apply when exploitation is actually plausible. For example, an internet-facing service with a vulnerability that has 0.1% EPSS and no known exploits should not be amplified to high risk just because it is exposed - there is no evidence anyone can exploit it. My gating mechanism ensures amplification only applies when EPSS >= 5% or known exploits exist.

**EPSS Trajectory Analysis (v2.2)**

Building on the Work-Averse Cyberattacker Model (Allodi et al., 2021), which found that attackers face high initial costs for exploit development leading to selective exploitation and weaponization lag, I implemented EPSS trajectory tracking to capture exploitation trends over time:

- **Rising EPSS (↑)**: Exploitation increasing → 1.2x risk amplification (active campaigns or new exploits)
- **Declining EPSS (↓)**: Exploitation decreasing → validates patch adoption effectiveness
- **Stable EPSS (→)**: Sustained threat level → consistent exploitation probability

This replaces the previous incorrect approach of using static patch availability factors that decreased risk over time. EPSS trajectory naturally captures patch adoption through observed exploitation patterns - as systems patch, exploitation probability declines in the real world, which EPSS reflects.

### 2. Kill-Chain Probability Analysis

Traditional vulnerability assessments treat each vulnerability independently. However, real attacks follow a kill-chain pattern: Initial Access -> Execution -> Lateral Movement -> Objective Achievement. (Actually a shortened version of the kill-chain, but it is good enough and serves the purpose)

My kill-chain analysis:

- **Models multi-component applications** - Analyzes complete systems (e.g., 7-component financial platform) rather than isolated services
- **Calculates stage-by-stage probabilities** - Each stage has base probability and conditional probability given previous stage success
- **Incorporates security controls** - Network segmentation, EDR/XDR, Docker hardening, SIEM monitoring all reduce stage probabilities
- **Identifies bottlenecks** - Shows which stage is hardest to breach, guiding defensive priorities

Attackers need to succeed at each stage sequentially. If initial access is very difficult (1% probability), it does not matter if lateral movement would be easy (50% probability) - the overall chain probability is still very low (0.5%). This helps prioritize defenses at the most critical stages.

**Security control penalty modeling**

A crucial aspect of my kill-chain analysis is that I do not just model protective controls - I also penalize bad practices. For example:

- Good Docker practices (non-root, read-only, seccomp): **0.3 LR (Likelihood Ratio)** (70% reduction in execution risk)
- Poor Docker practices (root containers, no hardening): **1.3 LR** (30% increase in execution risk)
- Network segmentation: **0.3 LR** (70% reduction in lateral movement)
- Flat network: **1.3 LR** (30% increase in lateral movement)

This ensures the model accurately reflects reality - in my view absence of security controls is not neutral, it actively increases probability of compromise and suffering from losses.

### 3. Adaptive Scenario Generation

To demonstrate the framework's capabilities across different environments, I worked out a generator which provides an adaptive scenario at each pipeline run that creates realistic IT environments based on:

- **Organization size** (small, mid, large) - affects number of services and complexity
- **Industry** (financial services, consulting, e-commerce) - determines application architecture and security requirements
- **Environment type** (dev, test, prod) - influences security control deployment
- **Security maturity** (initial, developing, defined, managed, optimizing) - determines which controls are active

**Probabilistic Control Types System (v2.0):**

The framework now uses a sophisticated probabilistic model for security controls, moving beyond simple boolean (present/absent) to model actual implementation quality:

**8 Control Types with Varying Effectiveness:**
- **MFA:** None, SMS (LR=0.35), Authenticator App (LR=0.15), Push Notification (LR=0.15), FIDO2 (LR=0.05)
- **Firewall:** None, Basic (LR=0.7), Stateful (LR=0.5), Next-Gen (LR=0.4), NGFW Advanced (LR=0.3)
- **WAF:** None, Basic (LR=0.6), Managed (LR=0.4), OWASP CRS (LR=0.3), Custom Tuned (LR=0.25)
- **Endpoint:** None, Traditional AV (LR=0.7), Basic EDR (LR=0.5), Advanced EDR (LR=0.4), XDR (LR=0.3)
- **Segmentation:** None, Basic VLAN (LR=0.7), VLAN+ACL (LR=0.5), Micro-Seg (LR=0.3), Zero Trust (LR=0.2)
- **IDS/IPS:** None, IDS Only (LR=0.8), IPS Signature (LR=0.5), IPS Behavioral (LR=0.4), IPS ML (LR=0.35)
- **SIEM:** None, Log Collection (LR=0.8), Basic Correlation (LR=0.6), Advanced Analytics (LR=0.5), Threat Hunting (LR=0.4)
- **Patch Mgmt:** None, Reactive (LR=0.9), Quarterly (LR=0.7), Monthly (LR=0.4), Weekly (LR=0.3), Automated (LR=0.2)

**Realistic Generation Example (Optimizing Financial Services):**
- MFA: 60% FIDO2, 30% Push Notification, 10% Authenticator App
- Firewall: 60% NGFW, 20% NGFW Advanced, 20% Stateful
- WAF: 50% OWASP CRS, 20% Managed, 20% Basic, 10% Custom Tuned

This probabilistic approach creates realistic variability - even mature organizations have some legacy systems. The generator uses industry modifiers (e.g., financial services 1.8x more likely to have FIDO2) and exposure modifiers (internet-facing services get stronger controls) to ensure realistic patterns.

**Validation Results:** Pipeline testing with large financial services organization (optimizing maturity) showed:
- Average exploitation probability: 0.34%
- 84.2% of vulnerabilities assessed as negligible after control analysis
- Only 6.1% requiring immediate action (Critical + High)
- Strong controls reduced actionable vulnerabilities from 2,493 to 392 (84% reduction)

See `docs/CONTROL_TYPES_VALIDATION_RESULTS.md` for detailed validation analysis and `docs/SECURITY_CONTROLS_GUIDE.md` for complete control type documentation.

## Technical Implementation

### Data Sources and Enrichment

The framework integrates multiple authoritative data sources:

1. **CVE v5 data** - Vulnerability descriptions, CVSS vectors, CWE classifications
2. **EPSS scores** - Monthly exploitation probability predictions from FIRST.org
3. **KEV catalog** - Known Exploited Vulnerabilities from CISA
4. **CVSS-BT** - CVSS with Base + Threat metrics including exploit availability indicators (Metasploit, ExploitDB, Nuclei, GitHub PoCs)
5. **CWE database** - Weakness classifications with detailed descriptions

**Enrichment pipeline:**

```
Raw CVE data -> EPSS enrichment -> KEV enrichment -> CWE enrichment -> CVSS vector parsing -> Bayesian risk calculation
```

Each enrichment step adds context that improves risk assessment accuracy. For example, knowing a vulnerability is in the KEV catalog immediately elevates its priority regardless of CVSS score.

### Bayesian Risk Calculation

The mathematical foundation is straightforward but powerful:

```
Posterior Odds = Prior Odds x LR1 x LR2 x ... x LRn
```

Where:
- **Prior Odds** = EPSS score converted to odds using the formula: `odds = probability / (1 - probability)`. For example, EPSS of 8.3% becomes odds of 0.083 / (1 - 0.083) = 0.0905. I decided to use [odds space](https://www.youtube.com/watch?v=lG4VkPoG3ko) because it simplifies combining multiple pieces of evidence - instead of applying Bayes' theorem repeatedly, I am simply multiplying likelihood ratios and convert back to probability at the end.
- **LR (Likelihood Ratio)** = Factor representing evidence strength
  - LR < 1.0: Evidence reduces exploitation probability (protective controls)
  - LR = 1.0: No effect (baseline)
  - LR > 1.0: Evidence increases exploitation probability (risk factors)

**Example calculation:**

Consider a vulnerability with:
- EPSS: 8.3% (prior probability)
- Internet-facing service (LR = 2.5)
- No security controls (LR = 1.0)
- Critical asset (LR = 1.5)
- Known exploit exists (LR = 2.0)

```
Prior odds = 0.083 / (1 - 0.083) = 0.0905
Posterior odds = 0.0905 x 2.5 x 1.0 x 1.5 x 2.0 = 0.679
Posterior probability = 0.679 / (1 + 0.679) = 40.4%
```

This vulnerability has 40.4% exploitation probability - clearly high risk requiring immediate attention.

### Kill-Chain Probability Calculation

Each stage in the kill-chain has:

1. **Base probability** - Likelihood of stage success without considering previous stages
2. **Conditional probability** - Likelihood given previous stage succeeded
3. **Contributing factors** - Security controls that modify the probability

**Stage calculation example (Lateral Movement):**

```
Base probability = 0.002 (0.2% baseline - probability attacker attempts lateral movement)

Apply security controls (each control reduces the probability):
- Network segmentation: 0.002 x 0.3 = 0.0006 (70% reduction)
- Docker network isolation: 0.0006 x 0.5 = 0.0003 (50% reduction)
- EDR/XDR: 0.0003 x 0.5 = 0.00015 (50% reduction)
- SIEM: 0.00015 x 0.6 = 0.00009 (40% reduction)

Final stage probability = 0.00009 (0.009%)

This means: IF an attacker successfully executes code (previous stage), 
there's a 0.009% chance they succeed at lateral movement.
```

The overall kill-chain probability is the product of all stage probabilities:

```
P(success) = P(initial_access) x P(execution|initial_access) x P(lateral|execution) x P(objective|lateral)
```

### Docker Security Assessment

Docker security is evaluated based on container configurations and the Linux kernel security features they leverage:

**Docker-Specific Configurations (protective):**
- [Non-root user execution](https://docs.docker.com/engine/security/#user-namespaces) (USER directive)
- [Read-only root filesystem](https://docs.docker.com/engine/reference/run/#security-configuration) (--read-only flag)
- [Capabilities dropped](https://docs.docker.com/engine/security/#linux-kernel-capabilities) (--cap-drop)
- [No privileged mode](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (--privileged=false)
- [Resource limits](https://docs.docker.com/config/containers/resource_constraints/) (CPU, memory constraints)

**Linux Kernel Security Features (leveraged by Docker):**
- [Seccomp](https://docs.docker.com/engine/security/seccomp/) profiles (system call filtering)
- [AppArmor](https://docs.docker.com/engine/security/apparmor/)/[SELinux](https://docs.docker.com/engine/security/selinux/) profiles (Mandatory Access Control)
- [Namespace isolation](https://docs.docker.com/engine/security/#kernel-namespaces)
- [Cgroup restrictions](https://docs.docker.com/engine/security/#control-groups)

**Network Security (Docker/Orchestrator level):**
- [Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) configured
- Network segmentation
- [No host networking](https://docs.docker.com/network/drivers/host/) (--net=host disabled)

**Poor practices (penalized):**
- Root user execution
- Writable root filesystem
- No seccomp profiles applied
- Privileged mode enabled
- Host networking enabled
- No capability restrictions
- No resource limits

The assessment checks container configurations and applies appropriate likelihood ratios. This ensures the kill-chain analysis accurately reflects the security posture of containerized environments, distinguishing between Docker-specific settings and the underlying Linux kernel security mechanisms that Docker utilizes.

## Analysis Flow

The complete analysis follows this workflow:

```
1. Environment Generation
   |
   v
   - Generate realistic IT environment based on parameters
   - Select services, assign roles, configure network topology
   - Deploy security controls based on maturity level
   
2. Docker Image Scanning
   |
   v
   - Scan selected Docker images using Grype
   - Extract vulnerability data (CVE IDs, CVSS scores, descriptions)
   - Identify affected packages and versions
   
3. Data Enrichment
   |
   v
   - Enrich with EPSS scores (exploitation probability)
   - Add KEV status (known exploited)
   - Fetch CWE classifications
   - Parse CVSS vectors for detailed analysis
   
4. Bayesian Risk Assessment
   |
   v
   - Calculate exploitation probability for each vulnerability
   - Apply environmental context (exposure, controls, criticality)
   - Implement exploitability gating
   - Quantify uncertainty with credible intervals
   
5. Kill-Chain Analysis
   |
   v
   - Build multi-component application model
   - Calculate stage-by-stage probabilities
   - Apply security control effects
   - Identify bottlenecks and critical paths
   
6. Attack Scenario Analysis
   |
   v
   - Build attack graph from vulnerabilities
   - Identify potential attack paths
   - Calculate path probabilities
   - Prioritize based on likelihood and impact
   
7. Report Generation
   |
   v
   - Executive summary with risk distribution
   - Kill-chain probability analysis
   - Risk-based prioritization
   - Remediation roadmap with effort estimates
   - Team-based risk heatmap
```

Each step builds on the previous one, progressively adding context and insight until arriving at actionable recommendations.

## Comparative Examples

To demonstrate the framework's effectiveness, I generated three scenarios with different security maturity levels. These examples show how the same vulnerability landscape is assessed differently based on environmental context.

### Scenario Comparison: The Impact of Security Maturity

| Metric | Poor Security | Average Security | Good Security |
|--------|---------------|------------------|---------------|
| **Organization** | Small on-line store | Mid consulting firm | Mid financial services |
| **Security Maturity** | Initial | Defined | Managed |
| **Active Controls** | 5 controls | 8 controls | 12 controls |
| **Total Vulnerabilities** | 1,363 | 6,806 | 3,783 |
| **Critical (Bayesian)** | 18 (1.3%) | 23 (0.3%) | 18 (0.5%) |
| **Actionable Vulns** | 41 | 134 | 75 |
| **Lateral Movement** | N/A | 5.2% | 3.1% |
| **Remediation Effort** | 101 hours | 236 hours | 146 hours |

**Key observations:**

1. **More vulnerabilities ≠ higher risk** - Average security has 6,806 vulnerabilities but only 0.3% are critical, vs poor security with 1,363 vulnerabilities but 1.3% critical. Security controls reduce exploitation probability.

2. **Controls compound** - Good security (12 controls) achieves 40% lower lateral movement probability than average security (8 controls).

3. **Remediation efficiency** - Bayesian assessment identifies which vulnerabilities actually matter in specific contexts.

### Example: How Security Controls Transform Risk Assessment

Example: how the same high-EPSS vulnerability is assessed across security maturity levels:

**CVE-2023-44487 (HTTP/2 Rapid Reset) - EPSS: 94.40%**

This vulnerability is actively mass-exploited in the wild, representing a realistic high-threat scenario.

**Vulnerability-Level Assessment:**

- **Poor Security** (internet-facing, no WAF, no EDR, poor Docker):
  - Exploitation probability: **98.6%** [93.3%-100.0%]
  - Classification: **CRITICAL**
  - Reasoning: High EPSS + internet exposure + no protective controls + poor Docker practices

- **Average Security** (internal, EDR, network segmentation, good Docker):
  - Exploitation probability: **78.3%** [69.9%-86.7%]
  - Classification: **CRITICAL**
  - Reasoning: High EPSS reduced by EDR (40%) and segmentation (70%), but still very high

- **Good Security** (internet-facing, WAF, EDR, SIEM, network segmentation, good Docker):
  - Exploitation probability: **82.8%** [76.0%-89.6%]
  - Classification: **CRITICAL**
  - Reasoning: High EPSS + internet exposure mitigated by comprehensive controls (WAF 70%, EDR 60%, SIEM 30%)

**Initial Observation**: "All scenarios are still CRITICAL - do security controls even matter?"

**Kill-Chain Reality (Defense in Depth):**

Even if the vulnerability is exploited, the attacker must succeed through the entire kill-chain:

**Poor Security Kill-Chain:**
- Initial Access (vulnerability exploited): 98.6%
- Execution (root containers, no EDR): 80% conditional
- Lateral Movement (flat network): 60% conditional
- Objective Achievement (no DLP, no SIEM): 90% conditional
- **Overall attack success**: 98.6% x 80% x 60% x 90% = **42.6%**

**Good Security Kill-Chain:**
- Initial Access (vulnerability exploited): 82.8%
- Execution (Docker hardening 70%, EDR 60%, WAF 40%): 5.8% conditional
- Lateral Movement (segmentation 70%, Docker isolation 50%, EDR 50%, SIEM 40%): 3.1% conditional
- Objective Achievement (SIEM 30%, encryption 50%, DLP 70%): 63% conditional
- **Overall attack success**: 82.8% x 5.8% x 3.1% x 63% = **0.094%**

**Defense in Depth Works:**

Vulnerability exploitation probability decreased from 98.6% to 82.8% (16% reduction), but **overall attack success probability** decreased from 42.6% to 0.094% - a **453x reduction**!

Key points:
1. Vulnerability-level probability is just the first stage
2. Security controls provide layered defense - even if initial access succeeds, subsequent stages become extremely difficult
3. Good security contains breaches - the difference between 42.6% and 0.094% is the difference between likely compromise and negligible risk
4. All scenarios should patch immediately - but good security provides time to respond and limits damage

### Kill-Chain Analysis Comparison

**Poor Security (Initial Maturity):**
- No kill-chain analysis available (insufficient security controls for meaningful modeling)
- Focus on individual vulnerability remediation
- High risk from poor Docker practices

**Average Security (Defined Maturity):**
```
Initial Access: 1.0% base probability (strong perimeter)
Execution: 5.8% conditional (IF initial access succeeds)
Lateral Movement: 5.2% conditional (IF execution succeeds)
Objective Achievement: 90.0% conditional (IF lateral movement succeeds)

Overall kill-chain probability: 1.0% x 5.8% x 5.2% x 90.0% = 0.00027% (approximately 0.0%)
Threat level: Negligible
```

**Good Security (Managed Maturity):**
```
Initial Access: 1.0% base probability (strong perimeter)
Execution: 5.8% conditional (IF initial access succeeds)
Lateral Movement: 3.1% conditional (IF execution succeeds) - 40% better than average
Objective Achievement: 63.0% conditional (IF lateral movement succeeds) - 30% better than average

Overall kill-chain probability: 1.0% x 5.8% x 3.1% x 63.0% = 0.00011% (approximately 0.0%)
Threat level: Negligible
```

**Why both show 0.0% overall probability:**

Both scenarios round to 0.0% because the overall probability is the product of all sequential stages. When you multiply very small probabilities together, the result becomes extremely small:

- Average: 0.01 x 0.058 x 0.052 x 0.90 = 0.0000027 (0.00027%)
- Good: 0.01 x 0.058 x 0.031 x 0.63 = 0.0000011 (0.00011%)

Both are effectively zero when rounded to one decimal place, but the good security scenario is actually **2.5x more secure** (0.00011% vs 0.00027%).

**Critical insight:**

The overall probability is dominated by the **bottleneck stage** - initial access at 1.0%. Even if an attacker gets past the perimeter (1% chance), they still face multiple hurdles:

- Average security: Must succeed at 5.8% x 5.2% x 90.0% = 0.027% of subsequent stages
- Good security: Must succeed at 5.8% x 3.1% x 63.0% = 0.011% of subsequent stages

Conditional probabilities reveal the real differences:
1. Lateral Movement: Good security is 40% better (3.1% vs 5.2%)
2. Objective Achievement: Good security is 30% better (63.0% vs 90.0%)
3. Layered controls at each stage provide additional protection

Good security provides:
- 2.5x lower attack success probability
- 40% better lateral movement defense (critical for containing breaches)
- 30% better objective achievement defense (reduces impact if other stages fail)

**Why Security Controls Matter Despite Low Probabilities:**

The negligible overall probability (0.00027% or 0.00011%) is not an argument against security controls - it is evidence that they work.

Key reasons to invest in controls:

1. **Perimeter defenses can fail** - Zero-day vulnerabilities, phishing, insider threats, supply chain attacks, and misconfigurations can bypass initial defenses. When this happens, the difference between 5.2% and 3.1% lateral movement probability becomes the difference between a contained incident and a catastrophic breach.

2. **Defense in depth is insurance** - Good security provides 2.5x better protection when the perimeter is breached, meaning faster detection, smaller blast radius, and lower recovery costs.

3. **Impact matters** - Even 0.00011% probability matters when the impact is $5.9M (average financial services breach cost). The actual loss in a successful attack is the full amount, not the expected value.

4. **Real attacks target weak controls** - Sophisticated attackers specifically target environments with weak controls. Automated attacks scan for vulnerable configurations. The 40% improvement in lateral movement defense directly translates to faster detection and reduced business disruption.

5. **Compliance and business value** - Regulatory compliance (PCI-DSS, HIPAA, GDPR, SOC 2), legal liability reduction, customer trust, and cyber insurance eligibility all require security controls.

6. **Attackers need to succeed once, defenders must succeed every time** - Multiple layers of protection provide resilience. If one control fails, others compensate.

Moving from average (8 controls) to good security (12 controls) provides:
- 2.5x lower attack success probability
- 40% better breach containment
- 30% better data protection
- Measurably better defense at every stage

## Methodological Decisions

### Bayesian vs Simple Scoring

Traditional scoring uses simple multiplication: `Risk = CVSS x Exposure x Criticality`

Problems:
- No probabilistic interpretation (what does a score of 42.5 mean?)
- Arbitrary weights (why 2.5 for internet exposure instead of 2.0 or 3.0?)
- No uncertainty quantification

Bayesian inference provides:
- Probabilistic output ("40.4% exploitation probability" has clear meaning)
- Principled evidence combination (likelihood ratios have theoretical justification)
- Uncertainty quantification (credible intervals express confidence)

### Penalty Modeling for Bad Practices

Absence of security controls is not neutral - it actively increases risk:
- Running containers as root increases attackers' success probability
- Flat networks enable lateral movement
- No patching extends exposure windows

Penalizing bad practices (LR > 1.0) ensures the model accurately reflects that poor security posture is actively harmful, not neutral.

## Limitations and Future Work

### Current Limitations

1. **EPSS dependency** - Currently, the proposed Bayesian approach relies on EPSS scores, which are only available for a subset of CVEs. Vulnerabilities without EPSS scores default to conservative estimates.

2. **Static analysis** - The framework analyzes a snapshot of the environment. It does not model dynamic factors like patch deployment speed or incident response effectiveness.

3. **Kill-chain simplification** - Real attacks are more complex than my four-stage model. I do not model persistence, privilege escalation as separate stages, or alternative attack paths.

4. **Control effectiveness assumptions** - My likelihood ratios for security controls are based on industry research and expert judgment, not empirical measurements from the specific environment.

### Future Enhancements

1. **Machine learning integration** - Use historical incident data to learn environment-specific likelihood ratios instead of using generic values.

2. **Continuous monitoring** - Extend the framework to track risk over time, showing how it changes as vulnerabilities are patched and new ones emerge.

3. **Attack simulation** - Add capability to simulate specific attack scenarios and measure defensive effectiveness.

4. **Integration with SIEM/EDR** - Pull actual security events to validate model predictions and refine probability estimates.

5. **Compliance mapping** - Map vulnerabilities to compliance requirements (PCI-DSS, HIPAA, GDPR) to support regulatory reporting.

## Conclusion

The framework combines Bayesian risk assessment, kill-chain probability modeling, and adaptive scenario generation to provide context-aware insights for efficient resource allocation.

Key innovations:
1. Probabilistic risk assessment with mathematical rigor and uncertainty quantification
2. Kill-chain modeling that reflects how attacks progress through systems
3. Security control penalty modeling that represents the cost of poor practices
4. Multi-scenario validation across different contexts

Results show that comprehensive security (12+ controls) achieves:
- 40% lower lateral movement probability vs basic security (8 controls)
- 47x reduction in exploitation probability for moderate-EPSS vulnerabilities
- 453x reduction in end-to-end attack success for high-EPSS vulnerabilities

The framework answers: which vulnerabilities to patch first, which security controls to deploy, and where to focus defensive resources for maximum impact.

## Technical Documentation

📚 **[Complete Documentation Hub](docs/index.md)** - Comprehensive documentation index with role-based navigation paths

### Core Documentation

- **[Technical Setup & Installation Guide](docs/TECHNICAL_SETUP.md)** - How to set it up, quick start, project structure, usage examples
- **[Bayesian Risk Assessment Methodology](docs/BAYESIAN_RISK_ASSESSMENT.md)** - Detailed explanation of Bayesian approach, likelihood ratios, uncertainty quantification, and mathematical foundations (includes consolidated mathematical reference as Appendix A4)
- **[Kill-Chain Probability Analysis](docs/EXTENDED_KILL_CHAIN_METHOD.md)** - Multi-stage attack modeling methodology and application templates
- **[Security Controls Configuration Guide](docs/SECURITY_CONTROLS_GUIDE.md)** - How to configure and customize security controls and likelihood ratios
- **[Pipeline Components](docs/PIPELINE_COMPONENTS.md)** - Detailed pipeline architecture and component documentation

### Examples & Comparisons

- **[Demo Report](docs/DEMO_REPORT.md)** - Example vulnerability assessment report with EPSS trajectory analysis (v2.2)
- **[Scenario Comparison](docs/SCENARIO_COMPARISON.md)** - Comparative analysis across different security maturity levels

## References and Data Sources

- **EPSS (Exploit Prediction Scoring System)**: https://www.first.org/epss/
- **CISA KEV Catalog**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **CVE Program**: https://www.cve.org/
- **CVSS-BT (CVSS with Base + Threat Metrics)**: https://github.com/t0sche/cvss-bt
- **CWE (Common Weakness Enumeration)**: https://cwe.mitre.org/
- **CVSS (Common Vulnerability Scoring System)**: https://www.first.org/cvss/
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **Verizon DBIR (Data Breach Investigations Report)**: https://www.verizon.com/business/resources/reports/dbir/
- **IBM Cost of Data Breach Report**: https://www.ibm.com/reports/data-breach

## Getting Started

Want to try it? Check the Technical Setup Guide (docs/TECHNICAL_SETUP.md) for installation and quick start instructions.

---

This document gives you comprehensive overview of the CVEs Analytics framework philosophy and methodology. For detailed technical implementation, check the documentation links above.
