# CVEs Analytics: Comprehensive Vulnerability Assessment Framework

## Introduction

A few years ago, I worked at a company where I experienced firsthand the absurdity of (so called)traditional vulnerability management. One day, they sat me down at a desk, handed me an Excel spreadsheet with a list of CRITICAL, HIGH, MEDIUM, and LOW vulnerabilities across servers in different locations, and told me to call local security leaders asking why they hadn't patched their systems yet.

The whole situation was ridiculous. I had no context about which vulnerabilities actually mattered. I didn't know if a CRITICAL vulnerability on an internal development server was more urgent than a MEDIUM one on an internet-facing production system. I had no information about whether security controls were in place that might mitigate the risks. I couldn't tell security leaders anything useful beyond "this CVE has a high CVSS score" - which they already knew from their own scanners.

The conversations were predictably frustrating. Security leaders would ask reasonable questions: "Is this actually exploitable in our environment?" "Do we have compensating controls?" "Is this being actively exploited in the wild?" And I had no answers. The Excel spreadsheet only had CVE IDs, CVSS scores, and server names. No context, no prioritization beyond severity labels, no actionable intelligence.

This experience highlighted a fundamental problem in how many organizations approach vulnerability management. We generate massive lists of vulnerabilities, categorize them by CVSS scores, and then expect security teams to somehow figure out what to fix first. It's inefficient, demotivating, and often leads to the wrong priorities. Critical vulnerabilities on isolated systems get immediate attention while actively exploited vulnerabilities on exposed systems wait in the queue because they're labeled "MEDIUM."

This project was born from that frustration, but also from reading great books about probability, quantitative risk, and Bayesian calculus - "Superforecasting" by Philip Tetlock and Dan Gardner, "How to Measure Anything in Cybersecurity Risk" by Douglas Hubbard and Richard Seiersen, "Metrics Manifesto" by Richard Seiersen and Doug Hubbard, "Bernoulli's Fallacy" by Aubrey Clayton, "Think Python" by Allen Downey, and "Think Bayes" by Allen Downey. Then I spent hours, days, and months practicing basic data management techniques using pandas and polars, working through [Professor Allen Downey's Bayesian statistics exercises on Github](https://github.com/AllenDowney/ThinkBayes2), and watching [Aubrey Clayton's excellent lecture series on Bayesian probability](https://www.youtube.com/watch?v=rfKS69cIwHc&list=PL9v9IXDsJkktefQzX39wC2YG07vw7DsQ_).

My goal was to build a framework that provides the context and intelligence that was missing from that Excel spreadsheet. A system that could answer the questions those security leaders were asking: Which vulnerabilities are actually exploitable in specific environment? What is the real-world probability of exploitation? How do security controls affect the risk? Where should limited resources be focused for maximum impact?

The result is a comprehensive vulnerability assessment framework that goes far beyond CVSS scores and severity labels. It combines Bayesian risk assessment, kill-chain probability modeling, and environmental context to provide actionable, prioritized recommendations. Instead of calling security leaders with a list of CVEs, I can now tell them: "These three vulnerabilities have a combined 85% exploitation probability in your environment, they are part of an attack chain that could lead to data exfiltration, and here is exactly why they matter more than the other 500 vulnerabilities in your backlog."

That is the kind of intelligence that actually helps security teams do their jobs effectively.

## Project Overview

This project represents a comprehensive approach to vulnerability assessment that goes beyond traditional scanning methods. Instead of simply listing vulnerabilities by their CVSS scores, I developed a framework that evaluates real-world exploitation probability using Bayesian statistics, models complete attack chains through multi-component applications, and provides actionable, context-aware recommendations.

The main motivation behind this work was to address a critical gap in existing vulnerability management tools: they often produce overwhelming lists of vulnerabilities without proper risk context, leading to inefficient resource allocation and missed critical threats. This framework aims to answer the question: "Which vulnerabilities actually matter in my specific environment?"

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
- **Environmental factors** as evidence that updates the probability - including security controls, network exposure, asset criticality
- **Uncertainty quantification** - providing 95% credible intervals to express confidence in risk estimates - I am 95% confident that the true exploitation probability lies between ci_low and ci_high. It directly expresses the degree of a given belief about this parameter given the available evidence. (I cannot believe I was able to write it down myself)

**Why Bayesian approach?**

The Bayesian method allows us to start with a reasonable baseline (EPSS) and systematically update it based on specific environmental context. This is more principled than arbitrary multiplicative scoring and provides mathematical rigor to risk assessment.

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

### 2. Kill-Chain Probability Analysis

Traditional vulnerability assessments treat each vulnerability independently. However, real attacks follow a kill-chain pattern: Initial Access -> Execution -> Lateral Movement -> Objective Achievement. (Actually a shortened version of the kill-chain, but it is good enough and serves the purpose)

My kill-chain analysis:

- **Models multi-component applications** - Analyzes complete systems (e.g., 7-component financial platform) rather than isolated services
- **Calculates stage-by-stage probabilities** - Each stage has base probability and conditional probability given previous stage success
- **Incorporates security controls** - Network segmentation, EDR/XDR, Docker hardening, SIEM monitoring all reduce stage probabilities
- **Identifies bottlenecks** - Shows which stage is hardest to breach, guiding defensive priorities

**Why kill-chain modeling?**

Because this reflects how actual attacks work. An attacker needs to succeed at each stage sequentially. A complex attack is multi-staged. It is not like KABOOM, system is compromised! If initial access is very difficult (1% probability), it does not matter if lateral movement would be easy (50% probability) - the overall chain probability is still very low (0.5%). This helps prioritize defenses at the most critical stages.

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
4. **CWE database** - Weakness classifications with detailed descriptions

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
- **Prior Odds** = EPSS score converted to odds using the formula: `odds = probability / (1 - probability)`. For example, EPSS of 8.3% becomes odds of 0.083 / (1 - 0.083) = 0.0905. I decided to use odds space because it simplifies combining multiple pieces of evidence - instead of applying Bayes' theorem repeatedly, I am simply multiplying likelihood ratios and convert back to probability at the end.
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

1. **More vulnerabilities does not equal higher risk** - The average security scenario has 6,806 vulnerabilities but only 0.3% are critical after Bayesian assessment, compared to 1.3% in the poor security scenario with only 1,363 vulnerabilities. This demonstrates that security controls effectively reduce exploitation probability.

2. **Security controls compound** - The good security scenario with 12 controls achieves 40% lower lateral movement probability (3.1% vs 5.2%) compared to average security with 8 controls. This shows that comprehensive security provides non-linear benefits.

3. **Remediation efficiency** - Despite having more total vulnerabilities, the average and good security scenarios have more efficient remediation because Bayesian assessment correctly identifies which vulnerabilities actually matter in their specific contexts.

### Example: How Security Controls Transform Risk Assessment

To demonstrate the framework's effectiveness, consider how the same high-EPSS vulnerability is assessed differently across security maturity levels:

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

**Key Insight - Defense in Depth Works:**

Even though the vulnerability exploitation probability only decreased from 98.6% to 82.8% (16% reduction), the **overall attack success probability** decreased from 42.6% to 0.094% - a **453x reduction**!

This demonstrates that:
1. **Vulnerability-level probability is just the first stage** - it's not the whole story
2. **Security controls provide layered defense** - even if initial access succeeds, subsequent stages become extremely difficult
3. **Good security contains breaches** - the difference between 42.6% and 0.094% is the difference between likely compromise and negligible risk
4. **All scenarios should patch immediately** - but good security provides critical time to respond and limits damage if exploitation occurs before patching

The framework correctly identifies the vulnerability as CRITICAL in all cases (patch immediately), but also shows that comprehensive security controls reduce the probability of a successful end-to-end attack by 453 times, demonstrating the real value of defense in depth.

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

**The critical insight:**

The overall probability is dominated by the **bottleneck stage** - initial access at 1.0%. Even if an attacker gets past the perimeter (1% chance), they still face multiple hurdles:

- Average security: Must succeed at 5.8% x 5.2% x 90.0% = 0.027% of subsequent stages
- Good security: Must succeed at 5.8% x 3.1% x 63.0% = 0.011% of subsequent stages

The **conditional probabilities reveal the real differences**:

1. **Lateral Movement**: Good security is 40% better (3.1% vs 5.2%) - comprehensive controls compound
2. **Objective Achievement**: Good security is 30% better (63.0% vs 90.0%) - SIEM monitoring reduces data exfiltration risk
3. **Defense in depth works**: Even if initial access fails, layered controls at each stage provide additional protection

**Practical implications:**

While both environments have negligible overall risk, the good security scenario provides:
- **2.5 times lower attack success probability** in absolute terms
- **40% better lateral movement defense** - critical for containing breaches
- **30% better objective achievement defense** - reduces impact if all other stages fail

This demonstrates that security controls matter even when overall risk appears negligible - they provide defense in depth and reduce the probability of successful attacks at each stage.

**Addressing the "Why Bother?" Question:**

A critical reader might ask: "If the overall kill-chain probability is so negligible (0.00027% or 0.00011%), why bother investing in security controls at all?"

This is a critical question that deserves a proper answer:

**1. The Bottleneck Can Fail**

The 1.0% initial access probability assumes strong perimeter defenses are in place and working correctly. However:

- **Zero-day vulnerabilities** can bypass perimeter controls overnight (e.g., Log4Shell, Heartbleed)
- **Phishing and social engineering** don't respect technical perimeter defenses
- **Insider threats** start from inside the perimeter
- **Supply chain attacks** can compromise trusted vendors with legitimate access
- **Misconfiguration** can accidentally expose internal systems

When the perimeter fails - and it will fail (I just do not know when) - the difference between 5.2% and 3.1% lateral movement probability can become the difference between a contained incident and a catastrophic breach.

**2. Defense in Depth is Insurance**

Security controls are a bit like insurance policies - usually you never need them (or even forget where they are), but when you do, they are invaluable:

- **Average security**: If initial access succeeds (1% chance), attacker has 0.027% chance of completing the kill-chain
- **Good security**: If initial access succeeds (1% chance), attacker has 0.011% chance of completing the kill-chain

Good security provides **2.5 times better protection** when the perimeter is breached. In a real breach scenario, this could mean:
- Detecting the attack before data exfiltration (SIEM monitoring)
- Containing the attack to a single system (network segmentation)
- Preventing privilege escalation (Docker hardening)

**3. The Probability x Impact = Risk**

Even a 0.00011% probability matters when the impact is catastrophic:

- **Financial services breach**: Average cost $5.9 million (IBM 2023)
- **Healthcare data breach**: Average cost $10.9 million
- **Regulatory fines**: GDPR allows up to 4% of global revenue

Expected loss calculation:
- Average security: 0.00027% x $5.9M = $15.93 expected annual loss
- Good security: 0.00011% x $5.9M = $6.49 expected annual loss

The difference ($9.44 annually) might seem laughable, but over 10 years that is $94.40 in expected loss reduction (still laughable). More importantly, this is the average - the actual loss in a successful attack is the full $5.9M, not the expected value.

(If you flip a coin 1000 times betting $100 on heads, your expected value is $0 (50% win, 50% loss)
But in any single flip, you either win $100 or lose $100 - not $0)

**4. Real-World Attacks Don't Follow Perfect Probability**

Our model assumes attackers face each stage independently. In reality:

- **Sophisticated attackers** specifically target environments with weak controls, like wolves choose the weakest in the pack
- **Automated attacks** scan for vulnerable configurations (flat networks, poor Docker practices),
- **Ransomware** spreads rapidly in environments without segmentation,
- **APT groups** persist for months in environments under the SIEM radars

The 40% improvement in lateral movement defense (3.1% vs 5.2%) directly translates to:
- Faster detection and response
- Smaller blast radius
- Lower recovery costs
- Reduced business disruption

**5. Compliance and Due Diligence**

Beyond probability calculations, security controls provide tangible business value:

- **Regulatory compliance** - PCI-DSS, HIPAA, GDPR, SOC 2 requirements mandate specific controls
- **Legal liability reduction** - Demonstrable due diligence in the event of a breach reduces legal exposure
- **Customer trust** - Security certifications and audit readiness are competitive differentiators
- **Cyber insurance** - Eligibility requirements and premium reductions directly tied to control implementation

These controls significantly reduce compliance and operational costs during audits, regulatory reviews, and customer security assessments. The ROI from avoiding compliance violations or failed audits may exceed the cost of the controls themselves.

**6. The Asymmetry of Attack and Defense**

Attackers only need to succeed once. Defenders must succeed every time. The negligible overall probability reflects:

- **Strong defenses working as intended** - this is success, not irrelevance
- **Multiple layers of protection** - each layer reduces probability further
- **Resilience to single point of failure** - if one control fails, others compensate

**The Bottom Line:**

The negligible overall probability is not an argument against security controls - it is evidence that security controls work. The question is not "Why bother with security controls?" but rather "Can we afford to have weaker controls?" - like "do I need to keep paying those license fees?"

The comparison shows that moving from average (8 controls) to good security (12 controls) provides:
- 2.5x lower attack success probability
- 40% better breach containment
- 30% better data protection
- Measurably better defense at every stage

In cybersecurity, as I try to make the attackers life harder, the overall negligible probability shows I am on the right track - and the conditional probabilities show that additional controls make their life even harder.

## Methodological Decisions and Rationale

### Why Bayesian Instead of Simple Scoring?

Traditional vulnerability scoring often uses simple multiplication:

```
Risk = CVSS x Exposure x Criticality
```

This approach has several problems (like risk heatmaps):

1. **No probabilistic interpretation** - What does a score of 42.5 actually mean?
2. **Arbitrary weights** - Why multiply by 2.5 for internet exposure instead of 2.0 or 3.0?
3. **No uncertainty quantification** - How confident should one be in this assessment?

Bayesian inference solves these issues:

1. **Probabilistic output** - "40.4% exploitation probability" has clear meaning
2. **Principled evidence combination** - Likelihood ratios have theoretical justification
3. **Uncertainty quantification** - Credible intervals express confidence

### Why Kill-Chain Modeling?

Single-vulnerability risk assessment by large, misses the bigger picture. Attackers do not need to exploit every vulnerability to succeed - they need to succeed at each stage of the chosen (most promising) kill-chain. This has important implications:

1. **Bottleneck identification** - If initial access is very difficult (1%), improving lateral movement defenses from 5% to 3% has minimal impact on overall risk
2. **Resource allocation** - Focus defensive resources on the weakest link
3. **Realistic threat modeling** - Reflects how actual attacks progress

### Why Penalty Modeling for Bad Practices?

Initially, I chose to only model protective controls (LR < 1.0). This created an unrealistic baseline where absence of controls was treated as neutral. In reality:

- Running containers as root actively increases attackers' success probability
- Flat networks actively enable lateral movement
- No patching or long intervals between patches actively extends exposure windows

By penalizing bad practices (LR > 1.0), it is kind of like saying "if you do this, you are making it easier for attackers to succeed". This ensures the model accurately reflects that poor security posture is not neutral - IT IS actively harmful! (Do you really think that leaving your door unlocked is neutral? Can you convince your insurance company that it WAS neutral?)

### Why Multi-Scenario Analysis?

Demonstrating the framework across different security maturity levels serves several purposes:

1. **Validation** - Shows the model behaves sensibly across different contexts
2. **Benchmarking** - Organizations can compare their posture to industry standards
3. **ROI demonstration** - Quantifies the value of security investments (e.g., 40% reduction in lateral movement from comprehensive controls)

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

This framework represents a significant advancement over traditional vulnerability assessment approaches. By combining Bayesian risk assessment, kill-chain probability modeling, and adaptive scenario generation, it provides security teams with actionable, context-aware insights that enable efficient resource allocation and measurable risk reduction.

The key innovations are:

1. **Probabilistic risk assessment** with mathematical rigor and uncertainty quantification
2. **Kill-chain modeling** that reflects how real attacks progress through systems
3. **Security control penalty modeling** that accurately represents the cost of poor practices
4. **Multi-scenario validation** demonstrating the framework's effectiveness across different contexts

The comparative examples demonstrate that security controls work - they measurably reduce both exploitation probability and attack success rates. Organizations investing in comprehensive security (12+ controls) achieve:
- **40% lower lateral movement probability** compared to basic security (8 controls)
- **47x reduction in exploitation probability** for moderate-EPSS vulnerabilities (42.5% -> 0.9%)
- **453x reduction in end-to-end attack success** for high-EPSS vulnerabilities (42.6% -> 0.094%)

Most importantly, the framework provides clear, actionable recommendations: which vulnerabilities to patch first, which security controls to deploy, and where to focus defensive resources for maximum impact. This transforms vulnerability management from an overwhelming list of CVEs into a strategic, data-driven process.

## Technical Documentation

If you want to dive deeper into technical details, installation steps, and API documentation, here is where to look:

- **[Technical Setup & Installation Guide](docs/TECHNICAL_SETUP.md)** - How to set it up, quick start, project structure, usage examples
- **[Bayesian Risk Assessment Methodology](docs/BAYESIAN_RISK_ASSESSMENT.md)** - Detailed explanation of Bayesian approach, likelihood ratios, uncertainty quantification
- **[Kill-Chain Probability Analysis](docs/EXTENDED_KILL_CHAIN_METHOD.md)** - Multi-stage attack modeling methodology and application templates
- **[Mathematical Reference](docs/MATHEMATICAL_REFERENCE.md)** - Mathematical foundations and references for the probabilistic risk assessment
- **[Security Controls Configuration Guide](docs/SECURITY_CONTROLS_GUIDE.md)** - How to configure and customize security controls and likelihood ratios
- **[Scenario Comparison](docs/SCENARIO_COMPARISON.md)** - Comparative analysis across different security maturity levels
- **[Demo Report](docs/DEMO_REPORT.md)** - Example vulnerability assessment report with kill-chain analysis

## References and Data Sources

These are the data sources I used:

- **EPSS (Exploit Prediction Scoring System)**: https://www.first.org/epss/
- **CISA KEV Catalog**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **CVE Program**: https://www.cve.org/
- **CWE (Common Weakness Enumeration)**: https://cwe.mitre.org/
- **CVSS (Common Vulnerability Scoring System)**: https://www.first.org/cvss/
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **Verizon DBIR (Data Breach Investigations Report)**: https://www.verizon.com/business/resources/reports/dbir/
- **IBM Cost of Data Breach Report**: https://www.ibm.com/reports/data-breach

## Getting Started

Want to try it? Check the Technical Setup Guide (docs/TECHNICAL_SETUP.md) for installation and quick start instructions.

---

This document gives you comprehensive overview of the CVEs Analytics framework philosophy and methodology. For detailed technical implementation, check the documentation links above.
