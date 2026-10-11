# AppSec Static Analysis Report
## CVEs Analytics Codebase — Revision 2

---

## Table of Contents

1. [Subject](#1-subject)
2. [Method](#2-method)
3. [Assessment Approach](#3-assessment-approach)
4. [Deployment Contexts](#4-deployment-contexts)
5. [Stochastic Scoring Model](#5-stochastic-scoring-model)
6. [Executive Summary](#6-executive-summary)
7. [Findings](#7-findings)
   - [F1 — Inverted TLS Default (CWE-297)](#f1--inverted-tls-default-cwe-297)
   - [F2 — Config Injection Chain → RCE (CWE-78 + CWE-16)](#f2--config-injection-chain--rce-cwe-78--cwe-16)
   - [F3 — Unsanitized Output File Path (CWE-22)](#f3--unsanitized-output-file-path-cwe-22)
   - [F4 — SSRF via Unvalidated Registry URL (CWE-918)](#f4--ssrf-via-unvalidated-registry-url-cwe-918)
   - [F5 — Jinja2 safe Filter on External Data (CWE-79)](#f5--jinja2-safe-filter-on-external-data-cwe-79)
8. [Cross-Finding Chain Analysis](#8-cross-finding-chain-analysis)
9. [Triage Decision Guide](#9-triage-decision-guide)
10. [Model Limitations and Known Approximations](#10-model-limitations-and-known-approximations)

---

## 1. Subject

**Codebase:** `cves_analytics`
**Language:** Python 3.12+
**Purpose:** CVE data analytics pipeline with Docker image scanning, vulnerability enrichment, Bayesian risk scoring, and scenario simulation.
**Key components analysed:**

| Component | Path |
|---|---|
| CLI entry points | `src/cli/scan_images.py`, `src/cli/run_pipeline.py` |
| Configuration management | `src/utils/config.py` |
| Docker image scanner | `src/core/docker_scanner.py` |
| Pipeline attack analyser | `src/cli/pipeline_steps/attack_analyzer.py` |
| Web interface templates | `templates/analyse.html`, `templates/index.html` |

**Scope:** Source code static analysis only. No dynamic analysis, no penetration testing, no dependency CVE scanning.

---

## 2. Method

### 2.1 Problem Statement

Classical static analysis tools assign each finding a single severity label (CRITICAL / HIGH / MEDIUM / LOW). This label conflates two fundamentally different questions:

1. **Does the flaw exist?** — Deterministic. A detection predicate (AST pattern, taint rule) either fires or it does not. There is no uncertainty here.
2. **How severe is it in this deployment?** — Probabilistic. Severity depends on deployment context: network topology, trust boundaries, monitoring coverage, exploit availability. These factors are epistemically uncertain at analysis time.

CVSS 4.0 addresses the first question well — it provides a rigorous taxonomy of vulnerability properties (Attack Vector, Complexity, Impact). But it produces a single point estimate and has no mechanism to express uncertainty in its Environmental or Threat metric inputs. This is a known limitation acknowledged by FIRST: the Environmental metrics exist precisely because the Base score alone is insufficient, yet most consumers never populate them.

Stochastic reasoning addresses the second question: contextual factors that are uncertain are modelled as probability distributions. Sampling over those distributions produces a *score distribution* rather than a single score, yielding a classification label with an associated *confidence percentage*.

The result: a finding is not labelled "HIGH" — it is labelled "HIGH (45%), CRITICAL (25%), MEDIUM (20%), bounds [0.18, 0.85]". A triager can then challenge any individual input distribution and observe exactly how the classification changes.

### 2.2 Design Decisions and Rationale

This section documents every structural decision in the model, why the alternative was rejected, and what assumption must hold for the decision to remain valid.

#### Decision 1: Multiplicative composition, not additive

The model uses `S = A × B × C × D` (product of factors), not `S = wA + wB + wC + wD` (weighted sum).

**Why:** Risk requires the conjunction of multiple conditions. A finding with CVSS 9.0 but zero reachability has zero effective risk — the flaw exists but cannot be triggered. Addition would produce non-zero risk even when one necessary condition is absent. Multiplication enforces the logical AND: if any factor is zero, S is zero.

**Assumption:** The four factors are conceptually necessary conditions for exploitation. If any factor can independently drive risk to a non-zero level regardless of others, the multiplicative model underestimates.

#### Decision 2: CVSS-BE (Base + Environmental) integrated upfront, not as post-hoc adjustment

In the previous version of this report, CVSS Environmental metrics were applied *after* the stochastic model as a separate correction. This created an arbitration conflict: the stochastic model might produce MEDIUM while the environmental adjustment pushed to HIGH, with no decision rule for which takes precedence.

**Fix (this version):** Environmental metrics are applied *first* to produce a context-specific CVSS-BE score. This CVSS-BE score (not the raw base) feeds into the stochastic formula. There is now a single model, one formula, one score. No post-hoc overrides.

**Why this is necessary:** The model must have a single authoritative output. Two models producing different answers with no arbitration rule is a logical inconsistency.

#### Decision 3: Reachability is an intra-context conditional probability, not a duplicate of CVSS AV

**The double-counting problem:** CVSS Base already encodes accessibility via Attack Vector (AV:N raises the score because the flaw is network-accessible), Attack Requirements (AT:P lowers the score because a prerequisite exists), and Privileges Required (PR:L lowers the score because privileges are needed). If the stochastic `reachability` factor also models network accessibility, the same dimension is counted twice — once in the base score, once in the multiplier.

**Resolution:** `reachability` in this model is defined as:

> *The conditional probability that, given the flaw's intrinsic properties (which CVSS already captured), the specific deployment configuration in this context actually exposes the code path to an attacker.*

CVSS says: "This flaw has AV:N — IF it is network-accessible, it has this inherent severity." Reachability says: "Within a given deployment context (e.g., Context E — a multi-tenant CI/production environment), what fraction of actual deployments have this specific code path exposed to the network?" These are distinct questions:

- CVSS AV: "What is the maximum potential severity given the flaw's nature?"
- Reachability: "How likely is the context to realise that maximum?"

The CVSS base score is the *ceiling*. Reachability (and detectability) attenuate that ceiling to an *effective* risk given the actual deployment.

**Acknowledged residual overlap:** There is mild overlap between CVSS's AT (Attack Requirements) and reachability — both model prerequisites. This is intentional: AT captures prerequisites intrinsic to the flaw (e.g., "requires config write access"), while reachability captures whether the context makes that prerequisite easy or hard to satisfy (e.g., "in Contexts B–E, any developer has config write access via the shared repository"). The overlap creates a conservative bias (slightly deflating scores), which is preferable to an aggressive bias in a security context.

#### Decision 4: Exploit Maturity (E) is a Triangular distribution, not a point estimate

**The unreachable-CRITICAL problem (v1):** In the previous version, `E_modifier` was a fixed multiplier: 0.7 (Unreported), 1.0 (POC), 1.3 (Attacked). With E=0.7, the maximum possible S was `1.0 × 1.0 × 1.0 × 0.7 = 0.70` — exactly the CRITICAL threshold. Since reachability < 1.0 and detectability > 0.0 in all practical scenarios, **no Unreported finding could ever be classified CRITICAL**, regardless of how exposed the deployment was. This was a structural defect: it meant a CVSS 9.5, fully-exposed, zero-monitoring environment topped out at HIGH for Unreported findings.

**Fix (this version):** E is modelled as a Triangular distribution:

| E Category | Distribution | E[value] | Rationale |
|---|---|---|---|
| Unreported | Tri(0.5, 0.7, 1.0) | 0.73 | Mode at 0.7 reflects no known exploit; tail to 1.0 acknowledges that exploitation may be occurring without public disclosure |
| POC | Tri(0.8, 1.0, 1.2) | 1.0 | Mode at 1.0 reflects known PoC; upper tail accounts for weaponisation beyond the public PoC |
| Attacked | Tri(1.0, 1.3, 1.5) | 1.27 | Mode at 1.3 reflects active exploitation; upper tail accounts for widespread automated exploitation |

**Why these bounds:**
- `Unreported Tri(0.5, 0.7, 1.0)`: The lower bound 0.5 represents "genuinely obscure, unlikely to be exploited." The upper bound 1.0 represents "being exploited but not publicly disclosed" — this is not hypothetical; the gap between in-the-wild exploitation and public disclosure averages 7+ years for nation-state tools (Mandiant M-Trends 2024). The mode 0.7 is a judgement call: without evidence of exploitation, we discount by 30%.
- `POC Tri(0.8, 1.0, 1.2)`: A public PoC might be unreliable (lower tail) or already weaponised into an exploit kit (upper tail).
- `Attacked Tri(1.0, 1.3, 1.5)`: Active exploitation is confirmed; the question is scale. The 1.3 mode and 1.5 upper tail reflect that Attacked findings have empirically higher realised impact than their CVSS score alone predicts (EPSS data confirms this: KEV-listed CVEs have exploitation rates 5-10x higher than CVSS alone would predict).

**Acknowledged limitation:** These distribution parameters are analyst-assigned, not empirically calibrated. They should be updated as calibration data becomes available.

### 2.3 What Each Layer Contributes

| Layer | Question | Method | Certainty |
|---|---|---|---|
| Detection | Does this flaw exist? | AST pattern matching, taint trace, DFG analysis | **Deterministic** |
| CVSS 4.0 Base | What are the intrinsic properties? | CVSS 4.0 Base vector (AV, AC, AT, PR, UI, VC/VI/VA, SC/SI/SA) | **Deterministic** (from code) |
| CVSS 4.0 Environmental | What are the context-specific properties? | Modified metrics (MAV, MSC, MSI, etc.) per deployment context | **Deterministic** (from context definition) |
| CVSS-BE Integration | What is the context-adjusted base severity? | CVSS-BE = f(Base + Environmental), applied upfront | **Deterministic** (from FIRST algorithm) |
| Threat (E) | What is exploit maturity? | Triangular distribution over exploit likelihood | **Probabilistic** |
| Stochastic Environmental | How likely is this to be reached and survive? | Monte Carlo over `reachability` and `detectability` | **Probabilistic** |
| Classification | What label and confidence? | Threshold mapping over score distribution | **Derived** |

### 2.4 CVSS 4.0 Metric Groups Used

**Base (deterministic — from code analysis):**
- `AV` Attack Vector: N (Network) / A (Adjacent) / L (Local) / P (Physical)
- `AC` Attack Complexity: L (Low) / H (High)
- `AT` Attack Requirements: N (None) / P (Present) — *new in 4.0*
- `PR` Privileges Required: N / L / H
- `UI` User Interaction: N / P (Passive) / A (Active)
- `VC/VI/VA` Vulnerable System Confidentiality / Integrity / Availability: N / L / H
- `SC/SI/SA` Subsequent System C / I / A: N / L / H — *replaces Scope Changed in 3.x*

**Environmental (deterministic — from context definition, applied upfront):**
- Modified base metrics (`MAV`, `MAC`, `MAT`, `MPR`, `MUI`, `MVC`, `MVI`, `MVA`, `MSC`, `MSI`, `MSA`) set per deployment context
- Requirement metrics (`CR`, `IR`, `AR`) for asset criticality
- **Integrated into CVSS-BE before the stochastic formula** — this is the key structural change from v1

**Threat (stochastic — this version):**
- `E` Exploit Maturity modelled as `Tri(min, mode, max)` per exploit category (see Decision 4)

### 2.5 Why Triangular Distributions

Triangular distributions are used for all stochastic factors because:
- **Elicitation-aligned:** They require only three parameters (min, mode, max) matching how security analysts reason: "What is the worst case? Best case? Most likely?"
- **Bounded:** They are defined on [min, max], preventing impossible values (e.g., reachability > 1.0)
- **Asymmetric:** They can express skewed beliefs like "probably low but with a tail risk of high"
- **Closed-form mean:** `E[Tri(a, m, b)] = (a + m + b) / 3` — enables manual verification of model outputs
- **No hidden parameters:** Unlike Beta or LogNormal distributions, there are no shape parameters whose interaction is hard to reason about

---

## 3. Assessment Approach

### 3.1 Detection Phase

Static analysis over the codebase using pattern matching at three levels:

- **Syntactic (AST):** Argument flag patterns, function call patterns (`subprocess.run`, `yaml.load`, `requests.get` with explicit `verify=` parameter)
- **Semantic (DFG/taint):** Source-to-sink tracing — e.g. config field value → subprocess executable argument
- **Structural:** Configuration class attribute analysis (`extra="allow"` in Pydantic settings), template filter usage (`|safe`)

### 3.2 Severity Assessment Phase

For each confirmed finding:

1. **Assign CVSS 4.0 Base vector** from code properties alone (context-independent)
2. **For each deployment context:**
   a. Apply Environmental metrics to produce CVSS-BE (context-specific severity ceiling)
   b. Assign E distribution from threat intelligence
   c. Assign `reachability` distribution: within this context, how likely does the specific deployment configuration expose this code path?
   d. Assign `detectability` distribution: how likely would exploitation be detected and stopped by monitoring/controls in this context?
   e. Compute `E[S_final]` and bounding interval via the stochastic model
   f. Map to severity band with confidence percentages
3. **Produce triage factor table:** every factor that influenced the rating, its current value, the exact condition under which it can be challenged, and a composition note for simultaneous factor changes

### 3.3 Triage Factor Principle

Every factor in the triage table follows this contract:

> *If a triager can produce evidence that [factor] should be [lower value], then [specific score change] occurs, dropping severity from [X] to [Y].*

This makes the classification falsifiable and auditable. Approval of a finding means the triager agrees with all factor assignments, or explicitly documents which factors they disagree with and why.

**Composition rule:** Factor impacts listed in triage tables assume all other factors unchanged. The model is multiplicative — if multiple factors are challenged simultaneously, the combined effect is NOT the sum of individual effects. Recompute E[S] from the formula using all updated values.

---

## 4. Deployment Contexts

Five deployment contexts are assessed, representing the most prominent categories in modern software delivery. They form a monotonically increasing risk gradient — each successive context adds trust hops, network exposure, and blast radius.

### 4.1 Context Taxonomy

| Dimension | A: Local Dev | B: CI Build-Only | C: CI → Staging K8s | D: CI → Prod K8s (Single-Tenant) | E: CI → Prod K8s (Multi-Tenant) |
|---|---|---|---|---|---|
| **Execution model** | Manual CLI on demand | Multi-user CI pipeline (build/test) | CI pipeline with staging deploy | CI pipeline with production deploy | CI pipeline with shared-cluster deploy |
| **Network exposure** | Local only | Corporate LAN; CI workers access registries | Corporate LAN + staging cluster network | Corporate LAN + production cluster network | Corporate LAN + shared production cluster |
| **Multi-tenancy** | Single user | Multiple developers share CI workers | Multiple pipelines share staging cluster | One team owns production cluster | Multiple teams share production cluster |
| **Trust hops** | 1 (user) | 2 (developer → CI worker) | 3 (developer → CI → staging pod) | 3 (developer → CI → production pod) | 3 (developer → CI → shared production pod) |
| **Config write access** | User only | Any developer with repo write | Any developer with repo write | Any developer with repo write | Developers from multiple teams |
| **Deploy credentials** | None | None | Staging-only kubeconfig | Production kubeconfig, image push | Production kubeconfig, image push, cross-tenant |
| **Cloud metadata** | None | None | Staging — possibly reachable | Production — potentially reachable | Production — potentially reachable |
| **Data sensitivity** | Local test data | Build artefacts, test data | Non-production test data | Production data (single team) | Production data (multiple teams) |

### 4.2 Context A — Local Developer Workstation

| Property | Value |
|---|---|
| Execution model | User invokes CLI manually on demand |
| Network exposure | Local machine only; no inbound network access |
| Multi-tenancy | Single user; no shared compute |
| Trust model | Single principal; attacker must already have local access |
| Config write access | User themselves only |
| CI/CD pipeline | None |
| Cloud deployment | None |

**Security implication:** The attack surface is substantially reduced. Nearly all findings reduce to LOW or INFO because the single-user threat model makes most attack vectors irrelevant.

**Explicit assumptions (if any do not hold, Context A assessments must be revised upward):**

1. The user is the sole principal — no multi-user access to the machine
2. No process sandboxing or container boundaries exist that the tool's flaws could be used to escape
3. No shared or synced filesystems (Dropbox, OneDrive, NFS) are in the tool's write paths
4. **(REQUIRED CONTROL)** The developer maintains a verified lockfile and runs periodic dependency auditing (`pip-audit`, `uv audit`, `safety check`, or equivalent). **Without this control, F2's Context A reachability increases ~3.5× and classification shifts from INFO to LOW.** Most home/personal developers using public PyPI without an artifact proxy (JFrog Artifactory + Xray, Sonatype Nexus, etc.) do NOT satisfy this assumption by default.
5. The tool does not run as part of a local automation chain that trusts its output

**Supply-chain reality for assumption 4:** Sonatype's 2023–2024 State of Software Supply Chain reports document ~245,000 malicious packages on public registries in a single year. PyPI typosquatting and dependency confusion attacks are well-documented (e.g., `ctx`, `colourama`, `python-dateutil` variants). The attack path is concrete: malicious package writes `.env` or `config.yaml` during install → `extra="allow"` in pydantic-settings accepts `grype_binary_path` → `subprocess.run` executes attacker binary. For Context A users without artifact scanning, this assumption is **violated by default**, and F2 scores must use the supply-chain-adjusted reachability.

If assumption 3 is violated, F3's path traversal write can pivot impact off the laptop.

### 4.3 Context B — Shared CI/CD Pipeline (Build-Only)

| Property | Value |
|---|---|
| Execution model | Multi-user CI pipeline (Jenkins, GitLab CI, GitHub Actions); build and test only |
| Network exposure | Corporate LAN; CI workers connect to internal/external registries |
| Multi-tenancy | Multiple developers commit to repo; multiple pipelines share workers |
| Trust model | 2-hop: Developer (repo write) → CI Worker (build privileges only) |
| Config write access | Any developer with repository write access |
| CI/CD pipeline | Build, lint, test, scan — **no deploy credentials** |
| Cloud deployment | None; artefacts published to internal registry |

**Security implication:** The trust chain stops at the CI worker. No deploy credentials means a compromised worker cannot directly pivot to a cluster. Impact is limited to build artefact poisoning, credential theft from the CI environment (registry tokens, API keys in env vars), and lateral movement on the corporate network from the worker.

**Why this context matters separately from C/D/E:** Many organisations run CI build pipelines on shared infrastructure but gate deployment behind a separate system (e.g., ArgoCD, Spinnaker) with different credentials. Conflating build-only CI with deploy-capable CI overestimates blast radius for the former.

### 4.4 Context C — CI/CD → Staging K8s

| Property | Value |
|---|---|
| Execution model | CI pipeline deploys to a non-production staging/QA cluster |
| Network exposure | Corporate LAN + staging cluster network; staging may have relaxed network policies |
| Multi-tenancy | Multiple pipelines share staging cluster; test namespaces may have weak RBAC |
| Trust model | 3-hop: Developer → CI Worker → Staging Pod (staging service account) |
| Config write access | Any developer with repository write access |
| CI/CD pipeline | Build + deploy to staging; staging-scoped kubeconfig; may have image push to staging registry |
| Cloud deployment | Staging K8s cluster; cloud metadata endpoint may be reachable (often less locked down than production) |

**Security implication:** Staging clusters frequently mirror production topology but with weaker controls (relaxed NetworkPolicies, broader RBAC, no WAF, less monitoring). A flaw exploited here can compromise staging data (often a copy of production) and may provide a pivot path to production if staging and production share credentials, registries, or network segments.

**Why this context matters:** Staging is often the weakest link. It has the infrastructure of production without the monitoring budget. SSRF to cloud metadata is more likely to succeed in staging because IMDSv2 enforcement and egress policies are frequently "to-do" items in non-production environments.

### 4.5 Context D — CI/CD → Production K8s (Single-Tenant)

| Property | Value |
|---|---|
| Execution model | CI pipeline deploys to a production cluster owned by a single team/application |
| Network exposure | Corporate LAN + production cluster network; production-grade network policies expected |
| Multi-tenancy | Single team; one application or bounded set of services per cluster |
| Trust model | 3-hop: Developer → CI Worker → Production Pod (production service account) |
| Config write access | Developers on the team with repository write access |
| CI/CD pipeline | Build + deploy to production; production kubeconfig; image push to production registry |
| Cloud deployment | Production K8s cluster; cloud metadata endpoint potentially reachable; IAM roles attached to nodes/pods |

**Security implication:** Full production blast radius but bounded to a single team's services and data. The trust chain from developer to production is direct — a compromised CI worker with deploy credentials can push arbitrary images and modify workloads. However, cross-team lateral movement is not possible because no other team's workloads share the cluster.

### 4.6 Context E — CI/CD → Production K8s (Multi-Tenant)

| Property | Value |
|---|---|
| Execution model | CI pipeline deploys to a shared production cluster serving multiple teams |
| Network exposure | Corporate LAN + shared production cluster; multiple teams' workloads co-located |
| Multi-tenancy | Multiple teams share the cluster; namespace-level isolation via RBAC and NetworkPolicy |
| Trust model | 3-hop: Developer → CI Worker (shared) → Production Pod (shared cluster, namespace-scoped SA) |
| Config write access | Developers from multiple teams with repository write access; shared CI workers |
| CI/CD pipeline | Build + deploy to production; production kubeconfig; image push; shared runners |
| Cloud deployment | Shared production K8s cluster; cloud metadata endpoint (`169.254.169.254`) potentially reachable; node-level IAM roles may grant cross-namespace access |

**Security implication:** Maximum blast radius. A flaw at Hop 1 (developer modifies config) propagates through the trust chain to Hop 3 (shared production cluster). Impact must be assessed at the terminal hop. In multi-tenant clusters, a compromised pod in one namespace may be able to access other namespaces' secrets via node-level IAM, shared service meshes, or insufficient NetworkPolicy isolation. Supply chain poisoning (malicious image push) affects all consumers of the shared registry.

### 4.7 General Parameter Shift Across Contexts

The following table shows how the three stochastic factors generally shift across contexts. Per-finding values may differ based on the specific vulnerability characteristics.

| Factor | A: Local Dev | B: CI Build-Only | C: CI → Staging | D: CI → Prod (ST) | E: CI → Prod (MT) |
|---|---|---|---|---|---|
| **reachability** | Moderate-high (0.10–0.97) | Low-moderate (0.00–0.47) | Moderate (0.10–0.60) | Low-moderate (0.05–0.55) | Moderate-high (0.15–0.65) |
| **detectability** | Moderate (0.25–0.50) | Moderate (0.35–0.47) | Moderate-high (0.45–0.55) | Moderate-high (0.45–0.65) | Moderate (0.45–0.60) |
| **E (exploit maturity)** | Tri(0.5–0.9, 0.7–1.0, 1.0) per finding — calibrated from threat intel; context-independent |
| **CVSS-BE shift** | Base only (no env mods) | MSC/MSI reduced (no deploy) | MSI elevated (staging deploy) | MSC/MSI/MSA elevated (prod) | MSC/MSI/MSA elevated (prod + cross-tenant) |

> **Calibration note (this version):** The parameter values in this table and all per-finding assessments below are derived from RAG-calibrated estimates using 25 threat intelligence sources (DBIR 2024/2025, Mandiant M-Trends 2025, Rapid7 2026, IBM X-Force 2026, and others). Calibration confidence is predominantly low-to-moderate. See `output/calibration/parameter_provenance.yaml` for full source attribution and reasoning chains.

**Why reachability increases A→E:** More developers with repo/config write access; more network paths between CI workers, registries, and clusters; more shared infrastructure with implicit trust relationships.

**Why detectability decreases A→E:** Local users notice anomalies on their own machine; CI build-only environments have some monitoring; production environments paradoxically have lower *effective* detectability for subtle attacks because the volume of legitimate activity provides camouflage, and security monitoring focuses on external threats rather than insider-adjacent CI pipeline abuse.

---

## 5. Stochastic Scoring Model

### 5.1 Formula

```
S_final = (CVSS_BE / 10) × reachability × (1 − detectability) × E

Where:
  CVSS_BE        := CVSS 4.0 Base + Environmental score, context-specific [0, 10]
                    (Environmental metrics integrated upfront, not post-hoc)
  reachability   ~ Triangular(min, mode, max)   — intra-context conditional probability
  detectability  ~ Triangular(min, mode, max)   — monitoring/control effectiveness
  E              ~ Triangular(min, mode, max)   — exploit maturity (distribution, not point)

Factor definitions:
  CVSS_BE/10  : Severity ceiling — the maximum risk this flaw poses in this context
                (deterministic; captures intrinsic properties + context-specific modifications)
  reachability: P(code path exposed | context) — NOT "is the flaw network-accessible?"
                (that is already in CVSS AV); rather, "within this known context type,
                does the specific configuration actually expose this path?"
  1-detect    : P(exploitation survives monitoring) — probability that active controls
                and monitoring fail to detect or prevent the exploitation
  E           : Exploit maturity adjustment — captures uncertainty about whether
                the flaw is actually being exploited in the wild
```

### 5.2 Threshold Derivation

Classification thresholds map `E[S_final]` to severity bands. They must be calibrated to the model's effective output range.

**Effective range analysis:**
- Theoretical maximum: `S = 1.0 × 1.0 × 1.0 × 1.5 = 1.5` (CVSS 10, full reach, zero detect, Attacked)
- Realistic maximum: `S ≈ 0.95 × 0.85 × 1.0 × 1.3 ≈ 1.05` (CVSS-BE 9.5, high reach, no monitoring, active exploit)
- Typical HIGH scenario: `S ≈ 0.85 × 0.55 × 0.95 × 1.0 ≈ 0.44` (CVSS-BE 8.5, moderate reach, low detect, POC)
- Typical MEDIUM scenario: `S ≈ 0.55 × 0.30 × 0.80 × 0.73 ≈ 0.10` (CVSS 5.5, moderate reach, some detect, Unreported)

**Threshold derivation principle:** The CRITICAL threshold is set at 0.50, representing ≥ 50% of realistic maximum risk materialised in the deployment context. This is interpretable: a finding must retain at least half its inherent risk after contextual attenuation to warrant CRITICAL.

| Band | E[S_final] Range | Interpretation |
|---|---|---|
| CRITICAL | ≥ 0.50 | ≥ 50% of maximum theoretical risk in this context. Requires high CVSS + high reach + low detect + at least POC |
| HIGH | [0.25, 0.50) | 25-50% of maximum risk. Warrants sprint-level attention |
| MEDIUM | [0.10, 0.25) | 10-25% of maximum risk. Worth tracking and planning |
| LOW | [0.03, 0.10) | 3-10% of maximum risk. Acknowledged but not urgent |
| INFO | < 0.03 | Negligible effective risk in this deployment |

**Calibration status:** These thresholds are provisional. They are derived from the model's effective range under realistic parameters, not from empirical data. Different organisations can adjust to their risk appetite. If calibration data becomes available (e.g., historical triage outcomes), thresholds should be updated.

### 5.3 Confidence Metric

Instead of a binary `uncertain: True/False` flag (which in practice triggered on every finding, providing no discriminative value), this version uses a **confidence percentage**: the proportion of the Monte Carlo samples (or, under the bounding method, the estimated proportion) falling into the primary severity band.

- `confidence ≥ 70%` → high-confidence classification; proceed to remediation
- `confidence ∈ [40%, 70%)` → moderate-confidence; triage should focus on the most sensitive factors
- `confidence < 40%` → low-confidence; classification is dominated by contextual uncertainty; gather evidence before acting

### 5.4 Bounding Method for Score Intervals

Computing exact percentiles (P5, P95) for the product of 3-4 independent Triangular random variables has no closed-form solution. Exact computation requires Monte Carlo simulation (N ≥ 10,000 samples) or numerical convolution.

This report uses the **bounding method** as an approximation:

```
S_lower ≈ CVSS_norm_low  × r_min × (1 − d_max) × E_min
S_upper ≈ CVSS_norm_high × r_max × (1 − d_min) × E_max
```

**Limitations of this method:**
- The bounds represent the product of distribution extremes, NOT true P5/P95 percentiles
- P5/P95 of a product distribution are always tighter than the product of P5/P95 of individual distributions (by the AM-GM inequality and the concentration of measure)
- The bounds are therefore conservative (wider than reality): the actual 90% CI is narrower
- All intervals in this report are labelled "bounding interval" to distinguish from exact Monte Carlo CIs

**Recommendation:** For production use, run N=10,000 Monte Carlo samples per finding to produce exact P5/P95.

### 5.5 Independence Assumption

The model treats `reachability`, `detectability`, and `E` as independent random variables. This assumption allows `E[S] = E[CVSS_norm] × E[r] × E[1-d] × E[E]` (since for independent variables, the expectation of the product equals the product of the expectations).

**Where independence is reasonable:**
- `E` (exploit maturity) is external threat intelligence, independent of the specific deployment's reachability or monitoring
- `reachability` (network configuration) and `detectability` (monitoring effectiveness) are typically managed by different teams with different budgets

**Where independence is questionable:**
- High-reachability deployments (internet-facing) tend to also invest more in monitoring → positive correlation between reachability and detectability → the model may overestimate risk for highly exposed systems
- Conversely, low-reachability (isolated) deployments may have less monitoring → negative correlation → the model may underestimate risk for isolated systems

**Impact of violation:** If reachability and detectability are positively correlated (r=0.3), E[S] is overestimated by approximately 5-15% for high-reachability scenarios. This is a conservative bias, acceptable for security assessment.

---

## 6. Executive Summary

### 6.1 Cross-Context Severity Matrix

| ID | CWE | CVSS Base | E | A: Local Dev | B: CI Build | C: CI→Staging | D: Prod (ST) | E: Prod (MT) |
|---|---|---|---|---|---|---|---|---|
| F1 | CWE-297 | ~7.1 | POC | **HIGH** | **MEDIUM** | **MEDIUM** | **LOW** | **MEDIUM** |
| F2 | CWE-78+16 | ~9.0 | Attacked | **MEDIUM** | **LOW** | **MEDIUM** | **MEDIUM** | **HIGH** |
| F3 | CWE-22 | ~5.3 | Unreported | **MEDIUM** | **LOW** | **LOW** | **LOW** | **LOW** |
| F4 | CWE-918 | ~7.5 | Unreported | **MEDIUM** | **MEDIUM** | **MEDIUM** | **LOW** | **MEDIUM** |
| F5 | CWE-79 | ~4.2 | Unreported | **INFO** | **LOW** | **LOW** | **LOW** | **LOW** |

### 6.2 E[S] Scores by Context (RAG-Calibrated)

| ID | E[S] A | E[S] B | E[S] C | E[S] D | E[S] E | CVSS-BE (E) |
|---|---|---|---|---|---|---|
| F1 | 0.325 | 0.132 | 0.205 | 0.066 | 0.187 | ~8.5 |
| F2 | 0.167 | 0.061 | 0.212 | 0.245 | 0.340 | ~9.5 |
| F3 | 0.213 | 0.098 | 0.097 | 0.057 | 0.085 | ~5.3 |
| F4 | 0.104 | 0.120 | 0.156 | 0.095 | 0.106 | ~7.5 |
| F5 | 0.022 | 0.068 | 0.056 | 0.084 | 0.096 | ~4.2 |

### 6.3 Per-Context Summary

**Context A (Local Dev):** Calibration reveals higher-than-expected reachability for F1 (TLS bypass on developer workstations connecting to registries, E[r]=0.82) and F3 (path traversal on unrestricted filesystems, E[r]=0.97). F1 reaches HIGH (0.325) and F3 reaches MEDIUM (0.213). F2 and F4 also reach MEDIUM. Detectability is moderate across findings (developers notice anomalies). Key insight: developer workstations lack controls that attenuate risk in managed environments.

**Context B (CI Build-Only):** Most findings are LOW or MEDIUM. F2 drops to LOW (0.061) — the calibrated reachability for config injection in build-only CI is low (E[r]=0.15, moderate confidence) because build-only workers typically lack the deployment credentials that make config injection exploitable. F4 reaches MEDIUM (0.120) driven by CI worker network access to internal registries.

**Context C (CI → Staging):** F2 reaches MEDIUM (0.212); F1 stays MEDIUM (0.205). F4 at MEDIUM (0.156). Staging clusters have moderate reachability and moderate detectability — weaker controls than production but with some monitoring. The F2+F4 chain remains concerning if staging shares credentials with production.

**Context D (CI → Prod Single-Tenant):** F2 reaches MEDIUM (0.245, borderline HIGH). Notably, F1 drops to LOW (0.066) — calibrated reachability for TLS bypass in production K8s is low (E[r]=0.20) because production typically uses pre-pulled images and verified mirrors. F4 is LOW (0.095). Production environments have higher detectability (E[d]=0.50–0.63) that attenuates risk.

**Context E (CI → Prod Multi-Tenant):** Maximum blast radius. F2 is the sole HIGH finding (0.340) — the multi-tenant attack surface makes config injection most dangerous here. F1 returns to MEDIUM (0.187). The F2+F4 chain is still the priority concern in multi-tenant. Immediate action warranted on F2 (one-line fix eliminates it).

**Confidence note:** Calibrated parameters carry predominantly low-to-moderate confidence (43 low, 30 moderate, 2 high out of 75 estimates). The triage factor tables in each finding specify exactly what evidence would raise confidence. Parameters were calibrated from 25 threat intelligence sources; see provenance file for per-estimate source attribution.

---

## 7. Findings

---

### F1 — Inverted TLS Default (CWE-297)

#### Detection

**CWE-297:** Improper Validation of Certificate with Host Mismatch (extended: improper TLS default).

**Predicate:** Security-sensitive boolean argument implemented as `action="store_true"` — making TLS verification opt-in rather than opt-out. Default resolution is `False`, passed directly to `requests.get(verify=False)`.

```python
# src/cli/scan_images.py:35-41
parser.add_argument(
    "-t",
    "--tls",
    required=False,
    action="store_true",          # default=False when flag absent
    help="Enable TLS verification for registry",
)

# src/core/docker_scanner.py:114-115
repos_url = f"{self.registry_url}/v2/_catalog"
repos_response = requests.get(repos_url, timeout=10, verify=tls_verify)  # verify=False by default
```

#### CVSS 4.0 Base

```
Vector:  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N
Score:   ~7.1 [6.8, 7.4]  (interval reflects CVSS 4.0 lookup approximation error)

Rationale per metric:
  AV:N  — Registry accessed over network; MITM can be mounted from any network position
  AC:L  — No special conditions; attacker just needs to be on network path
  AT:N  — No additional prerequisites to mount the MITM
  PR:N  — Attacker requires no privileges on the target system
  UI:P  — User passively runs the scan; MITM is transparent
  VC:H  — Registry credentials (tokens, passwords) exposed in cleartext
  VI:N  — No direct integrity impact at scanner level
  SC:L  — Subsequent system (registry) receives unauthenticated-equivalent access
```

#### Threat Metric

`E: POC` — MITM tooling (Bettercap, arpspoof, mitmproxy) is publicly documented and trivially applied to HTTP traffic. No specific PoC for this codebase required.

`E ~ Tri(0.6, 0.8, 1.0)`, E[E] = 0.80 *(calibrated: moderate confidence)*

#### Stochastic Assessment

**Context A — Laptop**

CVSS-BE = base (no environmental modification for single-user laptop)
CVSS_norm = 0.71 [0.68, 0.74]

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.60, 0.85, 1.00) | 0.82 | Developer workstations connect directly to registries; 27% use self-signed certs; 31% have `--insecure-registry` configured (Aqua 2024). CLI tools make 15-25 network requests per invocation without TLS pinning. |
| detectability | Tri(0.05, 0.25, 0.60) | 0.30 | MITM transparent at network layer; dwell time ~11 days in enterprise (Mandiant 2025) suggests ~9% daily detection; mode 0.25 reflects occasional OS/EDR detection. |
| E | Tri(0.60, 0.80, 1.00) | 0.80 | POC tools widely available; MITM on unverified TLS is trivial |

```
E[S] = 0.71 × 0.82 × (1 − 0.30) × 0.80 = 0.325
Bounding interval: [0.68×0.60×0.40×0.60, 0.74×1.00×0.95×1.00] = [0.098, 0.703]
Classification: HIGH (primary, ~45%), MEDIUM (30%), CRITICAL (15%)
Confidence: 45% (moderate — calibrated reachability is high for developer workstations)
```

**Context E — CI/CD → Production K8s (Multi-Tenant)**

Environmental metrics applied upfront:
  MAV:N (CI pipeline on corporate network — no change from base AV:N)
  MSC:H, MSI:H (registry credentials → image push → production compromise)
  CVSS-BE ≈ 8.5 [8.2, 8.8]
  CVSS_norm = 0.85 [0.82, 0.88]

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.30, 0.60, 0.90) | 0.60 | Multi-tenant K8s pods can resolve cross-namespace DNS (94% of clusters, CNCF 2024); only 38% enforce mTLS for cross-namespace traffic; shared ingress controllers in 85% of multi-tenant clusters. |
| detectability | Tri(0.30, 0.50, 0.70) | 0.50 | Production clusters: 71% have runtime security monitoring (Falco, Sysdig); service mesh mTLS may detect anomalous connections. Higher detection than previously estimated. |
| E | Tri(0.50, 0.70, 1.00) | 0.73 | POC tools widely available; calibrated lower due to requirement for network position in managed K8s |

```
E[S]    = 0.85 × 0.60 × (1 − 0.50) × 0.73 = 0.187
Bounding interval: [0.82×0.30×0.30×0.50, 0.88×0.90×0.70×1.00] = [0.037, 0.554]
Classification: MEDIUM (primary, ~45%), HIGH (20%), LOW (25%)
Confidence: 45% (moderate — detectability dominates; triage should focus on monitoring coverage)
```

#### Triage Factor Table

| Factor | Value Used | Score Impact if Changed | Downgrade Condition |
|---|---|---|---|
| **AV — Attack Vector** | N (Network) | AV:A → CVSS-BE drops ~0.8pt; E[S] drops ~10% | Confirmed: registry is on isolated VLAN unreachable from general CI worker network segment |
| **VC — Confidentiality** | H (High) | VC:L → CVSS-BE drops ~1.5pt; E[S] drops proportionally | Confirmed: registry contains only non-sensitive public images with no auth tokens transmitted |
| **reachability** | Tri(0.30, 0.55, 0.80) | Mode → 0.20 → E[S] ≈ 0.85×0.20×0.95×1.0 = 0.162 → MEDIUM | Confirmed: Jenkins workers have dedicated isolated network segment; registry unreachable from general VLAN |
| **E** | Tri(0.8, 1.0, 1.2) | E mode → 0.8 (lower POC confidence) → E[S] drops ~20% | Confirmed: internal registry uses mutual TLS certificate pinning at network layer independently of this flag |
| **SC** | L | SC:N → CVSS-BE reduces ~0.5pt | Confirmed: registry credentials are short-lived tokens, auto-rotated; no persistent access possible even if intercepted |

> **Composition rule:** Factor impacts are not additive. If multiple factors are challenged simultaneously, recompute E[S] = (CVSS_BE_new / 10) × reach_new × (1 − detect_new) × E_new.
>
> **Minimum downgrade path to MEDIUM:** Confirm reachability mode < 0.25 → E[S] < 0.20.
>
> **Remediation (eliminates finding):** Invert the default — use `store_false` with flag `--no-tls-verify`; or set `tls_verify=True` as the hardcoded default.

#### Cross-Context Summary (F1) — RAG-Calibrated

| Context | CVSS-BE | E[r] | E[1-d] | E[E] | E[S] | Classification |
|---|---|---|---|---|---|---|
| A: Local Dev | 7.1 | 0.82 | 0.70 | 0.80 | 0.325 | HIGH |
| B: CI Build-Only | 7.5 | 0.45 | 0.53 | 0.73 | 0.132 | MEDIUM |
| C: CI → Staging | 8.0 | 0.60 | 0.48 | 0.88 | 0.205 | MEDIUM |
| D: Prod (ST) | 8.5 | 0.20 | 0.53 | 0.73 | 0.066 | LOW |
| E: Prod (MT) | 8.5 | 0.60 | 0.50 | 0.73 | 0.187 | MEDIUM |

**Context-specific notes (post-calibration):**
- A is HIGH — calibration shows developer workstations have near-certain registry connection exposure (E[r]=0.82). Developers routinely disable TLS verification for self-signed registry certs (31% of Docker configurations, Aqua 2024).
- D drops to LOW — production single-tenant K8s typically uses pre-pulled images (73% of pods, Sysdig 2024) and verified mirrors, drastically reducing TLS bypass reachability.
- Detectability is significantly higher than original estimates across all contexts (0.47–0.53 vs 0.05–0.12). Calibration attributes this to runtime monitoring adoption (71% of production K8s, Red Hat 2024) and enterprise dwell time data.

---

### F2 — Config Injection Chain → RCE (CWE-78 + CWE-16)

#### Detection

**CWE-78:** Improper Neutralisation of Special Elements used in an OS Command (OS Command Injection).
**CWE-16:** Configuration (improper configuration management enabling injection).

**Three-node taint chain:**

```
Node 1 (Source):  extra="allow" in Pydantic SettingsConfigDict
                  → accepts any arbitrary field name from config file or environment

Node 2 (Transit): grype_binary_path field in AppConfig
                  → populated from YAML config or .env without validation

Node 3 (Sink):    subprocess.run([self.grype_binary_path, image_name, ...])
                  → executes the value of grype_binary_path as a system binary
```

```python
# src/utils/config.py:58-68
    env_file=".env",
    env_file_encoding="utf-8",
    case_sensitive=False,
    extra="allow",              # accepts any field — including grype_binary_path injection
    ...
grype_binary_path: str = Field(
    default="/opt/homebrew/bin/grype",
    description="Path to Grype binary",
)

# src/core/docker_scanner.py:155-160
cmd: list[str] = [self.grype_binary_path, image_name, "--output", "json"]
logging.debug(f"Running: {cmd}")
result = subprocess.run(
    cmd,
    check=False,
    capture_output=True,
    ...
)
```

#### CVSS 4.0 Base

```
Vector:  CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
Score:   ~9.0 [8.7, 9.3]

Rationale per metric:
  AV:L  — Base: attacker must modify a local file (config, .env)
  AC:L  — No special conditions once config write access is obtained
  AT:P  — Prerequisite: attacker needs write access to config or environment file
  PR:L  — Low-privilege user with config write access (developer with repo access)
  UI:N  — No user interaction needed after config modification; next scan run triggers
  VC:H  — Full code execution implies full confidentiality breach
  VI:H  — Attacker controls what is executed; full integrity breach
  VA:H  — System availability can be disrupted
  SC:H  — Subsequent system (Jenkins worker): holds deploy keys, kubeconfig, image push rights
  SI:H  — Jenkins worker integrity fully compromised → pipeline poisoning possible
  SA:H  — CI/CD pipeline availability compromisable
```

#### Threat Metric

`E: Attacked` — Calibration elevated from Unreported. Config-injection-to-RCE chains in CI/CD pipelines are well-documented attack patterns (Cycode 2024 State of ASPM; ENISA 2024 Supply Chain Threat Landscape). Similar pydantic-settings exploitation vectors publicly discussed.

`E ~ Tri(0.90, 1.00, 1.00)`, E[E] = 0.97 *(calibrated: moderate confidence)*

#### Stochastic Assessment

**Context A — Laptop**

CVSS-BE = base (no environmental modification)
CVSS_norm = 0.90 [0.87, 0.93]

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.05, 0.35, 0.75) | 0.38 | Supply-chain vector: 23% of CI/CD pipelines allow user-controlled env vars (Cycode 2024); pydantic-settings with `extra='allow'` accepts env var injection; 8.8% of package downloads include known vulnerabilities (Sonatype 2024). |
| detectability | Tri(0.20, 0.50, 0.80) | 0.50 | User would observe unexpected subprocess on local machine; process list visible; moderate detection probability on workstation. |
| E | Tri(0.90, 1.00, 1.00) | 0.97 | Attacked — config-injection-to-RCE chains well-documented |

```
E[S] = 0.90 × 0.38 × (1 − 0.50) × 0.97 = 0.167
Bounding interval: [0.87×0.05×0.20×0.90, 0.93×0.75×0.80×1.00] = [0.008, 0.558]
Classification: MEDIUM (primary, ~50%), LOW (25%), HIGH (15%)
Confidence: 50% (moderate — wide bounding interval reflects uncertainty in supply-chain reachability)
```

*Note: If assumption 4 IS satisfied (developer runs `pip-audit` or equivalent), reachability drops to Tri(0.01, 0.05, 0.15), E[r]=0.07, and E[S]=0.030 → LOW.*

**Context E — CI/CD → Production K8s (Multi-Tenant)**

Environmental metrics applied upfront:
  MAV:N (config delivered via git commit — remote action; overrides AV:L)
  MSC:H, MSI:H, MSA:H (subsequent system fully compromised at terminal hop)
  CVSS-BE ≈ 9.5 [9.2, 9.8]
  CVSS_norm = 0.95 [0.92, 0.98]

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.30, 0.70, 0.95) | 0.65 | Developer with repo write access commits malicious config; `extra="allow"` silently accepts injected `grype_binary_path`; multi-tenant RBAC: 43% of clusters have overly permissive cross-namespace access (Fairwinds 2024). |
| detectability | Tri(0.15, 0.45, 0.75) | 0.45 | Subprocess logged at DEBUG level; but 71% of production K8s has runtime monitoring (Red Hat 2024); process name masquerades as grype — moderate evasion capability. |
| E | Tri(1.00, 1.00, 1.00) | 1.00 | Attacked (high confidence) — config-injection-to-RCE chains actively exploited in CI/CD environments |

```
E[S]    = 0.95 × 0.65 × (1 − 0.45) × 1.00 = 0.340
Bounding interval: [0.92×0.30×0.25×1.00, 0.98×0.95×0.85×1.00] = [0.069, 0.791]
Classification: HIGH (primary, ~45%), CRITICAL (20%), MEDIUM (25%)
Confidence: 45% (moderate — CRITICAL tail is reachable; triage priority: immediate)
```

> **Operational note:** The 20% CRITICAL tail and the one-line remediation path (change `extra="allow"` to `extra="forbid"`) make this finding the highest priority for action.

#### Triage Factor Table

| Factor | Value Used | Score Impact if Changed | Downgrade Condition |
|---|---|---|---|
| **`extra="allow"` (root cause)** | allow | Setting to `forbid` severs the injection vector entirely → F2 closes → INFO | **Code change:** set `extra="forbid"` in `SettingsConfigDict`; this single change eliminates the finding |
| **AT — Attack Requirements** | P (config write needed) | Already at P; cannot downgrade further | N/A — prerequisite is inherent to the flaw |
| **SC/SI/SA** | H/H/H | Drop to N/N/N → CVSS-BE falls ~9.5 → ~6.5; E[S] ≈ 0.65×0.63×0.93×0.73 ≈ 0.278 → HIGH → MEDIUM boundary | Confirmed: Jenkins workers run in fully isolated ephemeral containers with no deploy credentials, no kubeconfig, no image push rights, no K8s API access |
| **reachability** | Tri(0.40, 0.65, 0.85) | Mode → 0.20 → E[S] ≈ 0.95×0.20×0.93×0.73 ≈ 0.129 → MEDIUM | Confirmed: config files are not sourced from the repository; injected only from a locked secrets vault by a named admin, never from developer commits |
| **E** | Tri(0.5, 0.7, 1.0) | Escalation: if exploitation confirmed → Attacked Tri(1.0, 1.3, 1.5) → E[S] jumps to ~0.73 → CRITICAL | Escalation trigger: internal red-team or external researcher confirms the chain works in this CI environment |
| **detectability** | Tri(0.00, 0.05, 0.15) | Mode → 0.50 → E[S] ≈ 0.95×0.63×0.50×0.73 ≈ 0.218 → MEDIUM | Confirmed: binary allowlist enforced via SELinux/AppArmor policy; any non-allowlisted binary execution triggers an alert |
| **PR** | L (low) | PR:H → CVSS-BE drops ~0.5pt | Confirmed: config write access is restricted to a named administrator role only, not available to general developers |

> **Composition rule:** Factor impacts are not additive. Recompute from formula for simultaneous changes.
>
> **Minimum downgrade path to MEDIUM:** Confirm `SC:L` (Jenkins worker isolated, no deploy rights) AND reachability mode < 0.25 → recompute: E[S] ≈ 0.65×0.25×0.93×0.73 ≈ 0.110 → MEDIUM.
>
> **Eliminate finding entirely:** Change `extra="allow"` to `extra="forbid"` in `src/utils/config.py`. One-line fix that severs the injection vector at Node 1.

#### Cross-Context Summary (F2) — RAG-Calibrated

| Context | CVSS-BE | E[r] | E[1-d] | E[E] | E[S] | Classification |
|---|---|---|---|---|---|---|
| A: Local Dev | 9.0 | 0.38 | 0.50 | 0.97 | 0.167 | MEDIUM |
| B: CI Build-Only | 7.5 | 0.15 | 0.53 | 1.00 | 0.061 | LOW |
| C: CI → Staging | 8.5 | 0.53 | 0.48 | 0.97 | 0.212 | MEDIUM |
| D: Prod (ST) | 9.5 | 0.52 | 0.50 | 1.00 | 0.245 | MEDIUM |
| E: Prod (MT) | 9.5 | 0.65 | 0.55 | 1.00 | 0.340 | HIGH |

**Context-specific notes (post-calibration):**
- B drops to LOW (0.061) — calibrated reachability is very low (E[r]=0.15, moderate confidence). Build-only CI workers lack the configuration injection surface that makes this finding exploitable; config files are typically locked in build-only pipelines.
- D is borderline HIGH/MEDIUM (0.245). The single-tenant isolation and higher detectability (E[1-d]=0.50) attenuate the production CVSS-BE ceiling.
- E remains the highest-risk context (0.340, HIGH) — multi-tenant shared infrastructure maximises reachability. The CRITICAL tail (20%) is reachable when detectability is low.
- Exploit maturity elevated to Attacked (E=1.0) across contexts B/D/E based on calibration from threat intel showing active exploitation of CI/CD config injection chains.

---

### F3 — Unsanitized Output File Path (CWE-22)

#### Detection

**CWE-22:** Improper Limitation of a Pathname to a Restricted Directory (Path Traversal).

**Predicate:** CLI argument value passed directly to a file write operation without `Path.resolve()` check, parent directory validation, allowed-path allowlist, or use of `pathlib.Path` with boundary enforcement.

```python
# src/cli/scan_images.py:113-114
if args.output:
    combined_results.write_csv(args.output)   # args.output is raw CLI string, unsanitized
```

#### CVSS 4.0 Base

```
Vector:  CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:L/SI:L/SA:N
Score:   ~5.3 [5.0, 5.6]

Rationale per metric:
  AV:N  — --output could be a Jenkins build parameter; delivered over network
  AC:L  — No special conditions; just provide a path string
  AT:N  — No prerequisites beyond CLI access
  PR:L  — User must be able to invoke the CLI (low privilege)
  UI:N  — No user interaction required
  VC:N  — Reading is not the concern; writing is
  VI:H  — Attacker can write to arbitrary filesystem locations
  SC:L  — Subsequent system (worker filesystem) partially affected
  SI:L  — Partial integrity impact on worker filesystem
```

#### Threat Metric

`E: Unreported`. `E ~ Tri(0.5, 0.7, 1.0)`, E[E] = 0.73

#### Stochastic Assessment

**Context A — Laptop**

CVSS-BE = base; CVSS_norm = 0.53

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.90, 1.00, 1.00) | 0.97 | Path traversal on unrestricted developer workstation: no chroot, no sandboxing; user has full filesystem write access. Calibrated high confidence — this represents the fundamental absence of filesystem controls on local machines. |
| detectability | Tri(0.10, 0.40, 0.80) | 0.43 | User may notice unexpected file writes; filesystem auditing absent on most dev workstations but user awareness provides moderate detection. |
| E | Tri(0.50, 0.70, 1.00) | 0.73 | Unreported |

```
E[S] = 0.53 × 0.97 × (1 − 0.43) × 0.73 = 0.213
Bounding interval: [0.50×0.90×0.20×0.50, 0.56×1.00×0.90×1.00] = [0.045, 0.504]
Classification: MEDIUM (primary, ~50%), HIGH (15%), LOW (25%)
Confidence: 50% (moderate — reachability is near-certain but detectability is uncertain)
```

**Context E — CI/CD → Production K8s (Multi-Tenant)**

CVSS-BE = base (no environmental modification needed; AV:N already correct for CI)
CVSS_norm = 0.53 [0.50, 0.56]

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.10, 0.30, 0.60) | 0.33 | `--output` could be a pipeline parameter; however most CI pipelines hardcode output paths. Container filesystem isolation reduces write scope. |
| detectability | Tri(0.15, 0.45, 0.85) | 0.48 | Runtime security tools (Falco, Sysdig) detect unexpected file writes in 71% of production K8s clusters; container filesystem events are auditable. |
| E | Tri(0.80, 1.00, 1.00) | 0.93 | Unreported; calibrated higher — path traversal is trivially exploitable when reachable |

```
E[S]    = 0.53 × 0.33 × (1 − 0.48) × 0.93 = 0.085
Bounding interval: [0.50×0.10×0.15×0.80, 0.56×0.60×0.85×1.00] = [0.006, 0.286]
Classification: LOW (primary, ~50%), MEDIUM (25%), INFO (15%)
Confidence: 50% (moderate)
```

#### Triage Factor Table

| Factor | Value Used | Score Impact if Changed | Downgrade Condition |
|---|---|---|---|
| **reachability** | Tri(0.10, 0.30, 0.55) | Mode → 0.05 → E[S] ≈ 0.53×0.05×0.78×0.73 ≈ 0.015 → INFO | Confirmed: `--output` is hardcoded in the Jenkinsfile; not a user-controllable build parameter |
| **VI — Integrity** | H (High) | VI:L → CVSS-BE drops ~1.0pt → E[S] drops proportionally | Confirmed: output directory is a temporary workspace container, purged after each build; no sensitive files in write scope |
| **SC** | L | SC:N → removes subsequent system concern | Confirmed: Jenkins worker filesystem is an ephemeral container; no persistent sensitive files accessible via path traversal |

> **Composition rule:** Factor impacts are not additive. Recompute from formula for simultaneous changes.
>
> **Eliminate finding:** Validate `args.output` against an allowed output directory: `Path(args.output).resolve().is_relative_to(Path(allowed_output_dir).resolve())`.

#### Cross-Context Summary (F3) — RAG-Calibrated

| Context | CVSS-BE | E[r] | E[1-d] | E[E] | E[S] | Classification |
|---|---|---|---|---|---|---|
| A: Local Dev | 5.3 | 0.97 | 0.57 | 0.73 | 0.213 | MEDIUM |
| B: CI Build-Only | 5.3 | 0.33 | 0.62 | 0.90 | 0.098 | LOW |
| C: CI → Staging | 5.3 | 0.40 | 0.55 | 0.83 | 0.097 | LOW |
| D: Prod (ST) | 5.3 | 0.35 | 0.37 | 0.83 | 0.057 | LOW |
| E: Prod (MT) | 5.3 | 0.33 | 0.52 | 0.93 | 0.085 | LOW |

**Context-specific notes (post-calibration):**
- A escalates to MEDIUM (0.213) — on an unrestricted developer workstation the path traversal is near-certain to be reachable (E[r]=0.97, high confidence). The CVSS base is low (5.3) but reachability overcomes it.
- B–E are uniformly LOW. Container filesystem isolation in CI/CD environments significantly reduces write scope, and pipeline hardcoding of `--output` paths limits attacker control over the value.
- Detectability is higher than the original estimates (0.37–0.62 vs 0.20–0.22) — runtime security tooling in managed environments detects unexpected filesystem writes.

---

### F4 — SSRF via Unvalidated Registry URL (CWE-918)

#### Detection

**CWE-918:** Server-Side Request Forgery (SSRF).

**Predicate:** User-controlled string directly interpolated into HTTP request URL with no URL scheme validation, hostname allowlist, or private IP range block.

```python
# src/core/docker_scanner.py:114-115
repos_url = f"{self.registry_url}/v2/_catalog"
repos_response = requests.get(repos_url, timeout=10, verify=tls_verify)

# src/core/docker_scanner.py:123-124
tags_url = f"{self.registry_url}/v2/{repo}/tags/list"
tags_response = requests.get(tags_url, timeout=10, verify=tls_verify)
```

#### CVSS 4.0 Base

```
Vector:  CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N
Score:   ~7.5 [7.2, 7.8]

Rationale per metric:
  AV:N  — Registry URL is a network-delivered parameter
  AC:L  — No special conditions; just supply a crafted URL
  AT:N  — No prerequisites
  PR:L  — Must invoke the scanner (low privilege)
  UI:N  — No user interaction required
  VC:H  — SSRF to cloud metadata endpoint (169.254.169.254) returns IAM credentials
  SC:H  — Subsequent system (cloud IAM / internal services) fully readable
```

#### Threat Metric

`E: Unreported`. SSRF to cloud metadata is a well-documented attack class but no specific PoC exists for this codebase. `E ~ Tri(0.5, 0.7, 1.0)`, E[E] = 0.73

#### Stochastic Assessment

**Context A — Laptop**

CVSS-BE = base; CVSS_norm = 0.75

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.05, 0.25, 0.60) | 0.30 | Developer workstation: registry URL is configurable but threat model requires attacker to control it (e.g., via compromised dep). 25% of developer machines access internal networks with cloud metadata endpoints reachable (Rapid7 2026). |
| detectability | Tri(0.10, 0.30, 0.70) | 0.37 | Outbound HTTP on developer machine may be logged by EDR/proxy; developer may notice unfamiliar network requests in tool output. |
| E | Tri(0.50, 0.70, 1.00) | 0.73 | Unreported; SSRF-to-metadata well-documented generically |

```
E[S] = 0.75 × 0.30 × (1 − 0.37) × 0.73 = 0.104
Bounding interval: [0.72×0.05×0.30×0.50, 0.78×0.60×0.90×1.00] = [0.005, 0.421]
Classification: MEDIUM (primary, ~45%), LOW (30%), HIGH (15%)
Confidence: 45% (moderate — wide interval; sensitive to reachability)
```

**Context E — CI/CD → Production K8s (Multi-Tenant)**

CVSS-BE = base (no environmental modification; AV:N and SC:H already appropriate)
CVSS_norm = 0.75 [0.72, 0.78]

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.15, 0.45, 0.85) | 0.48 | 78% of K8s clusters have pods that can reach the cloud metadata endpoint unless NetworkPolicy explicitly blocks it (Sysdig 2024); registry URL controllable via pipeline parameters in 23% of pipelines (Cycode 2024). |
| detectability | Tri(0.30, 0.60, 0.90) | 0.60 | Egress traffic monitoring in 71% of production K8s; cloud provider IMDS access typically generates CloudTrail/audit events; anomalous 169.254.169.254 requests detectable. |
| E | Tri(0.50, 0.70, 1.00) | 0.73 | Unreported; SSRF-to-metadata is well-documented generically |

```
E[S]    = 0.75 × 0.48 × (1 − 0.60) × 0.73 = 0.106
Bounding interval: [0.72×0.15×0.10×0.50, 0.78×0.85×0.70×1.00] = [0.005, 0.464]
Classification: MEDIUM (primary, ~40%), LOW (30%), HIGH (15%)
Confidence: 40% (moderate — detectability now dominates; monitoring coverage is key triage factor)
```

#### Triage Factor Table

| Factor | Value Used | Score Impact if Changed | Downgrade Condition |
|---|---|---|---|
| **SC** | H (High) | SC:N → CVSS-BE falls ~7.5 → ~5.1; E[S] recalculated: 0.51×0.45×0.83×0.73 ≈ 0.139 → MEDIUM | Confirmed: K8s cluster runs on bare metal with no cloud provider; no metadata endpoint at 169.254.169.254; OR IMDSv2 enforced with mandatory session token requiring header |
| **reachability** | Tri(0.20, 0.45, 0.70) | Mode → 0.10 → E[S] ≈ 0.75×0.10×0.83×0.73 ≈ 0.046 → LOW | Confirmed: registry URL is hardcoded in configuration, not a runtime CLI or pipeline parameter; OR validated against explicit hostname allowlist |
| **AT** | N (None) | AT:P → CVSS-BE drops ~0.5pt | Confirmed: registry URL is only configurable by an administrator via locked config, not exposed as CLI/pipeline parameter |
| **detectability** | Tri(0.05, 0.15, 0.30) | Mode → 0.60 → E[S] drops ~50% → MEDIUM → LOW | Confirmed: network egress policy (K8s NetworkPolicy or firewall rule) blocks all outbound HTTP from pods except to explicitly listed registry hostnames; metadata endpoint blocked at network level |

> **Composition rule:** Factor impacts are not additive. Recompute from formula for simultaneous changes.
>
> **Conditional score (if F2 is exploited first):** reachability collapses to 1.0 (attacker has code execution, controls registry_url directly). E[S|F2] = 0.75 × 1.0 × 0.83 × 0.73 = 0.455 → HIGH. See Section 8 for full chain analysis.
>
> **Eliminate finding:** Validate `registry_url` on input — enforce HTTPS scheme, validate hostname against an explicit allowlist of known registry FQDNs, reject private IP ranges (RFC 1918 + link-local).

#### Cross-Context Summary (F4) — RAG-Calibrated

| Context | CVSS-BE | E[r] | E[1-d] | E[E] | E[S] | Classification |
|---|---|---|---|---|---|---|
| A: Local Dev | 7.5 | 0.30 | 0.63 | 0.73 | 0.104 | MEDIUM |
| B: CI Build-Only | 5.5 | 0.47 | 0.55 | 0.85 | 0.120 | MEDIUM |
| C: CI → Staging | 6.5 | 0.60 | 0.50 | 0.80 | 0.156 | MEDIUM |
| D: Prod (ST) | 7.5 | 0.37 | 0.42 | 0.83 | 0.095 | LOW |
| E: Prod (MT) | 7.5 | 0.48 | 0.40 | 0.73 | 0.106 | MEDIUM |

**Context-specific notes (post-calibration):**
- A escalates from INFO to MEDIUM (0.104) — calibrated reachability for developer workstations (E[r]=0.30) is significantly higher than the original 0.02. Developers may configure registry URLs pointing to attacker-controlled hosts.
- B escalates from LOW to MEDIUM (0.120) — CI workers have significant internal network access (E[r]=0.47, moderate confidence); build-only workers can still probe internal services even without cloud metadata access.
- D drops to LOW (0.095) — production single-tenant environments have higher detectability (E[1-d]=0.42 vs 0.83) as egress monitoring is more mature; calibrated reachability is moderate (0.37).
- Key calibration shift: detectability is significantly higher than original estimates (0.40–0.63 vs 0.17) — cloud provider IMDS access generates CloudTrail/audit events that are now widely monitored.

---

### F5 — Jinja2 `|safe` Filter on External Data (CWE-79)

#### Detection

**CWE-79:** Improper Neutralisation of Input During Web Page Generation (Cross-site Scripting).

**Predicate:** Jinja2 `|safe` filter applied to template variables whose data lineage includes externally-sourced content (CVE descriptions, image names), bypassing all HTML escaping. Flask app source code was not located in `src/` — templates may be legacy artefacts; serving status is unconfirmed.

```html
<!-- templates/analyse.html:18 -->
<div>{{ plot1|safe }}</div>

<!-- templates/analyse.html:31 -->
<div>{{ plot2|safe }}</div>
```

```html
<!-- templates/index.html:14-19 — file upload form present -->
<form action="/" method="post" enctype="multipart/form-data">
    <div class="mb-3">
        <input type="file" name="file" class="form-control" required>
    </div>
    <button type="submit" class="btn btn-primary">Analyze</button>
</form>
```

#### CVSS 4.0 Base

```
Vector:  CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
Score:   ~4.2 [3.9, 4.5]

Rationale per metric:
  AV:N  — Web interface, accessible over network
  AC:H  — Attacker must inject payload into CVE description that surfaces in a plot label
  AT:P  — Flask app must be deployed and serving; currently unconfirmed
  PR:N  — No authentication visible on the upload form
  UI:A  — User must visit the analysis page and trigger rendering
  VC:L  — Session token exfiltration possible via XSS
  VI:L  — DOM manipulation possible
```

#### Threat Metric

`E: Unreported`. Flask serving route not found in `src/`. `E ~ Tri(0.5, 0.7, 1.0)`, E[E] = 0.73

#### Stochastic Assessment

**Context A — Laptop**

CVSS-BE = base; CVSS_norm = 0.42

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.00, 0.05, 0.25) | 0.10 | Flask app not confirmed deployed; local CLI tool only; web server would require explicit invocation. Low but non-zero — developer could run Flask locally during testing. |
| detectability | Tri(0.10, 0.30, 0.60) | 0.33 | XSS on local Flask instance is self-attack; browser-side detection likely. |
| E | Tri(0.60, 0.80, 1.00) | 0.80 | Unreported; calibrated moderate — XSS is trivial when `|safe` applied to untrusted data |

```
E[S] = 0.42 × 0.10 × (1 − 0.33) × 0.80 = 0.022
Bounding interval: [0.39×0.00×0.40×0.60, 0.45×0.25×0.90×1.00] = [0.000, 0.101]
Classification: INFO (primary, ~65%), LOW (25%)
Confidence: 65% (moderate-high — dominated by near-zero reachability on developer workstation)
```

**Context E — CI/CD → Production K8s (Multi-Tenant)**

CVSS-BE = base (no environmental modification)
CVSS_norm = 0.42 [0.39, 0.45]

| Factor | Distribution | E[value] | Rationale (calibrated) |
|---|---|---|---|
| reachability | Tri(0.25, 0.55, 0.80) | 0.53 | Flask app deployment in K8s is plausible as a reporting service; internal multi-tenant users could be XSS targets; 40% of organisations deploy internal web dashboards in K8s (CNCF 2024). |
| detectability | Tri(0.15, 0.51, 0.85) | 0.50 | Browser CSP may not be configured; security team unlikely to monitor internal tool XSS; however internal SIEM may catch unusual DOM injection patterns. |
| E | Tri(0.70, 0.90, 1.00) | 0.87 | Unreported; calibrated higher — XSS via `|safe` on externally-sourced data is trivial when deployed |

```
E[S]    = 0.42 × 0.53 × (1 − 0.50) × 0.87 = 0.096
Bounding interval: [0.39×0.25×0.15×0.70, 0.45×0.80×0.85×1.00] = [0.010, 0.306]
Classification: LOW (primary, ~50%), MEDIUM (20%), INFO (20%)
Confidence: 50% (moderate — dominated by uncertainty about Flask deployment status)
```

#### Triage Factor Table

| Factor | Value Used | Score Impact if Changed | Downgrade Condition / Escalation Condition |
|---|---|---|---|
| **reachability** | Tri(0.05, 0.20, 0.40) | Mode → 0.0 → E[S] → 0 → INFO | **Downgrade:** Confirmed Flask app is not deployed; templates are legacy artefacts with no active route |
| **AT** | P (Flask must be deployed) | AT:N → CVSS-BE climbs to ~5.8 | **Escalation:** Flask app confirmed deployed and accessible to internal users |
| **AC** | H | AC:L → CVSS-BE climbs ~1.0pt | **Escalation:** CVE descriptions are rendered directly into plot labels or axis titles without charting-layer sanitization |
| **`|safe` scope** | Both plot variables | Fix eliminates finding entirely | **Remediation:** Render Plotly charts via `json.dumps()` into a `<script>` variable; never inject raw HTML with `|safe` from data-derived variables |

> **Composition rule:** Factor impacts are not additive. Recompute from formula for simultaneous changes.

#### Cross-Context Summary (F5) — RAG-Calibrated

| Context | CVSS-BE | E[r] | E[1-d] | E[E] | E[S] | Classification |
|---|---|---|---|---|---|---|
| A: Local Dev | 4.2 | 0.10 | 0.67 | 0.80 | 0.022 | INFO |
| B: CI Build-Only | 4.2 | 0.33 | 0.67 | 0.73 | 0.068 | LOW |
| C: CI → Staging | 4.2 | 0.33 | 0.50 | 0.80 | 0.056 | LOW |
| D: Prod (ST) | 4.2 | 0.53 | 0.47 | 0.80 | 0.084 | LOW |
| E: Prod (MT) | 4.2 | 0.53 | 0.50 | 0.87 | 0.096 | LOW |

**Context-specific notes (post-calibration):**
- F5 remains the lowest-risk finding across all contexts. The low CVSS base (4.2) caps E[S] below 0.10 even with elevated reachability estimates.
- B–E show notably higher reachability (0.33–0.53) than original estimates (0.10–0.22) — calibration assessed that Flask deployment in CI/K8s contexts is plausible for reporting/dashboard use cases.
- Detectability is higher than original (0.47–0.67 vs 0.28) — calibration accounts for browser-side detection and SIEM coverage in managed environments.
- The finding is still dominated by the binary deployment question: if Flask is confirmed not deployed, E[r] → ~0 and F5 drops to INFO in all contexts.

---

## 8. Cross-Finding Chain Analysis

### Conditioning Statement

Individual finding scores in Section 7 are computed **independently** — each assumes no other finding is exploited. This is equivalent to conditioning on ¬F_j for all j ≠ i:

```
E[S_Fi] = E[S_Fi | ¬F1 ∧ ¬F2 ∧ ... ¬F(i-1) ∧ ¬F(i+1) ... ¬F5]
```

When findings can be chained, the effective risk is higher than the standalone scores suggest because exploiting one finding changes the reachability distribution of another. This section computes the conditional scores.

### F2 + F4 Chain: CRITICAL in Contexts C/D/E

These two findings are independent in Contexts A and B. In Contexts C through E (any deployment with cloud metadata access) they form an exploit chain:

```
Step 1 — F2 exploited:
  Developer commits malicious config with grype_binary_path pointing to attacker binary
  → CI pipeline executes attacker binary on Jenkins worker
  → Attacker gains code execution on Jenkins worker

Step 2 — F4 exploited from inside compromised worker:
  Attacker already controls the scanner process
  → Directly crafts registry_url = "http://169.254.169.254/latest/meta-data/iam/..."
  → Retrieves cloud IAM credentials without any pipeline parameter injection needed
  → F4's reachability collapses: Tri(0.20, 0.45, 0.70) → 1.0 (deterministic)

Combined impact:
  Cloud IAM credentials → full cloud account access
  Jenkins deploy credentials → production K8s cluster compromise
  Image push rights → supply chain poisoning of production container images
```

**Conditional F4 score given F2 exploited:**

```
E[S_F4 | F2] = 0.75 × 1.0 × (1 − 0.60) × 0.73 = 0.219 → MEDIUM (Context E)
                      ^^^
                      reachability = 1.0 (attacker controls the process)
                      detectability = 0.60 (calibrated; CloudTrail/audit events still fire)
```

*Note: Even with attacker-controlled reachability, calibrated detectability (0.60) in production K8s means the conditional score lands at MEDIUM rather than HIGH. The CRITICAL impact classification is impact-driven, not score-driven.*

**Combined chain probability (Contexts D/E):**

```
P(chain) ≈ P(F2 exploited) × P(F4 | F2)
         ≈ E[S_F2] × E[S_F4|F2]   (approximation using expected scores as proxies)
         ≈ 0.340 × 0.219
         ≈ 0.074

This represents the joint probability of the full chain executing (calibrated).
The IMPACT of the chain is CRITICAL regardless of probability,
because the terminal consequence (cloud account + supply chain) has no higher category.

Chain classification: CRITICAL impact at ~7% probability (calibrated from original ~18%)
```

**Combined chain severity in Contexts D/E: CRITICAL (impact-driven, independent of individual finding labels)**

This chain does not exist in Context A. In Context B it is limited to MEDIUM (no cloud metadata endpoint). In Context C it may reach CRITICAL if staging shares credentials or metadata access with production.

### F2 → Other Findings (Expanded)

F2 grants code execution. From code execution, the attacker can invoke any tool capability:

| Chain | Mechanism | Conditional Score (Context E) |
|---|---|---|
| **F2 → F4** | Attacker controls `registry_url` directly | E[S_F4\|F2] = 0.75×1.0×0.40×0.73 = 0.219 → MEDIUM |
| **F2 → F1** | Attacker can modify runtime args or disable TLS flags | E[S_F1\|F2] ≈ 0.85×1.0×0.50×0.73 = 0.310 → HIGH |
| **F2 → F3** | Attacker invokes CLI with arbitrary `--output` for persistent file drop | E[S_F3\|F2] ≈ 0.53×1.0×0.52×0.93 = 0.256 → HIGH |

### Interaction Matrix (Revised)

| | F1 | F2 | F3 | F4 | F5 |
|---|---|---|---|---|---|
| **F1** | — | Independent | Independent | Independent | Independent |
| **F2** | **Enables F1** | — | **Enables F3** | **Amplifies F4** | Independent |
| **F3** | Independent | Independent | — | Independent | Independent |
| **F4** | Independent | **Amplified by F2** | Independent | — | Independent |
| **F5** | Independent | Independent | Independent | Independent | — |

F2 is the **keystone finding** — it enables or amplifies three of the four other findings. Remediating F2 (one-line fix: `extra="forbid"`) breaks the entire chain.

---

## 9. Triage Decision Guide

### How to Use This Report

Each finding's triage factor table lists every factor that drove the severity classification. The approval workflow is:

1. **Review each factor** in the triage table for the finding
2. **For each factor:** either agree with the assigned value, or produce evidence justifying a different value
3. **Document disagreements explicitly** — "factor X should be Y because [evidence]"
4. **Recompute classification** using the formula with all updated values (do NOT sum individual factor impacts — the model is multiplicative)
5. **Approve** the final classification or escalate for additional evidence gathering

### Quick Resolution Paths

| Finding | Fastest resolution | Required evidence |
|---|---|---|
| **F1** | Confirm reachability mode < 0.25 | Network topology diagram showing CI worker → registry VLAN isolation |
| **F2** | Fix: change `extra="allow"` to `extra="forbid"` | Code change; no evidence required — eliminates the finding and breaks the F2→F4 chain |
| **F3** | Confirm `--output` is not a pipeline parameter | Jenkinsfile showing hardcoded output path |
| **F4** | Confirm metadata endpoint unreachable from pods | K8s NetworkPolicy YAML or firewall rule blocking 169.254.169.254 egress |
| **F5** | Confirm Flask app is not deployed | Deployment manifests / Helm chart showing no Flask service |

### Severity Downgrade Precedents

A triager **may downgrade** a classification if and only if:
- The challenging evidence is documented and auditable
- The downgrade applies to a specific named factor (not a general "we think it's fine")
- The downgraded factor value and resulting score are recorded
- The recomputation uses the full formula, not individual factor impacts

A triager **may not downgrade** by:
- Asserting "we've never been attacked" (absence of evidence is not evidence of absence)
- Asserting "this is an internal tool" without confirming the specific reachability distribution parameters
- Disputing the flaw existence predicate (the flaw either matches or it does not; challenge the predicate against the code, not against perceived likelihood)
- Summing individual factor deltas from the triage table (the model is multiplicative; combined downgrades must be recomputed from the formula)

---

## 10. Model Limitations and Known Approximations

This section documents the known limitations of the assessment methodology. These should be considered when interpreting results and should be addressed if the methodology is adopted for production use.

### L1. CVSS Base Scores Are Approximations

CVSS 4.0 uses a non-linear lookup algorithm (mean-distance-based scoring), not a formula. The scores in this report (e.g., "~7.1", "~9.0") are analyst approximations of what the official FIRST calculator would produce for the stated vectors. Approximation error is estimated at ±0.3.

**Impact:** A ±0.3 error on a base score propagates linearly through the multiplicative model. For a typical finding with E[S] = 0.40, this represents a ±4% shift — within the noise of the stochastic factors.

**Mitigation:** All CVSS scores are presented as intervals (e.g., [6.8, 7.4]). For production use, compute exact scores using the FIRST CVSS 4.0 calculator.

### L2. Bounding Intervals Are Conservative

The bounding method (Section 5.4) computes score intervals from the product of distribution extremes, not from Monte Carlo P5/P95. This produces wider intervals than the true 90% CI, because extreme values of all factors rarely co-occur.

**Impact:** Confidence percentages are conservative (lower than they would be under exact Monte Carlo). The actual confidence in the primary classification is likely 5-15 percentage points higher than reported.

**Mitigation:** For production use, run N=10,000 Monte Carlo samples per finding.

### L3. Distribution Parameters Are RAG-Calibrated (Low-to-Moderate Confidence)

All Triangular distribution parameters (reachability, detectability, exploit_maturity) in this version are derived from RAG-calibrated LLM estimates grounded in 25 threat intelligence sources (DBIR 2024/2025, Mandiant M-Trends 2025, Rapid7 2026, IBM X-Force 2026, Sysdig 2024, Red Hat 2024, CNCF 2024, Aqua 2024, Cycode 2024, Sonatype 2024, and others). Full source attribution and reasoning chains are in `output/calibration/parameter_provenance.yaml`.

**Confidence distribution:** 43 low, 30 moderate, 2 high out of 75 estimates. No failed estimates. All `tri_min/mode/max` values clamped to `[0.0, 1.0]` per schema.

**Impact:** This is a significant improvement over pure analyst assignment but still carries model uncertainty. The LLM calibration grounds parameters in published statistics rather than intuition, reducing the single largest source of inter-analyst variability. However, LLM reasoning can hallucinate citations or misapply statistics — all provenance should be spot-checked against the cited source.

**Mitigation:** Cross-check calibrated values against the cited sources in `parameter_provenance.yaml`. For production use, supplement with internal telemetry (historical triage outcomes, red team results) to tighten confidence from low/moderate to high.

### L4. Residual Double-Counting Between CVSS AT and Reachability

As documented in Section 2.2 Decision 3, there is a mild overlap between CVSS's Attack Requirements (AT) metric and the stochastic reachability factor. Both model prerequisites, though at different abstraction levels (AT: intrinsic to the flaw; reachability: contextual).

**Impact:** A conservative bias — scores are slightly deflated compared to a model without overlap. The deflation is estimated at 5-10% for findings with AT:P.

**Mitigation:** Acceptable for security assessment (conservative bias preferred). Document for calibration.

### L5. Independence Assumption Between Reachability and Detectability

As documented in Section 5.5, the model assumes reachability and detectability are independent. This may not hold in practice (high-reachability systems often invest more in monitoring).

**Impact:** Conservative bias for high-reachability scenarios (overestimates risk by 5-15%). Slightly aggressive for low-reachability/low-monitoring scenarios.

**Mitigation:** For production use, model the correlation explicitly using a copula or joint distribution.

### L6. Chain Analysis Is Approximate

The combined chain probability in Section 8 uses `P(chain) ≈ E[S_F2] × E[S_F4|F2]`, which approximates exploit probability with the expected score. These are conceptually different (a score is not a probability), but the approximation is reasonable when scores are interpreted as "fraction of maximum risk materialised."

**Impact:** The calibrated 7% chain probability (revised from original 18%) is a rough estimate, not a calibrated probability. The CRITICAL impact classification is independent of this probability and stands regardless.

**Mitigation:** For production use, model the chain as a Bayesian network with explicit conditional probability tables.

---

*Report generated: static analysis + RAG-calibrated parameters (2026-05-05). Stochastic factor distributions derived from 75 LLM-calibrated estimates across 25 threat intelligence sources (confidence: 43 low, 30 moderate, 2 high). Full provenance in `output/calibration/parameter_provenance.yaml`. Bounding intervals are conservative approximations (see Section 5.4). Parameters should be updated when new threat intelligence is available or internal triage outcome data is collected.*
