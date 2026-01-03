# CVEs Analytics - Technical Setup & Quick Start

**Version:** 2.2  
**Last Updated:** January 3, 2026  
**Document Type:** Installation & Setup Guide  
**Estimated Reading Time:** 15-20 minutes

## Intended Audience

**Primary:** New users, system administrators, DevOps engineers  
**Secondary:** Developers setting up development environment

**Prerequisites:**
- Python 3.12+ installed
- Basic command-line experience
- Docker installed (for container scanning features)
- Git installed

**What You'll Learn:**
- How to install and configure CVEs Analytics
- Basic CLI usage and examples
- System requirements and dependencies
- Quick start guide for first vulnerability assessment

---

A comprehensive Python application for CVE (Common Vulnerabilities and Exposures) data analytics, vulnerability assessment, and Docker image scanning with advanced Bayesian risk modeling and kill-chain probability analysis.

## 📋 Features

### Core Functionality

1. **CVE Data Management**
   - **Primary: [CVSS-BT dataset](https://github.com/t0sche/cvss-bt)** - Pre-computed CVSS with exploitability
   - Fallback: CVE v5 data from NVD (National Vulnerability Database)
   - Parse and store CVSS v2, v3, and v4 metrics
   - Extract CWE (Common Weakness Enumeration) information
   - Merge with EPSS (Exploit Prediction Scoring System) scores
   - Integrate KEV (Known Exploited Vulnerabilities) data
   - Exploit availability tracking (ExploitDB, Metasploit, Nuclei, GitHub PoC)

2. **Vulnerability Analysis**
   - Attack chain analysis using graph-based approach
   - **MITRE ATT&CK tactic mapping** (CWE/impact -> tactic, displayed in reports)
   - Vulnerability enrichment with CISAGOV data
   - CWE metadata retrieval and analysis

3. **Bayesian Risk Assessment**
   - Principled probabilistic risk scoring using Bayes' theorem
   - EPSS as prior probability, updated with environmental evidence
   - Configurable likelihood ratios for security controls, exposure, CVSS vectors
   - **Exploit maturity LRs** from CVSS-BT (Metasploit: ~2.5, ExploitDB: ~2.0, Nuclei: ~1.8, PoC: ~1.5)
   - Uncertainty quantification with 95% credible intervals
   - Exploitability gating to prevent false risk inflation
   - **Attack scenarios and remediation focused on Bayesian-critical vulns only**

4. **Kill-Chain Probability Analysis** ✨ NEW
   - **Multi-component application modeling** - Analyzes complete applications (e.g., 7-component financial platform)
   - Industry-specific application templates from config (ecommerce, financial services, SaaS, consulting, data analytics)
   - Sequential stage probability calculation (Initial Access -> Execution -> Lateral Movement -> Objective)
   - Component-level vulnerability assessment with actual CVSS vector analysis
   - Docker security posture integration
   - **Security control penalty modeling** - Bad practices increase risk (LR > 1.0), good practices reduce risk (LR < 1.0)
   - Security control effectiveness modeling per stage
   - Bottleneck identification and critical path analysis
   - Threat level categorization (Critical/High/Medium/Low/Negligible)
   - **Dynamic key insights** - Context-aware recommendations based on actual probabilities
   - **Stage-specific remediation actions** - Targeted recommendations for each high-risk stage
   - Adaptive analysis of perimeter defenses, network isolation, and security impact

5. **NLP Vulnerability Extraction**
   - Rule-based pattern matching on CVE descriptions
   - Attack type detection (RCE, SQLi, XSS, DoS, etc.)
   - Context extraction (auth requirements, user interaction)
   - Confidence scoring based on pattern matches
   - Integration with Bayesian risk as weak signals
   - **Attack categories displayed in vulnerability reports**

6. **Docker Image Scanning**
   - Scan Docker images using Grype
   - Support for public and private registries
   - Vulnerability detection and reporting
   - Batch scanning from CSV lists
   - **ARM64 compatible** - All images scannable on Apple Silicon

7. **Simulation & Scenario Generation**
   - Generate realistic IT environment scenarios
   - Configurable organization size and reach
   - Industry-specific architecture design
   - Network topology and security posture generation
   - Binary security controls with maturity-based generation
   - **Correlated security controls generation** ✨ NEW - Realistic control patterns based on industry and maturity
   - System configuration simulation

8. **Comprehensive Reporting**
   - Executive summary with Bayesian risk distribution
   - **Multi-component kill-chain probability analysis** ✨ NEW - Shows complete application architecture (7+ components)
   - **Dynamic key insights** - Bottleneck analysis, security impact, network isolation, threat level
   - **Stage-specific remediation actions** - Targeted recommendations for Initial Access, Execution, Lateral Movement, and Objective Achievement
   - Component-level attack surface analysis across application tiers
   - Risk prioritization by exploitation probability
   - Remediation roadmap based on Bayesian risk categories
   - Attack paths filtered to Bayesian-critical vulnerabilities
   - NLP attack categories in top vulnerability details
   - Team-based Bayesian risk heatmap
   - **[View Demo Report](DEMO_REPORT.md)**

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **Docker** - Running daemon required for image scanning
- **Grype** - Vulnerability scanner ([install guide](https://github.com/anchore/grype#installation))

```bash
# Install Grype on macOS
brew install grype

# Or download binary
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### Installation

```bash
# Clone the repository
git clone https://github.com/dominikmi/cves_analytics.git
cd cves_analytics

# Install dependencies using uv
uv sync

# Activate virtual environment
source .venv/bin/activate
```

### Basic Usage

#### Run the Full Pipeline (Recommended)

The easiest way to use this tool is to run the complete vulnerability assessment pipeline:

```bash
# Basic run with default settings (small environment)
python -m src.cli.run_pipeline

# Customize the simulated environment
python -m src.cli.run_pipeline \
  --org-size mid \
  --org-reach regional \
  --industry financial-services \
  --environment prod \
  --output-dir output/reports
```

**Available options:**

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `--org-size` | `small`, `mid`, `large`, `enterprise` | `small` | Organization size |
| `--org-reach` | `local`, `regional`, `national`, `global` | `local` | Geographic reach |
| `--industry` | `financial-services`, `healthcare`, `technology`, `retail`, `manufacturing` | `financial-services` | Industry type |
| `--environment` | `dev`, `staging`, `prod` | `prod` | Environment type |
| `--output-dir` | Any path | `output/` | Output directory for reports |

**What the pipeline does:**

1. **Generates a simulated IT environment** - Creates realistic services (nginx, postgres, redis, etc.) with security controls
2. **Scans Docker images** - Uses Grype to find vulnerabilities in each service's container image
3. **Enriches with threat intelligence** - Adds CVSS-BT exploit data, EPSS scores, KEV status, CWE details
4. **Performs Bayesian risk assessment** - Calculates exploitation probability considering your security controls
5. **Calculates kill-chain probabilities** ✨ NEW - Analyzes multi-stage attack success probability
6. **Generates a comprehensive report** - Creates a prioritized vulnerability report with kill-chain analysis

**Output:**
- Report saved to `output/report_YYYY-MM-DD_HH-MM-SS.txt`
- See [DEMO_REPORT.md](DEMO_REPORT.md) for an example with kill-chain analysis

> ⚠️ **Performance Warning:** Larger environments scan more Docker images and process more data.
>
> | Org Size | Services | Estimated Time | Docker Images |
> |----------|----------|----------------|---------------|
> | `small` | 5-8 | 3-5 minutes | ~7 images |
> | `mid` | 10-15 | 8-15 minutes | ~15 images |
> | `large` | 20-30 | 20-40 minutes | ~30 images |
> | `enterprise` | 40+ | 45+ minutes | ~50+ images |
>
> First run downloads ~2GB of CVE data (cached for subsequent runs).

---

## 📦 Project Structure

```
cves_analytics/
├── src/                          # Main source code
│   ├── core/                     # Core business logic
│   │   ├── bayesian_risk.py     # Bayesian risk assessment engine
│   │   ├── kill_chain_calculator.py  # Kill-chain probability analysis ✨ NEW
│   │   ├── risk_scoring.py      # Risk scoring (delegates to Bayesian)
│   │   ├── cvss_parser.py       # CVSS metric parsing
│   │   ├── cvss_vector_reassessment.py  # CVSS-based severity reassessment
│   │   ├── cvev5_processor.py   # CVE v5 data processing
│   │   ├── epss_processor.py    # EPSS score handling
│   │   ├── kev_processor.py     # Known exploited vulnerabilities
│   │   ├── cwe_processor.py     # CWE metadata processing
│   │   ├── vulnrichment_processor.py  # Vulnerability enrichment
│   │   ├── docker_scanner.py    # Docker image scanning
│   │   ├── vulnerability_analyzer.py  # Attack chain analysis
│   │   └── nlp_extractor.py     # NLP feature extraction
│   ├── simulation/               # Scenario generation
│   │   ├── application_templates.py  # Multi-component app templates ✨ NEW
│   │   ├── scenario_config.py   # Configuration constants
│   │   ├── scenario_generator.py # Scenario generation
│   │   ├── security_controls.py # Security controls model
│   │   └── system_simulator.py  # System configuration
│   ├── analysis/                 # Analysis modules
│   │   └── attack_scenario_analyzer.py  # Attack scenario analysis
│   ├── utils/                    # Shared utilities
│   │   ├── config.py            # Configuration management
│   │   ├── logging_config.py    # Centralized logging
│   │   └── error_handling.py    # Error handling
│   └── cli/                      # CLI entry points
│       ├── run_pipeline.py      # Main pipeline orchestrator
│       ├── pipeline.py          # Pipeline implementation
│       ├── pipeline_steps/      # Individual pipeline steps
│       │   ├── scenario_generator.py
│       │   ├── docker_scanner.py
│       │   ├── data_enricher.py
│       │   ├── attack_analyzer.py  # Includes kill-chain integration
│       │   └── report_generator.py # Includes kill-chain reporting
│       ├── create_dataset.py    # Dataset creation
│       ├── scan_images.py       # Docker scanning
│       └── generate_simulation.py # Scenario generation
├── tests/                        # Unit tests (121+ test cases)
├── config/                       # Configuration files
│   ├── security_controls.yaml   # Security controls configuration
│   └── services.yaml            # Service and application templates
├── docs/                         # Technical documentation
│   ├── BAYESIAN_RISK_ASSESSMENT.md
│   ├── EXTENDED_KILL_CHAIN_METHOD.md  # Kill-chain methodology ✨
│   ├── MATHEMATICAL_REFERENCE.md
│   └── SECURITY_CONTROLS_GUIDE.md
└── pyproject.toml               # Project configuration
```

## 🎯 Key Features in Detail

### Kill-Chain Probability Analysis ✨ NEW

The kill-chain calculator models multi-stage attack success probability:

```python
from src.core.kill_chain_calculator import KillChainCalculator
from src.simulation.application_templates import get_application_templates

calculator = KillChainCalculator()
templates = get_application_templates()

# Analyze an e-commerce application
ecommerce_app = templates["ecommerce"]
result = calculator.calculate_kill_chain_probability(
    application=ecommerce_app,
    vulnerabilities=vuln_df,
    security_controls={"waf": True, "mfa": True, "network_segmentation": True},
    docker_security_good=True
)

print(f"Total Probability: {result.total_probability:.1%}")
print(f"Threat Level: {result.threat_level}")
print(f"Bottleneck Stage: {result.bottleneck_stage}")
print(f"Critical Path: {result.critical_path}")

for stage in result.stages:
    print(f"{stage.name}: {stage.conditional_probability:.1%}")
```

**Kill-Chain Stages:**
1. **Initial Access** - Probability of gaining initial foothold
2. **Execution** - Probability of executing malicious code
3. **Lateral Movement** - Probability of moving to other components
4. **Objective Achievement** - Probability of achieving attacker goals

**Application Templates:**
- E-Commerce Platform
- Financial Services Platform
- Consulting Services Platform
- SaaS Platform
- Data Analytics Platform

See [docs/EXTENDED_KILL_CHAIN_METHOD.md](docs/EXTENDED_KILL_CHAIN_METHOD.md) for methodology details.

### Bayesian Risk Assessment

Principled probabilistic risk assessment using Bayes' theorem:

```python
from src.core.bayesian_risk import BayesianRiskAssessor, SecurityControlsInput

assessor = BayesianRiskAssessor()

controls = SecurityControlsInput(
    network_segmentation=True,
    waf=True,
    mfa=True,
    edr_xdr=False,
)

result = assessor.assess(
    epss_score=0.083,  # 8.3% EPSS
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvss_score=9.8,
    exposure="internet-facing",
    security_controls=controls,
    threat_indicators={"has_public_exploit": True},
    asset_criticality="critical",
)

print(f"Prior (EPSS): {result.prior_probability:.1%}")
print(f"Posterior: {result.posterior_probability:.1%}")
print(f"95% CI: [{result.credible_interval_low:.1%}, {result.credible_interval_high:.1%}]")
print(f"Risk Category: {result.risk_category}")
```

**Key Concepts:**

- **Likelihood Ratios (LRs)**: Quantify how evidence changes belief
  - LR < 1: Reduces exploitation probability (e.g., WAF -> LR~0.4)
  - LR > 1: Increases exploitation probability (e.g., public exploit -> LR~2.0)
  - **Note:** LR values are informed heuristics requiring calibration - see methodology docs
  
- **Exploitability Gating**: Amplification only applies when exploitation is plausible
  - Plausible if: EPSS >= 5% OR known exploit exists
  
- **Uncertainty Quantification**: 95% credible intervals for all risk estimates

See [docs/BAYESIAN_RISK_ASSESSMENT.md](docs/BAYESIAN_RISK_ASSESSMENT.md) for details.

> **Note:** The Bayesian risk assessment uses heuristic LR values that should be calibrated for your organization. See [BAYESIAN_RISK_ASSESSMENT.md](docs/BAYESIAN_RISK_ASSESSMENT.md) and [SECURITY_CONTROLS_GUIDE.md](docs/SECURITY_CONTROLS_GUIDE.md) for detailed methodology and validation guidance.

## 🧪 Testing

Run comprehensive unit tests:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_kill_chain_calculator.py

# Run with verbose output
pytest tests/ -v
```

**Test Coverage**: 121+ test cases across 13 test files
- CVSS Parser: 10 tests
- Bayesian Risk: 15+ tests
- Kill-Chain Calculator: 8 tests ✨ NEW
- Application Templates: 5 tests ✨ NEW
- NLP Extractor: 30 tests
- Configuration: 8 tests
- And more...

## 📚 Documentation

- **[DEMO_REPORT.md](DEMO_REPORT.md)** - Example vulnerability assessment report with kill-chain analysis
- **[docs/BAYESIAN_RISK_ASSESSMENT.md](docs/BAYESIAN_RISK_ASSESSMENT.md)** - Bayesian methodology and mathematical foundations
- **[docs/EXTENDED_KILL_CHAIN_METHOD.md](docs/EXTENDED_KILL_CHAIN_METHOD.md)** - Kill-chain probability analysis ✨
- **[docs/SECURITY_CONTROLS_GUIDE.md](docs/SECURITY_CONTROLS_GUIDE.md)** - Security controls configuration
- **[TEST_COVERAGE.md](TEST_COVERAGE.md)** - Test coverage details

## 🤝 Contributing

When adding new features:
1. Follow existing code structure
2. Add comprehensive type hints
3. Include docstrings
4. Add unit tests
5. Ensure 100% Ruff compliance
6. Update documentation

## 📄 License

MIT License - Copyright (c) 2025 Dominik Miklaszewski

See [LICENSE](LICENSE) for full details.

## 🎯 Roadmap

### Current ✅
- ✅ CVE data management
- ✅ EPSS and KEV integration
- ✅ CWE integration (local lookup)
- ✅ Docker image scanning (ARM64 compatible)
- ✅ Vulnerability analysis
- ✅ Scenario generation
- ✅ Bayesian risk assessment
- ✅ Security controls modeling
- ✅ **Correlated security controls generation** ✨ NEW
- ✅ Uncertainty quantification
- ✅ NLP vulnerability extraction
- ✅ Bayesian-focused reporting
- ✅ Attack scenarios filtered by Bayesian risk
- ✅ **Kill-chain probability analysis** ✨ NEW
- ✅ **Multi-component application templates** ✨ NEW
- ✅ **Stage-by-stage attack modeling** ✨ NEW

### Planned 🚧
- [ ] Interactive kill-chain visualization
- [ ] Custom application template builder
- [ ] Advanced attack chain analysis
- [ ] PDF report generation
- [ ] Web dashboard
- [ ] API server
- [ ] Custom likelihood ratio configuration UI
- [ ] Data storage in DuckDB

## 📊 Project Statistics

- **25+ Modules**: Organized by responsibility
- **6,000+ Lines**: Clean, production-ready code
- **121+ Tests**: Comprehensive test coverage
- **100% Type Hints**: Full type safety
- **100% Ruff Compliant**: Code quality assured
- **Bayesian Risk Engine**: Principled probabilistic assessment
- **Kill-Chain Calculator**: Multi-stage attack probability modeling ✨
- **NLP Feature Extraction**: Attack category detection from CVE descriptions
- **ARM64 Compatible**: All Docker images scannable on Apple Silicon

## 🌟 What Makes This Different

1. **Bayesian Risk Assessment** - Move beyond simple CVSS scores to probabilistic risk modeling
2. **Kill-Chain Probability Analysis** ✨ - Understand multi-stage attack success probability with dynamic insights
3. **Correlated Security Controls** ✨ - Realistic control patterns based on industry standards and maturity levels
4. **Exploitability Gating** - Prevent false risk inflation for low-probability vulnerabilities
5. **Uncertainty Quantification** - Know the confidence in your risk estimates
6. **Security Controls Integration** - Model real-world defensive measures with correlation rules
7. **Application-Centric Analysis** - Analyze complete multi-component applications with context-aware recommendations
8. **Config-Driven** - All likelihood ratios and controls defined in YAML
9. **Production-Ready** - Type-safe, tested, and Ruff-compliant code

---

**Ready to get started?** Run `python -m src.cli.run_pipeline` and see the [DEMO_REPORT.md](DEMO_REPORT.md) for what to expect!
