# CVEs Analytics - Documentation Hub

**Version:** 2.1  
**Last Updated:** January 3, 2026

Welcome to the CVEs Analytics documentation. This tool provides advanced vulnerability risk assessment using Bayesian inference, kill-chain probability analysis, and realistic security control modeling.

---

## Quick Navigation by Role

### 🚀 New Users & Getting Started
Start here if you're new to CVEs Analytics:

- **[Technical Setup & Quick Start](TECHNICAL_SETUP.md)** (15-20 min)
  - Installation, dependencies, basic CLI usage
  - First vulnerability assessment walkthrough

- **[Demo Report & Examples](DEMO_REPORT.md)** (20-30 min)
  - Real-world vulnerability assessment examples
  - Three maturity levels: Initial, Managed, Optimizing
  - Practical insights and interpretations

### 🔍 Security Analysts & Risk Assessors
Core methodology and risk assessment:

- **[Bayesian Risk Assessment](BAYESIAN_RISK_ASSESSMENT.md)** (45-60 min)
  - How Bayesian inference improves vulnerability scoring
  - Exposure-conditional likelihood ratios
  - Exploitability gating and temporal adjustments

- **[Extended Kill-Chain Method](EXTENDED_KILL_CHAIN_METHOD.md)** (60-90 min)
  - Multi-stage attack probability calculation
  - Sequential Markov chain modeling
  - Bottleneck identification and remediation

- **[Scenario Comparison](SCENARIO_COMPARISON.md)** (15-20 min)
  - Side-by-side maturity level comparison
  - ROI insights for security investments

### ⚙️ Configuration & Operations
For teams configuring and operating the tool:

- **[Security Controls Guide](SECURITY_CONTROLS_GUIDE.md)** (40-50 min)
  - Control type system and probabilistic modeling
  - Likelihood ratio calibration
  - Maturity-based distributions and sector adjustments

### 💻 Developers & Contributors
Technical reference for extending the platform:

- **[Pipeline Components](PIPELINE_COMPONENTS.md)** (30-45 min)
  - Complete software architecture reference
  - All classes, methods, and APIs
  - Testing coverage and configuration files

### 📚 Academic & Research
Mathematical foundations and validation:

- **[Bayesian Risk Assessment - Appendix](BAYESIAN_RISK_ASSESSMENT.md#appendix-mathematical-foundations--academic-references)** (25-35 min)
  - Bayesian inference foundations
  - Academic references and proofs
  - Methodology limitations and assumptions
  - **Note:** Mathematical foundations now integrated as appendix in main methodology document

---

## Documentation Metrics

| Document | Type | Audience | Reading Time | Size |
|----------|------|----------|--------------|------|
| [TECHNICAL_SETUP.md](TECHNICAL_SETUP.md) | Setup Guide | New Users | 15-20 min | 18KB |
| [DEMO_REPORT.md](DEMO_REPORT.md) | Examples | All Users | 20-30 min | 19KB |
| [BAYESIAN_RISK_ASSESSMENT.md](BAYESIAN_RISK_ASSESSMENT.md) | Methodology + Appendix | Analysts/Researchers | 60-90 min | 42KB |
| [EXTENDED_KILL_CHAIN_METHOD.md](EXTENDED_KILL_CHAIN_METHOD.md) | Methodology | Architects | 60-90 min | 49KB |
| [SECURITY_CONTROLS_GUIDE.md](SECURITY_CONTROLS_GUIDE.md) | Configuration | Operators | 40-50 min | 45KB |
| [PIPELINE_COMPONENTS.md](PIPELINE_COMPONENTS.md) | Technical Ref | Developers | 30-45 min | 21KB |
| [SCENARIO_COMPARISON.md](SCENARIO_COMPARISON.md) | Examples | Managers | 15-20 min | 16KB |

**Total Documentation:** ~210KB across 7 active documents

**Archived:** Mathematical foundations merged into BAYESIAN_RISK_ASSESSMENT.md Appendix

---

## Recommended Reading Paths

### Path 1: Quick Start (45-60 minutes)
For users who want to get started quickly:
1. [TECHNICAL_SETUP.md](TECHNICAL_SETUP.md) - Install and configure
2. [DEMO_REPORT.md](DEMO_REPORT.md) - See examples
3. Start using the tool!

### Path 2: Security Analyst (2-3 hours)
For analysts who need to understand the methodology:
1. [DEMO_REPORT.md](DEMO_REPORT.md) - See what's possible
2. [BAYESIAN_RISK_ASSESSMENT.md](BAYESIAN_RISK_ASSESSMENT.md) - Learn the theory
3. [SECURITY_CONTROLS_GUIDE.md](SECURITY_CONTROLS_GUIDE.md) - Configure for your org
4. [EXTENDED_KILL_CHAIN_METHOD.md](EXTENDED_KILL_CHAIN_METHOD.md) - Advanced analysis

### Path 3: Developer (1-2 hours)
For developers extending or contributing:
1. [TECHNICAL_SETUP.md](TECHNICAL_SETUP.md) - Set up dev environment
2. [PIPELINE_COMPONENTS.md](PIPELINE_COMPONENTS.md) - Understand architecture
3. [BAYESIAN_RISK_ASSESSMENT.md](BAYESIAN_RISK_ASSESSMENT.md) - Core methodology
4. Review source code with API reference

### Path 4: Researcher (3-4 hours)
For academics validating or extending methodology:
1. [BAYESIAN_RISK_ASSESSMENT.md](BAYESIAN_RISK_ASSESSMENT.md) - Methodology + Mathematical Appendix
2. [EXTENDED_KILL_CHAIN_METHOD.md](EXTENDED_KILL_CHAIN_METHOD.md) - Kill-chain model
3. [DEMO_REPORT.md](DEMO_REPORT.md) - Validation examples

---

## Additional Resources

- **[GitHub Repository](https://github.com/dominikmi/cves_analytics)** - Source code and issues
- **[Contributing Guide](../CONTRIBUTING.md)** - How to contribute
- **[License](../LICENSE)** - MIT License
- **[Changelog](../CHANGELOG.md)** - Version history

---

## Document Status

| Status | Documents |
|--------|-----------|
| **Active** | All 7 documents listed above |
| **Archived** | `archive/MATHEMATICAL_REFERENCE.md` - Merged into BAYESIAN_RISK_ASSESSMENT.md Appendix |
| **Archived** | `archive/CONTROL_TYPES_VALIDATION_RESULTS.md` - Historical test results (Jan 2, 2026) |

---

**Need Help?** 
- Open an issue on [GitHub](https://github.com/dominikmi/cves_analytics/issues)
- Check existing documentation for your use case
- Review [DEMO_REPORT.md](DEMO_REPORT.md) for practical examples
