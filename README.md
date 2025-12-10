# CVEs Analytics

A comprehensive Python application for CVE (Common Vulnerabilities and Exposures) data analytics, vulnerability assessment, and Docker image scanning with advanced simulation capabilities.

## 📋 Features

### Core Functionality
1. **CVE Data Management**
   - Download CVE data from NVD (National Vulnerability Database)
   - Parse and store CVSS v2 and v3 metrics
   - Extract CWE (Common Weakness Enumeration) information
   - Merge with EPSS (Exploit Prediction Scoring System) scores
   - Integrate KEV (Known Exploited Vulnerabilities) data

2. **Vulnerability Analysis**
   - Attack chain analysis using graph-based approach
   - **MITRE ATT&CK tactic mapping** (CWE/impact → tactic, displayed in reports)
   - Vulnerability enrichment with CISAGOV data
   - CWE metadata retrieval and analysis

3. **Bayesian Risk Assessment**
   - Principled probabilistic risk scoring using Bayes' theorem
   - EPSS as prior probability, updated with environmental evidence
   - Configurable likelihood ratios for security controls, exposure, CVSS vectors
   - Uncertainty quantification with 95% credible intervals
   - Exploitability gating to prevent false risk inflation
   - **Attack scenarios and remediation focused on Bayesian-critical vulns only**

4. **NLP Vulnerability Extraction**
   - Rule-based pattern matching on CVE descriptions
   - Attack type detection (RCE, SQLi, XSS, DoS, etc.)
   - Context extraction (auth requirements, user interaction)
   - Confidence scoring based on pattern matches
   - Integration with Bayesian risk as weak signals
   - **Attack categories displayed in vulnerability reports**

5. **Docker Image Scanning**
   - Scan Docker images using Grype
   - Support for public and private registries
   - Vulnerability detection and reporting
   - Batch scanning from CSV lists

6. **Simulation & Scenario Generation**
   - Generate realistic IT environment scenarios
   - Configurable organization size and reach
   - Industry-specific architecture design
   - Network topology and security posture generation
   - Binary security controls with maturity-based generation
   - System configuration simulation

7. **Bayesian-Focused Reporting**
   - Executive summary with Bayesian risk distribution
   - Risk prioritization by exploitation probability
   - Remediation roadmap based on Bayesian risk categories
   - Attack paths filtered to Bayesian-critical vulnerabilities
   - NLP attack categories in top vulnerability details
   - Team-based Bayesian risk heatmap
   - **[View Demo Report](DEMO_REPORT.md)**

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd cves_analytics

# Install dependencies using uv
uv sync
```

### Basic Usage

#### Create CVE Dataset

```bash
python -m src.cli.create_dataset \
  --start_year 2020 \
  --end_year 2024 \
  --data_path ./data \
  --output_path ./output
```

This will:
1. Download NVD CVE data for specified years
2. Download EPSS scores
3. Merge with KEV data
4. Enrich with CWE details
5. Export to CSV

#### Scan Docker Images

```bash
# Scan single image
python -m src.cli.scan_images --image ubuntu:latest

# Scan from registry
python -m src.cli.scan_images --registry https://registry.example.com

# Scan from CSV list
python -m src.cli.scan_images \
  --list_of_images images.csv \
  --output results.csv
```

#### Generate Simulation Scenarios

```bash
python -m src.cli.generate_simulation \
  --size mid \
  --reach global \
  --industry financial-services \
  --environment prod \
  --format json
```

## 📦 Project Structure

```
cves_analytics/
├── src/                          # Main source code
│   ├── core/                     # Core business logic
│   │   ├── bayesian_risk.py     # Bayesian risk assessment engine
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
│   │   ├── scenario_config.py   # Configuration constants
│   │   ├── scenario_generator.py # Scenario generation
│   │   ├── security_controls.py # Security controls model
│   │   └── system_simulator.py  # System configuration
│   ├── utils/                    # Shared utilities
│   │   ├── config.py            # Configuration management
│   │   ├── logging_config.py    # Centralized logging
│   │   └── error_handling.py    # Error handling
│   └── cli/                      # CLI entry points
│       ├── create_dataset.py    # Dataset creation
│       ├── scan_images.py       # Docker scanning
│       └── generate_simulation.py # Scenario generation
├── tests/                        # Unit tests (48 test cases)
├── notebooks/                    # Jupyter notebooks
├── config/                       # Configuration files
└── pyproject.toml               # Project configuration
```

## 🔧 Core Modules

### CVSS Parser (`src/core/cvss_parser.py`)

Parse CVSS v2 and v3 metrics from CVE impact data.

```python
from src.core.cvss_parser import CVSSParser

impact_data = {
    "baseMetricV3": {
        "cvssV3": {
            "version": "3.1",
            "baseScore": 7.5,
            "baseSeverity": "High",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }
    }
}

metrics = CVSSParser.parse_cvss(impact_data)
print(f"Base Score: {metrics['base_score']}")
print(f"Severity: {metrics['base_severity']}")
```

### NVD Processor (`src/core/nvd_processor.py`)

Download and process NVD CVE data.

```python
from src.core.nvd_processor import (
    download_nvd_cve_data,
    unzip_files,
    load_nvd_cve_data
)

# Download data
download_nvd_cve_data(2020, 2024, "./data")

# Unzip files
unzip_files("./data")

# Load into DataFrame
cves_df = load_nvd_cve_data(2020, 2024, "./data")
print(f"Loaded {len(cves_df)} CVEs")
```

### EPSS Processor (`src/core/epss_processor.py`)

Download and process EPSS scores.

```python
from src.core.epss_processor import download_epss_scores

# Download EPSS scores for today
epss_file = download_epss_scores("2025-12-06", "./data")

# Load and process
import pandas as pd
epss_scores = pd.read_csv(epss_file, skiprows=1)
print(f"Loaded {len(epss_scores)} EPSS scores")
```

### Docker Scanner (`src/core/docker_scanner.py`)

Scan Docker images for vulnerabilities.

```python
from src.core.docker_scanner import DockerImageScanner

scanner = DockerImageScanner(registry_url="https://registry.example.com")

# Scan single image
results = scanner.scan_image_with_grype("ubuntu:latest")
print(f"Found {len(results)} vulnerabilities")

# Get images from registry
images = scanner.list_images_and_tags()
for repo, tags in images.items():
    print(f"Repository: {repo}, Tags: {tags}")
```

### Vulnerability Analyzer (`src/core/vulnerability_analyzer.py`)

Analyze attack chains and vulnerability relationships.

```python
from src.core.vulnerability_analyzer import AttackChainAnalyzer
import pandas as pd

# Create DataFrame with CVE data
cve_data = pd.DataFrame({
    'cve_id': ['CVE-2021-1', 'CVE-2021-2'],
    'impact': ['RCE', 'Privilege Escalation'],
    'severity': ['Critical', 'High'],
    'cwe': ['CWE-79', 'CWE-79']
})

analyzer = AttackChainAnalyzer(cve_data)

# Find attack chains
chains = analyzer.find_unique_chains()
print(f"Found {len(chains)} attack chains")

# Get graph statistics
stats = analyzer.get_graph_statistics()
print(f"Graph density: {stats['density']}")
```

### Bayesian Risk Assessor (`src/core/bayesian_risk.py`)

Principled probabilistic risk assessment using Bayes' theorem.

```python
from src.core.bayesian_risk import BayesianRiskAssessor, SecurityControlsInput

assessor = BayesianRiskAssessor()

# Define security controls in place
controls = SecurityControlsInput(
    network_segmentation=True,
    waf=True,
    mfa=True,
    edr_xdr=False,
)

# Assess a vulnerability
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
print(f"Explanation: {result.explanation}")
```

#### Key Concepts

**Likelihood Ratios (LRs)**: Quantify how evidence changes belief
- LR < 1: Evidence reduces exploitation probability (e.g., WAF present → LR=0.4)
- LR > 1: Evidence increases exploitation probability (e.g., public exploit → LR=2.0)
- LR = 1: Uninformative evidence

**Exploitability Gating**: Amplification factors only apply when exploitation is plausible
- Plausible if: EPSS ≥ 5% OR known exploit exists
- Prevents low-EPSS vulnerabilities from being falsely inflated

**Security Controls** (reduce risk):
| Control | LR | Risk Reduction |
|---------|-----|----------------|
| Air-gapped | 0.05 | 95% |
| Network Segmentation | 0.3 | 70% |
| MFA | 0.3 | 70% |
| WAF | 0.4 | 60% |
| EDR/XDR | 0.4 | 60% |

**Threat Indicators** (increase risk):
| Indicator | LR | Risk Increase |
|-----------|-----|---------------|
| Weaponized | 4.0 | 300% |
| KEV Listed | 3.0 | 200% |
| Metasploit Module | 2.5 | 150% |
| Public Exploit | 2.0 | 100% |

### NLP Feature Extractor (`src/core/nlp_extractor.py`)

Extract vulnerability features from CVE descriptions using rule-based NLP.

```python
from src.core.nlp_extractor import VulnDescriptionExtractor, enrich_with_nlp_features

extractor = VulnDescriptionExtractor()

# Extract features from a description
desc = "A remote code execution vulnerability allows attackers to execute arbitrary code."
features = extractor.extract(desc)

print(f"Attack Types: {[at.value for at, _ in features.attack_types]}")
print(f"Confidence: {features.confidence:.2f}")
print(f"Network Accessible: {features.is_network_accessible}")
print(f"Requires Auth: {features.requires_authentication}")

# Enrich a DataFrame with NLP features
import polars as pl
df = pl.DataFrame({
    "cve_id": ["CVE-2021-44228"],
    "description": ["Apache Log4j2 allows remote code execution via JNDI lookups."]
})
enriched_df = enrich_with_nlp_features(df)
print(enriched_df.columns)  # Includes nlp_attack_types, nlp_confidence, etc.
```

#### Detected Attack Types

| Attack Type | Example Patterns |
|-------------|------------------|
| Remote Code Execution | "RCE", "execute arbitrary code" |
| SQL Injection | "SQL injection", "SQLi" |
| Cross-Site Scripting | "XSS", "cross-site scripting" |
| Command Injection | "command injection", "arbitrary command" |
| Buffer Overflow | "buffer overflow", "out-of-bounds" |
| Privilege Escalation | "privilege escalation", "elevate privileges" |
| Information Disclosure | "information disclosure", "data leak" |
| Denial of Service | "DoS", "denial of service", "crash" |
| Authentication Bypass | "authentication bypass", "bypass auth" |

#### NLP Likelihood Ratios

NLP-extracted features are used as weak signals in Bayesian risk assessment:

| Attack Type | LR | Rationale |
|-------------|-----|----------|
| Remote Code Execution | 1.15 | High exploitability |
| Command Injection | 1.12 | Often weaponized |
| SQL Injection | 1.10 | Common attack vector |
| Buffer Overflow | 1.08 | Memory corruption risk |
| Denial of Service | 0.98 | Lower direct impact |
| Open Redirect | 0.95 | Lower severity |

**Confidence Gating**: NLP LRs only apply when `nlp_confidence >= 0.3` to avoid noise.

### Scenario Generator (`src/simulation/scenario_generator.py`)

Generate realistic IT environment scenarios with security controls.

```python
from src.simulation.scenario_generator import ScenarioGenerator

generator = ScenarioGenerator()

# Generate scenario
scenario = generator.generate_scenario(
    size="mid",
    reach="global",
    industry="financial-services",
    environment_type="prod",
    output_format="json"
)

print(f"Generated scenario: {scenario['scenario_id']}")
print(f"Company: {scenario['company_name']}")
print(f"Services: {len(scenario['services'])}")
print(f"Security Maturity: {scenario['security_maturity']}")
print(f"Active Controls: {[k for k, v in scenario['security_controls'].items() if v]}")
```

## 🧪 Testing

Run comprehensive unit tests:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_cvss_parser.py

# Run specific test class
pytest tests/test_cvss_parser.py::TestCVSSParser

# Run with verbose output
pytest tests/ -v
```

**Test Coverage**: 108 test cases across 11 test files
- CVSS Parser: 10 tests
- Configuration: 8 tests
- Logging: 7 tests
- Error Handling: 8 tests
- Vulnerability Analyzer: 8 tests
- Scenario Configuration: 7 tests
- NLP Extractor: 30 tests
- Pipeline Structure: 4 tests
- Bayesian Risk: Additional tests

## ⚙️ Configuration

### Using Configuration Manager

```python
from src.utils.config import get_config

config = get_config()

# Get value with default
timeout = config.get("api.timeout", default=30)

# Get environment variable
api_key = config.get_env("API_KEY")

# Get as Path object
log_dir = config.get_path("logging.directory", default="/tmp/logs")
```

### Configuration File (config/config.yaml)

```yaml
api:
  timeout: 30
  retries: 3

logging:
  level: INFO
  directory: ./logs

database:
  host: localhost
  port: 5432
```

## 📝 Logging

### Using Centralized Logging

```python
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

logger.info("Processing CVE data")
logger.warning("High severity vulnerability found")
logger.error("Failed to download data")
```

### Logging Configuration

Logs are automatically created in `./logs/` directory with both console and file output.

## 🛡️ Error Handling

### Using Error Handler Decorator

```python
from src.utils.error_handling import error_handler

@error_handler(default_return=None)
def process_cve_data(cve_id):
    # Your code here
    return result
```

The decorator automatically:
- Catches exceptions
- Logs errors with context
- Returns default value on error
- Preserves function metadata

## 📊 Data Flow

### CVE Dataset Creation

```
NVD Data Download
    ↓
Unzip Files
    ↓
Parse CVE Data
    ↓
Download EPSS Scores
    ↓
Merge with KEV Data
    ↓
Enrich with CWE Details
    ↓
Export to CSV
```

### Docker Image Scanning

```
Registry/Image Input
    ↓
List Images (if registry)
    ↓
Scan with Grype
    ↓
Parse Results
    ↓
Export to CSV
```

### Scenario Generation

```
Input Parameters
    ↓
Generate Network Topology
    ↓
Design Architecture
    ↓
Generate Security Posture
    ↓
Create Network Policies
    ↓
Export Scenario
```

## 🔍 Examples

### Example 1: Complete CVE Analysis Pipeline

```python
from src.core.nvd_processor import download_nvd_cve_data, load_nvd_cve_data
from src.core.epss_processor import download_epss_scores
from src.core.cwe_processor import get_cwe_name_and_description
import pandas as pd

# Download and load CVE data
download_nvd_cve_data(2023, 2024, "./data")
cves_df = load_nvd_cve_data(2023, 2024, "./data")

# Add EPSS scores
epss_file = download_epss_scores("2025-12-06", "./data")
epss_df = pd.read_csv(epss_file, skiprows=1)
cves_with_epss = pd.merge(cves_df, epss_df, left_on="cve_id", right_on="cve")

# Add CWE details
cves_with_epss["cwe_details"] = cves_with_epss["cwe_id"].apply(
    get_cwe_name_and_description
)

# Save results
cves_with_epss.to_csv("cves_enriched.csv", index=False)
print(f"Processed {len(cves_with_epss)} CVEs")
```

### Example 2: Docker Image Vulnerability Scanning

```python
from src.core.docker_scanner import DockerImageScanner
import pandas as pd

scanner = DockerImageScanner()

# Scan multiple images
images = ["ubuntu:22.04", "nginx:latest", "python:3.12"]
all_results = []

for image in images:
    results = scanner.scan_image_with_grype(image)
    all_results.append(results)

# Combine and save
combined = pd.concat(all_results, ignore_index=True)
combined.to_csv("scan_results.csv", index=False)
print(f"Found {len(combined)} vulnerabilities across {len(images)} images")
```

### Example 3: Vulnerability Attack Chain Analysis

```python
from src.core.vulnerability_analyzer import AttackChainAnalyzer
import pandas as pd

# Load CVE data
cves_df = pd.read_csv("cves_data.csv")

# Analyze attack chains
analyzer = AttackChainAnalyzer(cves_df)

# Find critical paths
critical_paths = analyzer.get_critical_paths(min_length=3)
print(f"Found {len(critical_paths)} critical attack paths")

# Get graph statistics
stats = analyzer.get_graph_statistics()
print(f"Total CVEs: {stats['total_nodes']}")
print(f"Attack relationships: {stats['total_edges']}")
print(f"Graph density: {stats['density']:.2%}")
```

### Example 4: Generate IT Environment Scenarios

```python
from src.simulation.scenario_generator import ScenarioGenerator
import json

generator = ScenarioGenerator()

# Generate different scenarios
scenarios = []
for size in ["small", "mid"]:
    for reach in ["local", "global"]:
        scenario = generator.generate_scenario(
            size=size,
            reach=reach,
            industry="financial-services",
            environment_type="prod"
        )
        scenarios.append(scenario)

# Save scenarios
with open("scenarios.json", "w") as f:
    json.dump(scenarios, f, indent=2)

print(f"Generated {len(scenarios)} scenarios")
```

## 📋 Requirements

- Python 3.12+
- pandas
- networkx
- faker
- pygrype
- requests
- pyyaml
- python-dotenv

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

## 📞 Support

For issues, questions, or contributions, please open an issue or submit a pull request.

## 🎯 Roadmap

### Current
- ✅ CVE data management
- ✅ EPSS and KEV integration
- ✅ Docker image scanning
- ✅ Vulnerability analysis
- ✅ Scenario generation
- ✅ Bayesian risk assessment
- ✅ Security controls modeling
- ✅ Uncertainty quantification
- ✅ NLP vulnerability extraction
- ✅ **Bayesian-focused reporting** *(NEW)*
- ✅ **Attack scenarios filtered by Bayesian risk** *(NEW)*

### Planned
- [ ] ML-based categorization using spacy.io
- [ ] Advanced threat modeling
- [ ] Web dashboard
- [ ] API server
- [ ] Custom likelihood ratio configuration UI

## 📊 Project Statistics

- **20+ Modules**: Organized by responsibility
- **5,000+ Lines**: Clean, production-ready code
- **108 Tests**: Comprehensive test coverage
- **100% Type Hints**: Full type safety
- **100% Ruff Compliant**: Code quality assured
- **Bayesian Risk Engine**: Principled probabilistic assessment
- **NLP Feature Extraction**: Attack category detection from CVE descriptions
