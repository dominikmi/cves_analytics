# CVEs Analytics Pipeline - Software Components Reference

**Version:** 2.1  
**Last Updated:** January 3, 2026  
**Document Type:** Technical Reference  
**Estimated Reading Time:** 30-45 minutes

## Intended Audience

**Primary:** Software developers, contributors, code reviewers  
**Secondary:** Technical architects, security researchers implementing custom extensions

**Prerequisites:**
- Python programming experience
- Understanding of object-oriented design
- Familiarity with Bayesian statistics (helpful but not required)

**What You'll Learn:**
- Complete inventory of all pipeline classes and methods
- Software architecture and component relationships
- API reference for extending the pipeline
- Testing coverage and configuration files

---

This document provides a comprehensive reference of all working software components (classes and methods) in the CVEs Analytics pipeline.

---

## Table of Contents

1. [Core Components](#core-components)
2. [Pipeline Steps](#pipeline-steps)
3. [Simulation Components](#simulation-components)
4. [Analysis Components](#analysis-components)
5. [Utility Components](#utility-components)
6. [CLI Entry Points](#cli-entry-points)

---

## Core Components

### Bayesian Risk Assessment

**File:** `src/core/bayesian_risk.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `SecurityControlsInput` | - | Pydantic model for security controls input |
| `ThreatIndicators` | - | Pydantic model for threat intelligence indicators |
| `BayesianRiskAssessment` | - | Pydantic model for risk assessment results |
| `BayesianRiskAssessor` | `__init__`, `_calculate_prior_odds`, `_calculate_threat_lr`, `_calculate_control_lr`, `_calculate_exposure_lr`, `_calculate_cvss_lr`, `_calculate_asset_lr`, `_apply_posterior_floor`, `assess` | Performs Bayesian risk assessment with exposure-conditional LRs |

**Key Functions:**
- `calculate_bayesian_risk()` - Main entry point for risk calculation

---

### Temporal Risk Assessment

**File:** `src/core/temporal_risk.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `TemporalFactors` | - | Pydantic model for temporal factors (age, patch, KEV) |
| `TemporalAdjustment` | - | Pydantic model for temporal adjustment results |

**Key Functions:**
- `calculate_age_factor()` - Calculate vulnerability age decay factor
- `calculate_patch_factor()` - Calculate patch availability factor
- `apply_temporal_adjustment()` - Apply temporal factors to probability (NOT odds)
- `calculate_days_since_disclosure()` - Calculate days since CVE disclosure
- `calculate_days_since_patch()` - Calculate days since patch availability

**Important:** Temporal factors are applied to PROBABILITY after Bayesian updating, not to odds.

---

### Kill Chain Calculator

**File:** `src/core/kill_chain_calculator.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `KillChainStage` | - | Pydantic model for kill chain stage results |
| `KillChainResult` | - | Pydantic model for complete kill chain analysis |
| `KillChainCalculator` | `__init__`, `calculate`, `_calculate_initial_access`, `_calculate_execution`, `_calculate_lateral_movement`, `_calculate_objective_achievement`, `_apply_control_lr`, `_identify_bottleneck` | Calculate multi-stage kill chain probability |

---

### CVSS Processing

**File:** `src/core/cvss_parser.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `CVSSParser` | `parse_cvss_v2()`, `parse_cvss_v3()` | Parse CVSS v2 and v3 vectors from CVE data |

**File:** `src/core/cvss_vector_reassessment.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `CVSSVectorParser` | `parse_cvss_vector()` | Parse CVSS vector strings into components |
| `CVSSEPSSReassessment` | `reassess()` | Reassess severity based on CVSS vectors and EPSS |

**Key Functions:**
- `reassess_vulnerabilities()` - Batch reassessment for DataFrames

**File:** `src/core/cvss_models.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `CVSSv2Metrics` | - | Pydantic model for CVSS v2 metrics |
| `CVSSv3Metrics` | - | Pydantic model for CVSS v3 metrics |

---

### Data Processors

**File:** `src/core/cvev5_processor.py`

**Key Functions:**
- `download_cvev5_cve_data()` - Download CVE v5 data from GitHub
- `load_cvev5_cve_data()` - Load CVE v5 data from disk

**File:** `src/core/epss_processor.py`

**Key Functions:**
- `download_epss_scores()` - Download EPSS scores for a specific date
- `download_epss_scores_for_months()` - Download EPSS scores for multiple months (async)
- `load_epss_scores()` - Load EPSS scores from disk

**File:** `src/core/kev_processor.py`

**Key Functions:**
- `download_kev_catalog()` - Download CISA KEV catalog
- `load_kev_catalog()` - Load KEV catalog from disk

**File:** `src/core/cwe_processor.py`

**Key Functions:**
- `fetch_cwe_data()` - Fetch CWE data from MITRE API
- `enrich_cwe_data_async()` - Async CWE enrichment with caching

**File:** `src/core/cvss_bt_processor.py`

**Key Functions:**
- `load_cvss_bt_data()` - Load CVSS-BT (Exploit Prediction) data
- `enrich_with_cvss_bt()` - Enrich CVE data with exploit indicators

**File:** `src/core/vulnrichment_processor.py`

**Key Functions:**
- `download_vulnrichment_data()` - Download CISA Vulnrichment data
- `load_vulnrichment_data()` - Load Vulnrichment data from disk

---

### Threat Intelligence

**File:** `src/core/threat_intelligence.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `ThreatIntelligence` | `__init__`, `get_threat_indicators()`, `_check_kev()`, `_check_metasploit()`, `_check_exploitdb()`, `_check_nuclei()`, `_check_github_poc()` | Aggregate threat intelligence from multiple sources |

---

### Docker Scanning

**File:** `src/core/docker_scanner.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `DockerScanner` | `__init__`, `scan_image()`, `scan_images()` | Scan Docker images for vulnerabilities using Grype |

---

### Vulnerability Analysis

**File:** `src/core/vulnerability_analyzer.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `AttackChainAnalyzer` | `__init__`, `analyze()`, `build_graph()`, `find_unique_chains()`, `get_critical_paths()`, `get_graph_statistics()`, `get_node_impact()`, `map_to_mitre_attack()` | Analyze attack chains and vulnerability relationships |

---

### Remediation Planning

**File:** `src/core/remediation_planner.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `RemediationPlanner` | `__init__`, `plan()`, `_prioritize_vulnerabilities()`, `_estimate_effort()`, `_create_timeline()` | Generate remediation plans and timelines |

---

### Risk Scoring

**File:** `src/core/risk_scoring.py`

**Key Functions:**
- `calculate_risk_score()` - Calculate comprehensive risk score
- `categorize_risk()` - Categorize risk level (Critical/High/Medium/Low/Negligible)

---

### Control LR Mapper

**File:** `src/core/control_lr_mapper.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `ControlLRMapper` | `__init__`, `get_control_lr()`, `get_exposure_lr()`, `get_threat_indicator_lr()` | Map security controls to likelihood ratios |

---

### NLP Extractor

**File:** `src/core/nlp_extractor.py`

**Key Functions:**
- `extract_attack_patterns()` - Extract attack patterns from CVE descriptions
- `extract_affected_components()` - Extract affected components using NLP

---

## Pipeline Steps

### Main Pipeline

**File:** `src/cli/pipeline.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `VulnerabilityAssessmentPipeline` | `__init__`, `run()`, `_execute_step()`, `_generate_environment()`, `_scan_docker_images()`, `_enrich_data()`, `_analyze_attack_scenarios()`, `_generate_report()` | Main pipeline orchestrator |

---

### Environment Generator

**File:** `src/cli/pipeline_steps/environment_generator.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `EnvironmentGenerator` | `__init__`, `generate()` | Generate simulated environment and application architecture |

---

### Docker Scanner (Pipeline Step)

**File:** `src/cli/pipeline_steps/docker_scanner.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `DockerScanner` | `__init__`, `scan()` | Pipeline step for Docker image scanning |

---

### Data Enricher

**File:** `src/cli/pipeline_steps/data_enricher.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `DataEnricher` | `__init__`, `enrich()`, `_add_environment_context()`, `_log_control_distribution()`, `_convert_posture_to_controls()`, `_load_and_merge_epss_data()`, `_fetch_missing_cve_data()`, `_extract_cvss_data()`, `_enrich_with_cvss_bt()`, `_enrich_with_cvev5_fallback()` | Enrich vulnerability data with EPSS, CVSS, threat intelligence |

---

### Attack Analyzer

**File:** `src/cli/pipeline_steps/attack_analyzer.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `AttackAnalyzer` | `__init__`, `analyze()`, `_load_service_catalog()` | Analyze attack scenarios and chains |

---

### Kill Chain Analyzer (Pipeline Step)

**File:** `src/cli/pipeline_steps/kill_chain_analyzer.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `KillChainAnalyzer` | `__init__`, `analyze()`, `_assess_docker_security()`, `_convert_to_template()` | Analyze kill chain probabilities for application |

**Key Functions:**
- `analyze_kill_chain()` - Standalone kill chain analysis function

---

### Report Generator

**File:** `src/cli/pipeline_steps/report_generator.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `ReportGenerator` | `__init__`, `generate()`, `_generate_executive_summary()`, `_generate_kill_chain_analysis()`, `_generate_stage_recommendations()`, `_generate_kill_chain_insights()`, `_generate_risk_prioritization()`, `_generate_remediation_roadmap()`, `generate_pdf_report()` | Generate comprehensive vulnerability assessment reports |

---

## Simulation Components

### Scenario Generator

**File:** `src/simulation/scenario_generator.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `ScenarioGenerator` | `__init__`, `_load_config()`, `generate_scenario()`, `export_to_csv()`, `_generate_network_policies()`, `_generate_security_controls()`, `_generate_posture()`, `_design_architecture()`, `_get_zone()`, `_calculate_asset_value()`, `_determine_ownership()`, `_get_data_classification()`, `_add_sidecar_exporters()`, `_add_cicd_services()` | Generate realistic security scenarios |

---

### Application Builder

**File:** `src/simulation/application_builder.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `ApplicationBuilder` | `__init__`, `build()`, `_select_services()`, `_assign_zones()`, `_assign_asset_values()`, `_generate_network_policies()` | Build multi-component applications |

---

### Application Templates

**File:** `src/simulation/application_templates.py`

**Key Functions:**
- `_get_online_store_template()` - E-commerce application template
- `_get_financial_services_template()` - Banking/trading platform template
- `_get_consulting_template()` - Consulting firm template
- `_get_saas_platform_template()` - SaaS platform template
- `_get_data_analytics_template()` - Data analytics platform template
- `get_application_templates()` - Get all templates
- `get_template_for_industry()` - Get template for specific industry
- `get_all_templates()` - Get all available templates

---

### Security Controls

**File:** `src/simulation/security_controls.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `SecurityMaturityLevel` | - | Enum for security maturity levels |
| `PatchManagementCadence` | - | Enum for patch management cadence |
| `ControlProbabilities` | - | Pydantic model for control probabilities |
| `SecurityControlsConfig` | `get_patch_cadence()`, `to_dict()`, `get_active_controls()`, `count_controls()` | Security controls configuration |
| `SecurityControlsGenerator` | `__init__`, `generate()`, `_should_have_control()`, `_select_patch_cadence()`, `_get_industry_modifiers()`, `_get_environment_modifiers()`, `_get_size_modifiers()` | Generate realistic security controls |
| `ExposureBasedControlProbabilities` | `get_modifier()`, `get_mandatory_controls()` | Exposure-based control probabilities |
| `ServiceSecurityControlsGenerator` | `__init__`, `generate_for_service()`, `_get_asset_value_modifiers()`, `_get_service_role_modifiers()` | Generate per-service security controls |

**Key Functions:**
- `estimate_maturity_from_posture()` - Estimate maturity level from security posture

---

### Control Type Selector

**File:** `src/simulation/control_type_selector.py`

**Key Functions:**
- `select_mfa_type()` - Select MFA implementation type
- `select_firewall_type()` - Select firewall type
- `select_waf_type()` - Select WAF type
- `select_endpoint_type()` - Select endpoint protection type
- `select_segmentation_type()` - Select network segmentation type
- `select_ids_ips_type()` - Select IDS/IPS type
- `select_siem_maturity()` - Select SIEM maturity level
- `select_patch_quality()` - Select patch management quality

---

### Control Types

**File:** `src/simulation/control_types.py`

| Class | Purpose |
|-------|---------|
| `MFAType` | Enum for MFA types (SMS, Authenticator, FIDO2, etc.) |
| `FirewallType` | Enum for firewall types (Stateful, NGFW, Cloud-native) |
| `WAFType` | Enum for WAF types (Basic, ModSecurity, Cloud WAF) |
| `EndpointProtectionType` | Enum for endpoint protection (Antivirus, EDR, XDR) |
| `SegmentationType` | Enum for segmentation (VLANs, Micro-segmentation, Zero Trust) |
| `IDSIPSType` | Enum for IDS/IPS types (Signature-based, Behavioral, ML-based) |
| `SIEMMaturity` | Enum for SIEM maturity (Basic, Managed, Advanced) |
| `PatchManagementQuality` | Enum for patch quality (Ad-hoc, Scheduled, Automated) |

---

### System Simulator

**File:** `src/simulation/system_simulator.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `SimSystem` | `__init__`, `__str__`, `generate_random_system()` | Simulate system configurations |

---

### Scenario Config

**File:** `src/simulation/scenario_config.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `ScenarioConfig` | - | Pydantic model for scenario configuration |

---

### Control Probabilities

**File:** `src/simulation/control_probabilities.py`

Contains probability distributions for control selection based on:
- Organization size (small, mid, large)
- Industry (online-store, financial-services, consulting)
- Environment (dev, test, qa, stage, prod)
- Security maturity level

---

## Analysis Components

### Attack Scenario Analyzer

**File:** `src/analysis/attack_scenario_analyzer.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `AttackScenarioAnalyzer` | `__init__`, `analyze()`, `_identify_critical_vulnerabilities()`, `_build_attack_graph()`, `_calculate_attack_paths()`, `_assess_impact()` | Analyze attack scenarios and paths |

---

## Utility Components

### Configuration Management

**File:** `src/utils/config.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `AppConfig` | - | Pydantic model for application configuration |
| `ConfigManager` | `__new__`, `config()`, `initialize()`, `reset()` | Singleton configuration manager |

**Key Functions:**
- `get_config()` - Get global configuration instance
- `initialize_config()` - Initialize configuration

---

### Security Controls Config

**File:** `src/utils/security_controls_config.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `SecurityControlsConfig` | `validate_control_structure()`, `validate_docker_structure()`, `get_control_value()`, `get_docker_control_value()`, `get_exposure_value()`, `get_threat_indicator_value()`, `get_temporal_factor()`, `get_probability_bound()`, `get_kill_chain_control_value()` | Load and validate security controls configuration |

**Key Functions:**
- `load_security_controls_config()` - Load controls config from YAML
- `get_security_controls_config()` - Get singleton config instance

---

### Logging

**File:** `src/utils/logging_config.py`

**Key Functions:**
- `setup_logger()` - Setup logger with file and console handlers
- `get_logger()` - Get logger instance

---

### Error Handling

**File:** `src/utils/error_handling.py`

| Class | Purpose |
|-------|---------|
| `CVEsAnalyticsError` | Base exception class |
| `DataValidationError` | Data validation exception |
| `ConfigurationError` | Configuration exception |

**Key Functions:**
- `error_handler()` - Decorator for error handling

---

### Control Correlation

**File:** `src/utils/control_correlation.py`

| Class | Methods | Purpose |
|-------|---------|---------|
| `ControlCorrelationEngine` | `__init__`, `apply_correlations()`, `_apply_maturity_level()`, `_apply_positive_correlations()`, `_apply_negative_correlations()`, `generate_realistic_controls()`, `explain_control_presence()` | Apply realistic control correlations |

**Key Functions:**
- `generate_correlated_controls()` - Generate correlated security controls

---

## CLI Entry Points

### Create Dataset

**File:** `src/cli/create_dataset.py`

**Key Functions:**
- `main()` - Create enriched CVE dataset with EPSS, KEV, CWE data

**Usage:**
```bash
python -m src.cli.create_dataset --year 2024 --output data/cve_dataset_2024.csv
```

---

### Generate Simulation

**File:** `src/cli/generate_simulation.py`

**Key Functions:**
- `main()` - Generate simulated security scenario

**Usage:**
```bash
python -m src.cli.generate_simulation \
  --org-size large \
  --industry financial-services \
  --environment prod \
  --output scenarios/financial_prod.csv
```

---

### Scan Images

**File:** `src/cli/scan_images.py`

**Key Functions:**
- `main()` - Scan Docker images for vulnerabilities

**Usage:**
```bash
python -m src.cli.scan_images \
  --images nginx:latest postgres:14 \
  --output scans/results.json
```

---

### Run Pipeline

**File:** `src/cli/run_pipeline.py`

**Key Functions:**
- `main()` - Run full vulnerability assessment pipeline

**Usage:**
```bash
python -m src.cli.run_pipeline \
  --org-size large \
  --org-reach global \
  --industry financial-services \
  --environment prod \
  --output-dir output/reports
```

---

## Pipeline Flow

```
1. Environment Generation (EnvironmentGenerator)
   - Generate application architecture
   - Assign security controls
   - Create network policies

2. Docker Scanning (DockerScanner)
   - Scan container images
   - Extract vulnerabilities

3. Data Enrichment (DataEnricher)
   - Add EPSS scores
   - Add KEV status
   - Add CVSS vectors
   - Add threat intelligence
   - Perform Bayesian risk assessment
   - Apply temporal adjustments

4. Attack Analysis (AttackAnalyzer)
   - Build attack graphs
   - Identify critical paths
   - Map to MITRE ATT&CK

5. Kill Chain Analysis (KillChainAnalyzer)
   - Calculate stage probabilities
   - Identify bottlenecks
   - Assess Docker security

6. Report Generation (ReportGenerator)
   - Executive summary
   - Risk prioritization
   - Remediation roadmap
   - Kill chain insights
```

---

## Key Design Patterns

### 1. Bayesian Risk Assessment
- **Prior**: EPSS score
- **Likelihood Ratios**: Security controls, exposure, CVSS vectors, threat indicators
- **Posterior**: Final exploitation probability
- **Floors**: Minimum risk levels for KEV, exploits

### 2. Temporal Adjustments
- Applied to PROBABILITY (not odds) after Bayesian updating
- Age factor: Vulnerability lifecycle decay
- Patch factor: Patch availability impact
- KEV multiplier: Maintains high probability for active threats

### 3. Exposure-Conditional LRs
- Controls have different effectiveness based on exposure
- WAF: 70% reduction (internet-facing) vs 10% (internal)
- Network Segmentation: 50% (perimeter) vs 70% (internal)

### 4. Exploitability Gating
- Amplification factors (LR > 1) only applied when exploitation is plausible
- Prevents false inflation for unexploitable vulnerabilities

### 5. Kill Chain Modeling
- Multi-stage probability calculation
- Stage-specific controls
- Bottleneck identification
- Docker security assessment

---

## Testing

All core components have comprehensive unit tests in `tests/`:

- `test_bayesian_risk.py` - Bayesian risk assessment tests
- `test_temporal_risk.py` - Temporal adjustment tests (37 tests)
- `test_kill_chain_calculator.py` - Kill chain calculation tests
- `test_vulnerability_analyzer.py` - Attack chain analysis tests
- `test_cvss_parser.py` - CVSS parsing tests
- `test_risk_scoring.py` - Risk scoring tests

**Test Coverage:** 334+ tests passing

---

## Configuration Files

- `config/security_controls.yaml` - Security controls LR values
- `config/services.yaml` - Service templates and configurations
- `.env` - Environment variables (API keys, paths)

---

## Dependencies

**Core:**
- Python 3.12+
- Pydantic v2 - Data validation
- Polars v1.0+ - Data processing
- NetworkX - Graph analysis

**External Tools:**
- Grype - Docker vulnerability scanning
- EPSS API - Exploit prediction scores
- CISA KEV - Known exploited vulnerabilities
- MITRE CWE API - Weakness enumeration

---

## Version History

- **v2.1** (2026-01-03): Fixed temporal adjustment logic, improved documentation
- **v2.0** (2026-01-02): Probabilistic control types, exposure-conditional LRs
- **v1.0** (2025-12-xx): Initial release

---

## References

- [BAYESIAN_RISK_ASSESSMENT.md](BAYESIAN_RISK_ASSESSMENT.md) - Detailed Bayesian methodology
- [EXTENDED_KILL_CHAIN_METHOD.md](EXTENDED_KILL_CHAIN_METHOD.md) - Kill chain probability calculation
- [SECURITY_CONTROLS_GUIDE.md](SECURITY_CONTROLS_GUIDE.md) - Security controls reference
- [DEMO_REPORT.md](DEMO_REPORT.md) - Example reports and scenarios

---

**Maintained by:** CVEs Analytics Team  
**License:** MIT  
**Repository:** https://github.com/dominikmi/cves_analytics
