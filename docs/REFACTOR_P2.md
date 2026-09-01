# Phase 2: Core Modules & Models

## Objective
Migrate and refactor the core risk assessment and attack modeling logic from `cves_analytics` into the new modular architecture.

## What Was Done

### 1. Module Extraction
- Extracted Pydantic V2 models from monolithic source into `src/core/models/__init__.py`
- Separated Bayesian risk assessor into `src/core/risk/bayesian_assessor.py`
- Separated kill chain calculator into `src/core/attack/kill_chain.py`

### 2. Models Created
- `CVERecord` (Pydantic V2 BaseModel) — canonical CVE representation
- `LikelihoodRatioConfig` — configurable LR thresholds
- `SecurityControlsInput` — control presence flags
- `ThreatIndicatorsInput` — active threat signals
- `KillChainStage` / `KillChainResult` — attack chain modeling
- `BayesianRiskResult` — full risk assessment output with credible intervals

### 3. Bayesian Risk Assessor
- `CVSSVectorLR` — vector metric parsing and LR mapping
- `ExposureConditionalControlLR` — control effectiveness model
- `BayesianRiskAssessor` — full Bayesian inference pipeline
- Fixed `_parse_cvss_vector` bug (original skipped all KEY:VALUE parts)
- Fixed `_normalize_threats` field alignment

### 4. Kill Chain Calculator
- Stage-by-stage probability computation
- Control mitigation factors per stage
- Lateral movement, execution, persistence, objective modeling

### 5. Test Suite
- `test_bayesian_risk.py`: 78 tests covering all assessor methods
- `test_kill_chain.py`: 40 tests covering all calculator methods
- `test_models.py`: 15 tests for Pydantic model validation
- `test_coverage_gaps.py`: 18 targeted branch coverage tests
- **Total: 151 tests, 99% coverage (1 unreachable dead-code line)**

## Bugs Fixed from Source
1. `_parse_cvss_vector` skipped all `KEY:VALUE` parts due to `if ":" not in part` check before split
2. `ThreatIndicatorsInput` field names mismatched between model and consumer code
3. Dead code in `_apply_nlp_features` (line 432-433: unreachable `if not values` after truthy guard)

## Coverage Report
```
src/core/attack/kill_chain.py          125      0   100%
src/core/models/__init__.py             62      0   100%
src/core/risk/bayesian_assessor.py     179      1    99%   (line 433: dead code)
TOTAL                                  394      1    99%
```

## Files Produced
- `src/core/models/__init__.py`
- `src/core/risk/bayesian_assessor.py`
- `src/core/attack/kill_chain.py`
- `tests/unit/test_bayesian_risk.py`
- `tests/unit/test_kill_chain.py`
- `tests/unit/test_models.py`
- `tests/unit/test_coverage_gaps.py`

## Design Decisions
1. **Pydantic V2 models** over dataclasses for input validation and serialization
2. **Strong typing** throughout: all methods have type hints, mypy-clean
3. **Modular separation**: models / risk / attack in distinct subpackages
4. **No loops in hot paths**: vectorized operations where possible
5. **Credible intervals** in risk results for uncertainty quantification

## Next: Phase 3
Data layer migration (loaders, transformers, stores) with polars pipelines.
