# Monte Carlo Simulation Framework

## Overview

This directory contains the Monte Carlo simulation framework for the CVEs Analytics vulnerability assessment system. The framework enables probabilistic risk analysis by running multiple pipeline iterations with varying parameters to generate statistical distributions of outcomes.

## Purpose

Instead of single-point estimates, Monte Carlo simulation provides:
- **Probability distributions** for exploitation likelihood
- **Confidence intervals** around risk metrics
- **Sensitivity analysis** to identify key risk drivers
- **Control effectiveness validation** across multiple scenarios
- **Budget optimization** insights for security investments

## Directory Structure

```
monte_carlo/
├── src/                    # Source code
│   ├── simulator.py        # Main Monte Carlo simulation engine
│   ├── analyzer.py         # Statistical analysis of results
│   └── visualizer.py       # Visualization tools
├── docs/                   # Documentation
│   ├── METHODOLOGY.md      # Simulation methodology
│   ├── ANALYSIS_GUIDE.md   # How to interpret results
│   └── EXAMPLES.md         # Usage examples
├── output/                 # Simulation results
│   ├── runs/              # Individual run data
│   ├── aggregated/        # Aggregated statistics
│   └── visualizations/    # Charts and graphs
└── config/                 # Configuration files
    └── scenarios.yaml     # Simulation scenario definitions

```

## Key Capabilities

### 1. Risk Distribution Analysis
- Generate probability distributions for kill-chain exploitation
- Calculate confidence intervals (e.g., 95% CI)
- Identify tail risks (p95, p99 scenarios)

### 2. Control Effectiveness Validation
- Compare risk distributions across maturity levels
- Quantify risk reduction from specific controls
- Validate probabilistic control type system

### 3. Sensitivity Analysis
- Identify which parameters drive risk outcomes
- Understand relative importance of EPSS vs. controls
- Focus data collection on high-impact variables

### 4. Scenario Planning
- "What-if" analysis for control failures
- Budget optimization for security investments
- Risk forecasting under different conditions

## Usage

```python
from monte_carlo.src.simulator import MonteCarloSimulator

# Initialize simulator
simulator = MonteCarloSimulator(
    n_iterations=1000,
    scenario_config="config/scenarios.yaml"
)

# Run simulation
results = simulator.run(
    org_size="large",
    maturity="optimizing",
    industry="financial-services"
)

# Analyze results
from monte_carlo.src.analyzer import analyze_results
stats = analyze_results(results)

# Visualize
from monte_carlo.src.visualizer import plot_distribution
plot_distribution(results, metric="killchain_probability")
```

## Metrics Tracked

- Kill-chain exploitation probability (mean, median, std, p95, p99)
- Actionable vulnerabilities count
- Bayesian risk assessment distributions
- Control effectiveness (LR values)
- Attack path frequencies

## Statistical Methods

- **Descriptive statistics**: Mean, median, standard deviation, percentiles
- **Confidence intervals**: Bootstrap methods for robust CI estimation
- **Hypothesis testing**: Compare maturity levels, control configurations
- **Correlation analysis**: Identify key risk drivers

## Development Status

- [x] Directory structure created
- [ ] Core simulation engine
- [ ] Statistical analysis module
- [ ] Visualization tools
- [ ] Documentation
- [ ] Example scenarios

## References

- Hubbard, D. & Seiersen, R. (2016). "How to Measure Anything in Cybersecurity Risk"
- Tetlock, P. & Gardner, D. (2015). "Superforecasting"
- Clayton, A. (2021). "Bernoulli's Fallacy"
