# Monte Carlo Framework Integration Guide

## Overview

This guide explains how to integrate the Monte Carlo simulation framework with the main CVEs Analytics pipeline and run simulations.

## Prerequisites

1. **Main pipeline operational**: Ensure the main CVEs Analytics pipeline runs successfully
2. **Data available**: CVE data, EPSS scores, KEV catalog downloaded
3. **Docker images**: Docker images to scan are available
4. **Python environment**: All dependencies installed (see requirements)

## Quick Start

### 1. Validate Framework

Run the test suite to ensure everything works:

```bash
python3 monte_carlo/test_monte_carlo.py
```

Expected output: "All tests passed! Framework is ready for use."

### 2. Run Small Test Simulation

Start with a small simulation (10 iterations) to verify integration:

```bash
python3 monte_carlo/run_monte_carlo.py \
    --iterations 10 \
    --maturity optimizing \
    --org-size large \
    --industry financial-services
```

### 3. Run Full Simulation

Once validated, run the full 1000-iteration simulation:

```bash
python3 monte_carlo/run_monte_carlo.py \
    --iterations 1000 \
    --maturity optimizing \
    --org-size large \
    --industry financial-services \
    --seed 42
```

## Command Line Options

```
--iterations N          Number of Monte Carlo iterations (default: 1000)
--org-size SIZE        Organization size: small, medium, large
--industry INDUSTRY    Industry type (default: financial-services)
--maturity LEVEL       Security maturity: initial, managed, optimizing
--environment ENV      Environment: dev, test, prod
--seed N               Random seed for reproducibility
--force-cache-rebuild  Force rebuild of cache
--skip-analysis        Skip Bayesian analysis
--skip-visualization   Skip plot generation
```

## Integration Architecture

### Phase 1: Cache Setup (One-time, ~10 minutes)

The first run builds a cache of expensive operations:

1. **Generate scenario**: Creates architecture and control baseline
2. **Scan Docker images**: Runs Grype scans on all images
3. **Load CVE data**: Loads and enriches vulnerability dataset
4. **Load EPSS/KEV**: Loads exploitation probability data
5. **Save cache**: Stores results for reuse

**Cache location**: `monte_carlo/output/cache/`

**Cache invalidation**:
- Version mismatch
- Age > 7 days
- Force rebuild flag
- Scenario change

### Phase 2: Fast Iterations (~1-5 seconds each)

Each iteration:

1. **Generate controls**: Probabilistic control selection
2. **Map to LRs**: Convert controls to likelihood ratios
3. **Bayesian update**: Apply LRs to cached vulnerabilities
4. **Kill-chain calc**: Calculate exploitation probability
5. **Record results**: Store metrics

**No Docker scanning or data loading** - uses cache!

## Output Structure

```
monte_carlo/output/
├── cache/                                  # Cached data
│   └── cache_large_financial-services_prod.json
├── runs/                                   # Simulation results
│   ├── mc_large_optimizing_1000iter_20260102_105400.json
│   └── analysis_optimizing_20260102_105430.json
└── visualizations/                         # Plots
    ├── dist_killchain_probability_large_optimizing.png
    ├── control_effectiveness_mfa_type_optimizing.png
    └── ...
```

## Running Multiple Scenarios

To compare maturity levels, run simulations for each:

```bash
# Scenario 1: Initial maturity
python3 monte_carlo/run_monte_carlo.py \
    --iterations 1000 \
    --maturity initial \
    --seed 42

# Scenario 2: Managed maturity
python3 monte_carlo/run_monte_carlo.py \
    --iterations 1000 \
    --maturity managed \
    --seed 42

# Scenario 3: Optimizing maturity
python3 monte_carlo/run_monte_carlo.py \
    --iterations 1000 \
    --maturity optimizing \
    --seed 42
```

Then compare results programmatically:

```python
from monte_carlo.src.analyzer import BayesianAnalyzer
import json

# Load results
with open("monte_carlo/output/runs/mc_large_initial_1000iter_*.json") as f:
    initial_results = json.load(f)

with open("monte_carlo/output/runs/mc_large_optimizing_1000iter_*.json") as f:
    optimizing_results = json.load(f)

# Compare
analyzer = BayesianAnalyzer()
comparison = analyzer.compare_scenarios(initial_results, optimizing_results)

print(f"Probability optimizing is better: {comparison['probability_scenario2_better']:.1%}")
print(f"Expected risk reduction: {comparison['relative_risk_reduction']:.1%}")
```

## Performance Expectations

### First Run (with cache build)
- Cache setup: ~10 minutes
- 1000 iterations: ~15-20 minutes
- Analysis: ~1 minute
- Visualization: ~1 minute
- **Total: ~25-30 minutes**

### Subsequent Runs (cache exists)
- Cache load: ~1 second
- 1000 iterations: ~15-20 minutes
- Analysis: ~1 minute
- Visualization: ~1 minute
- **Total: ~17-22 minutes**

### Scaling
- 100 iterations: ~2-3 minutes
- 1000 iterations: ~15-20 minutes
- 5000 iterations: ~75-100 minutes
- 10000 iterations: ~150-200 minutes

## Troubleshooting

### Issue: Import errors

**Solution**: Ensure you're running from the repository root:
```bash
cd /path/to/cves_analytics
python3 monte_carlo/run_monte_carlo.py ...
```

### Issue: Cache build fails

**Symptoms**: Error during Phase 1 (cache setup)

**Solutions**:
1. Verify main pipeline works: `python3 src/cli/run_pipeline.py ...`
2. Check Docker images are available
3. Verify CVE data is downloaded
4. Check disk space (cache needs ~50 MB)

### Issue: Slow iterations

**Symptoms**: Iterations take > 10 seconds each

**Solutions**:
1. Verify cache is being used (check logs)
2. Reduce dataset size if testing
3. Check system resources (CPU, memory)

### Issue: Results seem unstable

**Symptoms**: Different runs give very different results

**Solutions**:
1. Increase iterations (try 5000 or 10000)
2. Check control generation randomness
3. Verify EPSS data is consistent
4. Use fixed seed for reproducibility

### Issue: Visualizations fail

**Symptoms**: Plots not generated or errors

**Solutions**:
1. Check matplotlib/seaborn installation
2. Verify output directory exists and is writable
3. Check for data in results (empty iterations?)

## Advanced Usage

### Custom Analysis

```python
from monte_carlo.src.analyzer import BayesianAnalyzer
import json

# Load results
with open("monte_carlo/output/runs/mc_*.json") as f:
    results = json.load(f)

# Custom analysis
analyzer = BayesianAnalyzer(bootstrap_samples=50000)  # More samples
analysis = analyzer.analyze_results(results)

# Extract specific metrics
kc_prob = analysis["metrics"]["killchain_probability"]
print(f"Mean: {kc_prob['mean']:.3f}")
print(f"99% CI: [{kc_prob['credible_intervals_mean']['99%']['lower']:.3f}, "
      f"{kc_prob['credible_intervals_mean']['99%']['upper']:.3f}]")
```

### Custom Visualizations

```python
from monte_carlo.src.visualizer import MonteCarloVisualizer
import json

# Load results
with open("monte_carlo/output/runs/mc_*.json") as f:
    results = json.load(f)

# Create custom plots
visualizer = MonteCarloVisualizer("custom_output_dir")
visualizer.plot_distribution(results, metric="actionable_vulnerabilities")
```

### Batch Processing

```bash
#!/bin/bash
# Run multiple scenarios in sequence

for maturity in initial managed optimizing; do
    echo "Running simulation for $maturity maturity..."
    python3 monte_carlo/run_monte_carlo.py \
        --iterations 1000 \
        --maturity $maturity \
        --seed 42
done

echo "All simulations complete!"
```

## Integration with CI/CD

Add to your CI/CD pipeline:

```yaml
# .github/workflows/monte_carlo.yml
name: Monte Carlo Risk Assessment

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  monte_carlo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run Monte Carlo simulation
        run: |
          python3 monte_carlo/run_monte_carlo.py \
            --iterations 1000 \
            --maturity optimizing
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: monte-carlo-results
          path: monte_carlo/output/
```

## Best Practices

1. **Start small**: Test with 10-100 iterations before full run
2. **Use seeds**: Set `--seed` for reproducible results
3. **Cache management**: Rebuild cache weekly or after major changes
4. **Monitor convergence**: Check running mean stabilizes
5. **Validate assumptions**: Review control LR values periodically
6. **Document runs**: Keep log of simulation parameters
7. **Version control**: Track which code version produced results
8. **Backup results**: Save important simulation outputs

## Next Steps

1. Run validation tests
2. Execute small test simulation (10 iterations)
3. Review test results and visualizations
4. Run full simulation (1000 iterations)
5. Analyze results and create reports
6. Compare multiple scenarios
7. Integrate into regular risk assessment workflow

## Support

For issues or questions:
1. Check test suite output
2. Review logs in console output
3. Verify prerequisites are met
4. Check troubleshooting section
5. Review methodology documentation
