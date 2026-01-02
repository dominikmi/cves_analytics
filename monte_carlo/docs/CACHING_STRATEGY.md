# Monte Carlo Caching Strategy

## Overview

The Monte Carlo simulation framework uses a two-phase architecture to achieve ~670x speedup over naive implementation:

1. **Phase 1: One-time Setup** (~10 minutes) - Expensive operations cached
2. **Phase 2: Fast Iterations** (~1-5 seconds per iteration) - Uses cached data

## Performance Comparison

### Without Caching (Naive Approach)
```
Setup:           10 minutes
Per iteration:   10 minutes
1000 iterations: ~167 hours (7 days!)
```

### With Caching (Optimized Approach)
```
Setup:           10 minutes (one-time)
Per iteration:   1-5 seconds
1000 iterations: 10 + 5 = 15 minutes total

Speedup: ~670x faster
```

## What Gets Cached

### Expensive Operations (Cached Once)

1. **Docker Image Scanning** (~5-10 minutes)
   - Grype vulnerability scans
   - Image layer analysis
   - CVE extraction per image
   - **Why cached**: Same images = same vulnerabilities

2. **CVE Dataset Loading** (~30 seconds)
   - CVE v5 data parsing
   - CVSS score extraction
   - Vulnerability metadata
   - **Why cached**: Static dataset per run

3. **EPSS Data Loading** (~10 seconds)
   - Exploitation probability scores
   - Historical EPSS data
   - **Why cached**: Updated daily, constant within simulation

4. **KEV Catalog Loading** (~5 seconds)
   - Known Exploited Vulnerabilities
   - CISA KEV catalog
   - **Why cached**: Updated weekly, constant within simulation

5. **CWE Enrichment** (~40 seconds first run, instant after)
   - Already has disk caching
   - Reused across iterations

### Fast Operations (Regenerated Each Iteration)

1. **Security Control Generation** (~0.1 seconds)
   - Probabilistic control type selection
   - Control quality assignment
   - **Why regenerated**: Core of Monte Carlo variability

2. **Control Effectiveness Mapping** (~0.01 seconds)
   - Map control types to likelihood ratios
   - Calculate LR values
   - **Why regenerated**: Depends on generated controls

3. **Bayesian Risk Assessment** (~0.5 seconds)
   - Apply new LR values to cached vulnerabilities
   - Recalculate posterior probabilities
   - Reassess severity levels
   - **Why regenerated**: Depends on control LRs

4. **Kill-Chain Probability** (~0.1 seconds)
   - Calculate stage-by-stage probabilities
   - Apply control effectiveness
   - Determine threat level
   - **Why regenerated**: Depends on controls and reassessed risks

## Cache Structure

```python
cache = {
    "version": "1.0",
    "timestamp": "2026-01-02T10:23:00",
    "scenario_config": {
        "org_size": "large",
        "industry": "financial-services",
        "maturity": "optimizing",
        "environment": "prod"
    },
    "docker_scans": {
        "nginx:latest": [
            {"cve_id": "CVE-2023-1234", "severity": "HIGH", ...},
            ...
        ],
        "postgres:14": [...],
        ...
    },
    "enriched_cves": {
        # DataFrame serialized as dict
        "cve_id": ["CVE-2023-1234", ...],
        "cvss_score": [7.5, ...],
        "epss_score": [0.083, ...],
        "is_kev": [true, ...],
        ...
    },
    "epss_data": {
        "CVE-2023-1234": 0.083,
        ...
    },
    "kev_data": {
        "CVE-2023-1234": {
            "date_added": "2023-06-15",
            "required_action": "Apply updates",
            ...
        },
        ...
    },
    "architecture": {
        "components": [...],
        "network_topology": {...},
        ...
    }
}
```

## Cache Invalidation

Cache is invalidated when:

1. **Version mismatch**: Cache format changed
2. **Age > 7 days**: EPSS/KEV data may be stale
3. **Force rebuild**: User explicitly requests rebuild
4. **Scenario change**: Different org_size/industry/environment

## Cache Storage

- **Location**: `monte_carlo/output/cache/`
- **Format**: JSON (human-readable, debuggable)
- **Naming**: `cache_{org_size}_{industry}_{environment}.json`
- **Size**: ~10-50 MB per scenario (depends on image count)

## Implementation Details

### Cache Manager (`cache_manager.py`)

```python
class SimulationCache:
    def build_cache(scenario_config, force_rebuild=False):
        # Check if valid cache exists
        if cache_exists and not force_rebuild:
            return load_cache()
        
        # Run pipeline once to extract data
        result = run_full_pipeline(...)
        
        # Extract and cache expensive parts
        cache = {
            "docker_scans": extract_docker_scans(result),
            "enriched_cves": extract_enriched_cves(result),
            "epss_data": extract_epss_data(result),
            "kev_data": extract_kev_data(result),
            ...
        }
        
        save_cache(cache)
        return cache
```

### Simulator (`simulator.py`)

```python
class MonteCarloSimulator:
    def run(org_size, maturity, ...):
        # Phase 1: Build cache (one-time)
        cache = cache_manager.build_cache(scenario_config)
        
        # Phase 2: Fast iterations
        for i in range(n_iterations):
            # Generate new controls
            controls = generate_controls(seed=i)
            
            # Use cached vulnerability data
            vulns = cache["enriched_cves"]
            
            # Calculate with new controls
            lr_values = map_controls_to_lr(controls)
            reassessed = apply_bayesian_risk(vulns, lr_values)
            killchain = calculate_killchain(reassessed, controls)
            
            results.append(...)
```

## Benefits

1. **Speed**: 670x faster than naive approach
2. **Consistency**: Same vulnerability data across iterations
3. **Reproducibility**: Cached data ensures consistent baseline
4. **Resource efficiency**: No redundant Docker scans
5. **Scalability**: Can run 10,000+ iterations in reasonable time

## Trade-offs

1. **Disk space**: ~10-50 MB per cached scenario
2. **Initial setup**: First run takes 10 minutes
3. **Staleness**: Cache may become outdated (7-day limit)
4. **Memory**: Large caches loaded into memory during simulation

## Future Optimizations

1. **Incremental caching**: Only rescan changed images
2. **Compression**: Compress cached JSON files
3. **Distributed caching**: Share caches across team
4. **Lazy loading**: Load cache data on-demand
5. **Parallel iterations**: Run multiple iterations concurrently

## Usage Example

```python
from monte_carlo.src.simulator import MonteCarloSimulator

# Initialize simulator
simulator = MonteCarloSimulator(
    n_iterations=1000,
    cache_dir="monte_carlo/output/cache"
)

# First run: builds cache (~10 min setup + 5 min iterations)
results1 = simulator.run(
    org_size="large",
    maturity="optimizing",
    industry="financial-services"
)

# Second run: reuses cache (~5 min iterations only)
results2 = simulator.run(
    org_size="large",
    maturity="optimizing",
    industry="financial-services"
)

# Force rebuild if needed
results3 = simulator.run(
    org_size="large",
    maturity="optimizing",
    industry="financial-services",
    force_cache_rebuild=True
)
```

## Monitoring Cache Performance

The simulator logs timing information:

```
PHASE 1: CACHE SETUP (one-time, ~10 minutes)
Loading cache from monte_carlo/output/cache/cache_large_financial-services_prod.json
Cache is valid, using cached data
Cache setup completed in 0.5 seconds

PHASE 2: MONTE CARLO ITERATIONS (1000x)
Progress: 100/1000 (10.0%) - Avg: 1.23s/iter - ETA: 1107s
Progress: 200/1000 (20.0%) - Avg: 1.21s/iter - ETA: 968s
...

SIMULATION COMPLETE
Cache setup time: 0.5s
Iterations time: 1215.3s
Total time: 1215.8s
Average per iteration: 1.22s
```

## References

- Hubbard, D. & Seiersen, R. (2016). "How to Measure Anything in Cybersecurity Risk" - Monte Carlo methods
- Downey, A. (2021). "Think Bayes" - Computational Bayesian statistics
