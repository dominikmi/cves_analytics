# Monte Carlo Methodology for Vulnerability Risk Assessment

## Overview

This document describes the mathematical and statistical methodology underlying the Monte Carlo simulation framework for vulnerability risk assessment. The approach combines Bayesian inference, probabilistic control modeling, and Monte Carlo methods to generate robust risk estimates with quantified uncertainty.

## Core Methodology

### 1. Bayesian Risk Assessment Foundation

The framework uses Bayesian inference to update vulnerability exploitation probabilities based on evidence. This is consistent with the main pipeline's approach but extended through Monte Carlo simulation.

#### Prior Probability
The prior probability comes from EPSS (Exploit Prediction Scoring System):

```
P(exploit) = EPSS_score
```

For example, EPSS = 0.083 means 8.3% baseline exploitation probability.

#### Likelihood Ratios
Evidence is incorporated through likelihood ratios (LR):

```
LR = P(evidence | exploit) / P(evidence | no exploit)
```

Control types map to LR values:
- **LR < 1.0**: Protective (reduces risk)
- **LR = 1.0**: Neutral (no effect)
- **LR > 1.0**: Risk factor (increases risk)

#### Posterior Calculation (Odds Form)
Using odds formulation for computational efficiency:

```
Prior odds = EPSS / (1 - EPSS)
Posterior odds = Prior odds * LR1 * LR2 * ... * LRn
Posterior probability = Posterior odds / (1 + Posterior odds)
```

**Why odds space?**
- Simplifies multiplication of multiple evidence sources
- Avoids repeated application of Bayes' theorem
- Computationally efficient
- Mathematically equivalent to full Bayesian updating

Reference: [Odds space explanation video](https://www.youtube.com/watch?v=lG4VkPoG3ko)

### 2. Probabilistic Control Generation

Security controls are generated probabilistically based on organization maturity level, creating realistic variation in control portfolios.

#### Control Type Distribution

Each maturity level has a probability distribution over control types:

```python
P(control_type | maturity, industry, size) = f(maturity_level)
```

For example, "optimizing" maturity:
- Advanced controls: 60% probability
- Intermediate controls: 30% probability  
- Basic controls: 10% probability
- None: 0% probability

#### Control Effectiveness Mapping

Each control type maps to a likelihood ratio:

```python
LR_control = {
    "advanced": 0.3,    # 70% risk reduction
    "intermediate": 0.5, # 50% risk reduction
    "basic": 0.7,       # 30% risk reduction
    "none": 1.0         # No effect
}
```

### 3. Kill-Chain Probability Model

The kill-chain model calculates stage-by-stage exploitation probability through a multi-component application.

#### Stage Probabilities

For each stage s in {reconnaissance, weaponization, delivery, exploitation, installation, command_control, actions_on_objectives}:

```
P(stage_s | controls, architecture) = base_probability_s * product(LR_control_i)
```

#### Overall Probability

The overall kill-chain probability is the product of stage probabilities:

```
P(successful_attack) = product of P(stage_s) for all s in stages
```

This represents the probability of successfully completing all stages.

#### Control Impact

Controls affect specific stages:
- **Firewall**: Reduces delivery probability
- **WAF**: Reduces exploitation probability
- **IDS/IPS**: Reduces command & control probability
- **Segmentation**: Reduces lateral movement probability

### 4. Monte Carlo Simulation

Monte Carlo simulation generates probability distributions by repeated sampling.

#### Iteration Process

For each iteration i = 1, 2, ..., N:

1. **Generate controls**: Sample from P(control_type | maturity)
2. **Map to LRs**: Convert control types to likelihood ratios
3. **Calculate posterior**: Apply Bayesian updating to each vulnerability
4. **Calculate kill-chain**: Compute overall exploitation probability
5. **Record metrics**: Store results for statistical analysis

#### Convergence

The simulation converges to the true distribution as N approaches infinity. In practice, N = 1000 provides stable estimates.

**Convergence criterion:**
```
|mean(iterations[1:N]) - mean(iterations[1:N-100])| < ε
```

Where ε = 0.001 (0.1% change threshold).

### 5. Bayesian Statistical Analysis

Analysis uses pure Bayesian methods without frequentist hypothesis testing.

#### Descriptive Statistics with Uncertainty

For any metric M (e.g., kill-chain probability):

**Point estimates:**
- Mean: E[M] = (1/N) ∑ Mᵢ
- Median: M₅₀ = 50th percentile
- Mode: Most frequent value

**Uncertainty quantification:**
- Standard deviation: σ = √(Var[M])
- Percentiles: M_p = pth percentile
- Credible intervals: Bootstrap resampling

#### Bootstrap Credible Intervals

Credible intervals are computed via bootstrap resampling:

1. Resample with replacement: M* = {M*₁, M*₂, ..., M*ₙ}
2. Calculate statistic: θ* = f(M*)
3. Repeat B times (B = 10,000)
4. Credible interval: [θ*₂.₅%, θ*₉₇.₅%] for 95% CI

**Interpretation:**
"There is 95% probability that the true mean lies within [lower, upper]"

This is a Bayesian credible interval, not a frequentist confidence interval.

#### Scenario Comparison

To compare two scenarios (e.g., initial vs. optimizing maturity):

**Probability of superiority:**
```
P(scenario2 < scenario1) = (1/N) ∑ I(M₂ᵢ < M₁ᵢ)
```

Where I() is the indicator function.

**Expected difference:**
```
E[Δ] = E[M₁ - M₂] = (1/N) ∑ (M₁ᵢ - M₂ᵢ)
```

**Credible interval for difference:**
Bootstrap the difference distribution to get CI.

**Interpretation:**
"There is 99.8% probability that optimizing maturity has lower risk than initial maturity. Expected risk reduction: 68% (95% CI: [62%, 74%])"

### 6. Control Effectiveness Analysis

Analyze which controls are most effective by stratifying results.

#### Stratified Analysis

For each control type c:

```
E[risk | control = c] = mean(risk for iterations where control = c)
```

#### Marginal Effectiveness

The marginal effectiveness of control c:

```
Δ_c = E[risk | control = none] - E[risk | control = c]
```

#### Control ROI Estimation

Relative risk reduction:

```
RRR_c = Δ_c / E[risk | control = none]
```

This quantifies the percentage risk reduction from implementing control c.

## Mathematical Foundations

### Bayes' Theorem (Odds Form)

Starting from standard Bayes' theorem:

```
P(H|E) = P(E|H) * P(H) / P(E)
```

Converting to odds:

```
Odds(H|E) = P(H|E) / P(¬H|E)
          = [P(E|H) / P(E|not H)] * [P(H) / P(not H)]
          = LR * Prior_odds
```

For multiple independent evidence sources:

```
Posterior_odds = Prior_odds * LR1 * LR2 * ... * LRn
```

### Law of Total Probability

For kill-chain stages:

```
P(success) = P(stage1) * P(stage2|stage1) * ... * P(stageN|stage1,...,stageN-1)
```

Assuming conditional independence given controls:

```
P(success) approximately equals product of P(stage_i | controls) for all i
```

### Central Limit Theorem

As N approaches infinity, the distribution of sample means converges to normal:

```
sqrt(N) * (X_bar - mu) converges in distribution to N(0, sigma^2)
```

This justifies using bootstrap methods for credible intervals even with non-normal risk distributions.

## Assumptions and Limitations

### Assumptions

1. **Independence**: Vulnerabilities are independent given controls
2. **Stationarity**: Control effectiveness doesn't change during simulation
3. **Conditional independence**: Kill-chain stages are independent given controls
4. **EPSS accuracy**: EPSS scores accurately reflect baseline exploitation probability
5. **LR calibration**: Likelihood ratios are correctly calibrated

### Limitations

1. **Historical data**: Limited validation data for control effectiveness
2. **Interaction effects**: Control interactions not fully modeled
3. **Temporal dynamics**: No time-varying risk modeling
4. **Adversary adaptation**: Doesn't model adversary learning
5. **Zero-day vulnerabilities**: Not included in EPSS-based priors

### Validation Approaches

1. **Backtesting**: Compare predictions to historical breach data
2. **Expert elicitation**: Validate LR values with security experts
3. **Sensitivity analysis**: Test robustness to parameter variations
4. **Cross-validation**: Hold-out testing on vulnerability subsets

## Computational Complexity

### Time Complexity

**Per iteration:**
- Control generation: O(k) where k = number of control types
- Bayesian updating: O(n) where n = number of vulnerabilities
- Kill-chain calculation: O(s * c) where s = stages, c = components

**Total:** O(N * n) where N = iterations, n = vulnerabilities

**With caching:** O(n + N * k) - vulnerability data cached, only controls regenerated

### Space Complexity

- Cached data: O(n) - vulnerability dataset
- Iteration results: O(N * m) where m = metrics per iteration
- Typical: ~50 MB cache + ~10 MB results for N=1000

## References

### Bayesian Methods
- Clayton, A. (2021). "Bernoulli's Fallacy: Statistical Illogic and the Crisis of Modern Science"
- Downey, A. (2021). "Think Bayes: Bayesian Statistics in Python"
- [Odds space explanation](https://www.youtube.com/watch?v=lG4VkPoG3ko)

### Risk Assessment
- Hubbard, D. & Seiersen, R. (2016). "How to Measure Anything in Cybersecurity Risk"
- Seiersen, R. (2023). "Metrics Manifesto: Confronting Security with Data"

### Monte Carlo Methods
- Metropolis, N. & Ulam, S. (1949). "The Monte Carlo Method"
- Robert, C. & Casella, G. (2004). "Monte Carlo Statistical Methods"

### Forecasting
- Tetlock, P. & Gardner, D. (2015). "Superforecasting: The Art and Science of Prediction"

### Statistical Computing
- Downey, A. (2024). "Think Python"
- [Bayesian statistics exercises](https://github.com/AllenDowney/ThinkBayes2)
