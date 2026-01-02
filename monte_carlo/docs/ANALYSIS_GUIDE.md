# Monte Carlo Analysis Guide

## Introduction

This guide explains how to interpret Monte Carlo simulation results and make informed decisions based on the analysis. It focuses on practical interpretation rather than mathematical theory.

## Understanding Your Results

### 1. Distribution Plots

Distribution plots show how risk varies across iterations.

#### What to Look For

**Shape of distribution:**
- **Narrow distribution**: Consistent risk across scenarios (predictable)
- **Wide distribution**: High variability (uncertain)
- **Skewed right**: Occasional high-risk scenarios (tail risk)
- **Bimodal**: Two distinct risk profiles (investigate why)

**Key markers:**
- **Mean (red dashed line)**: Average risk across all iterations
- **Median (green dashed line)**: Middle value (50th percentile)
- **95% Credible Interval (gray shading)**: Where 95% of outcomes fall

**Interpretation example:**
```
Mean: 0.35 (35% exploitation probability)
Median: 0.32 (32% exploitation probability)
95% CI: [0.22, 0.51]

Translation: "On average, there's a 35% chance of successful attack. 
In 95% of scenarios, risk falls between 22% and 51%."
```

#### When Mean ≠ Median

If mean > median: Distribution is right-skewed (tail risk exists)
- Example: Mean 0.40, Median 0.35
- Interpretation: "Most scenarios have ~35% risk, but a few high-risk outliers pull the average up to 40%"

**Action:** Investigate high-risk scenarios to understand what drives tail risk.

### 2. Credible Intervals

Credible intervals quantify uncertainty in your estimates.

#### Reading Credible Intervals

**95% Credible Interval: [0.28, 0.38]**

Bayesian interpretation:
"There is 95% probability that the true mean risk lies between 28% and 38%"

This is NOT a frequentist confidence interval. It's a direct probability statement about where the true value lies.

#### Width Matters

**Narrow interval** (e.g., [0.30, 0.32]):
- High confidence in estimate
- Consistent outcomes across iterations
- Reliable for decision-making

**Wide interval** (e.g., [0.15, 0.55]):
- High uncertainty
- Variable outcomes
- Need more iterations or better data

**Rule of thumb:** If CI width > 20% of mean, consider running more iterations.

### 3. Scenario Comparisons

Comparing scenarios answers: "Is one approach actually better?"

#### Probability of Superiority

**"99.8% probability that optimizing maturity has lower risk"**

This is the key Bayesian metric. It directly answers: "How confident are we that scenario A is better than scenario B?"

**Interpretation thresholds:**
- **> 99%**: Very strong evidence (act with confidence)
- **95-99%**: Strong evidence (reasonable to act)
- **90-95%**: Moderate evidence (consider carefully)
- **80-90%**: Weak evidence (more data needed)
- **< 80%**: Insufficient evidence (scenarios may be similar)

#### Expected Risk Reduction

**"Expected risk reduction: 68% (95% CI: [62%, 74%])"**

This tells you:
1. **Point estimate**: On average, risk drops by 68%
2. **Uncertainty**: We're 95% confident the reduction is between 62-74%

**Decision-making:**
- If lower bound > 0: Clear benefit
- If CI includes 0: Uncertain benefit
- If lower bound < 0: Possible harm

#### Relative vs. Absolute Reduction

**Relative reduction: 68%**
- Risk drops from 0.45 to 0.14 (68% reduction)

**Absolute reduction: 0.31**
- Risk drops by 31 percentage points

Both matter:
- **Relative**: Shows proportional improvement
- **Absolute**: Shows actual risk change

### 4. Control Effectiveness

Control effectiveness analysis shows which controls provide the most risk reduction.

#### Reading Control Charts

**Mean risk by control type:**
```
Advanced WAF:     0.12 (n=450)
Intermediate WAF: 0.25 (n=350)
Basic WAF:        0.38 (n=150)
None:             0.55 (n=50)
```

**Interpretation:**
- Advanced WAF reduces risk to 12% (from 55% baseline)
- 78% relative risk reduction
- Selected in 450/1000 iterations (45% of time)

#### Marginal Effectiveness

**Question:** "Is upgrading from intermediate to advanced WAF worth it?"

**Analysis:**
- Intermediate: 0.25 risk
- Advanced: 0.12 risk
- Marginal reduction: 0.13 (13 percentage points)
- Relative improvement: 52% additional reduction

**Decision:** If upgrade cost < value of 13% risk reduction, upgrade.

### 5. Percentiles (Risk Thresholds)

Percentiles help set risk thresholds and understand tail risk.

#### Common Percentiles

**p50 (Median):** Typical scenario
**p95:** Worst-case in 95% of scenarios
**p99:** Extreme scenario (1 in 100)

**Example:**
```
p50: 0.32 (32% risk in typical scenario)
p95: 0.51 (51% risk in worst 5% of scenarios)
p99: 0.68 (68% risk in extreme 1% of scenarios)
```

#### Setting Risk Thresholds

**Risk appetite:** "We accept up to 40% exploitation probability"

**Analysis:**
- p50 = 0.32: Typical scenario is acceptable
- p95 = 0.51: 5% of scenarios exceed threshold
- p99 = 0.68: Extreme scenarios significantly exceed threshold

**Action:** Implement additional controls to reduce p95 and p99.

## Common Decision Scenarios

### Scenario 1: Maturity Level Investment

**Question:** "Should we invest in moving from 'managed' to 'optimizing' maturity?"

**Analysis steps:**
1. Run Monte Carlo for both maturity levels
2. Compare distributions
3. Calculate probability optimizing is better
4. Estimate expected risk reduction
5. Compare cost vs. benefit

**Example result:**
```
Probability optimizing is better: 99.2%
Expected risk reduction: 65% (95% CI: [58%, 71%])
Absolute reduction: 0.28 (28 percentage points)

Cost of maturity upgrade: $500K/year
Value of 28% risk reduction: $2M/year (estimated breach cost × reduction)

ROI: 4:1 (clear benefit)
```

**Decision:** Invest in maturity upgrade.

### Scenario 2: Control Selection

**Question:** "Which control type should we prioritize?"

**Analysis steps:**
1. Run Monte Carlo with different control configurations
2. Calculate mean risk for each control type
3. Rank by effectiveness
4. Consider cost and implementation difficulty

**Example result:**
```
Control Effectiveness (risk reduction from baseline):
1. Advanced SIEM: 72% reduction (cost: $$$$)
2. Advanced WAF: 68% reduction (cost: $$$)
3. Network Segmentation: 55% reduction (cost: $$)
4. Advanced Firewall: 45% reduction (cost: $$)
```

**Decision:** Prioritize WAF (high effectiveness, moderate cost) over SIEM (slightly higher effectiveness, much higher cost).

### Scenario 3: Risk Acceptance

**Question:** "Can we accept current risk level?"

**Analysis steps:**
1. Run Monte Carlo for current state
2. Compare p95 to risk threshold
3. Calculate probability of exceeding threshold
4. Estimate expected loss

**Example result:**
```
Current risk distribution:
- Mean: 0.42 (42%)
- p95: 0.65 (65%)
- p99: 0.78 (78%)

Risk threshold: 40%
Probability exceeding threshold: 58%

Expected annual loss: $1.2M
Cost of additional controls: $300K/year

Net benefit of controls: $900K/year
```

**Decision:** Implement additional controls (clear benefit).

## Best Practices

### 1. Run Sufficient Iterations

**Minimum:** 1000 iterations for stable estimates
**Recommended:** 5000 iterations for critical decisions
**Check convergence:** Plot running mean to verify stability

### 2. Validate Assumptions

**Control effectiveness:** Are LR values realistic?
**EPSS accuracy:** Does EPSS match your threat landscape?
**Independence:** Are vulnerabilities truly independent?

**Action:** Sensitivity analysis to test robustness.

### 3. Consider Context

**Industry:** Financial services has different risk tolerance than retail
**Regulatory:** Compliance requirements may override cost-benefit
**Threat landscape:** Active targeting increases risk beyond EPSS

### 4. Update Regularly

**Frequency:** Quarterly or after major changes
**Triggers:** New vulnerabilities, control changes, threat intelligence

### 5. Communicate Uncertainty

**Always report:**
- Point estimate (mean or median)
- Credible interval (95% CI)
- Probability statements (not p-values)

**Example:**
"There is 95% probability that optimizing maturity reduces risk by 58-71%, with expected reduction of 65%."

## Common Pitfalls

### 1. Ignoring Tail Risk

**Mistake:** Focusing only on mean/median
**Problem:** Misses extreme scenarios
**Solution:** Always check p95 and p99

### 2. Confusing Credible Intervals with Confidence Intervals

**Credible Interval (Bayesian):** "95% probability true value is in interval"
**Confidence Interval (Frequentist):** "If we repeated this 100 times, 95% of intervals would contain true value"

**Use Bayesian interpretation** - it's more intuitive and correct for our framework.

### 3. Over-interpreting Small Differences

**Example:** Scenario A: 0.35, Scenario B: 0.34

**Problem:** Difference may be noise, not signal
**Solution:** Check probability of superiority. If < 80%, scenarios are likely similar.

### 4. Ignoring Costs

**Mistake:** Choosing most effective control regardless of cost
**Problem:** Inefficient resource allocation
**Solution:** Calculate ROI for each control option

### 5. Not Validating Results

**Mistake:** Trusting simulation without validation
**Problem:** Garbage in, garbage out
**Solution:** Compare to historical data, expert judgment, industry benchmarks

## Reporting Results

### Executive Summary Template

```
Monte Carlo Risk Assessment: [Scenario Name]

Key Findings:
- Current risk: [mean]% (95% CI: [lower]% - [upper]%)
- Risk threshold: [threshold]%
- Probability exceeding threshold: [prob]%

Recommendation:
[Action] will reduce risk by [reduction]% (95% CI: [lower]% - [upper]%)
with [confidence]% probability of improvement.

Expected benefit: $[benefit]/year
Implementation cost: $[cost]/year
ROI: [ratio]:1

Confidence: [Very Strong/Strong/Moderate/Weak]
```

### Technical Report Template

Include:
1. **Methodology:** Brief description of approach
2. **Parameters:** Iterations, scenarios, assumptions
3. **Results:** Distributions, comparisons, control analysis
4. **Visualizations:** Key plots with interpretations
5. **Sensitivity Analysis:** Robustness checks
6. **Recommendations:** Prioritized action items
7. **Limitations:** Assumptions and caveats

## Questions and Troubleshooting

### Q: Results seem unstable across runs

**A:** Increase iterations (try 5000 or 10000) or check for bugs in control generation.

### Q: Credible intervals are very wide

**A:** High variability in control effectiveness or vulnerability distribution. Consider more consistent control selection or investigate outliers.

### Q: Probability of superiority is 50%

**A:** Scenarios are essentially equivalent. Look for other decision factors (cost, ease of implementation).

### Q: Results don't match intuition

**A:** Validate assumptions (LR values, EPSS accuracy). Run sensitivity analysis. Consult domain experts.

### Q: How do I explain Bayesian results to management?

**A:** Use probability language: "99% confident that X is better than Y" instead of "statistically significant at p < 0.01". Focus on expected outcomes and credible intervals.

## Further Reading

- Hubbard, D. & Seiersen, R. (2016). "How to Measure Anything in Cybersecurity Risk"
- Tetlock, P. & Gardner, D. (2015). "Superforecasting"
- Clayton, A. (2021). "Bernoulli's Fallacy"
- [Think Bayes](https://allendowney.github.io/ThinkBayes2/)
