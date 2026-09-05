#!/usr/bin/env python3
"""
Statistical Analysis of DNSSEC Timing Data

Performs:
1. Distribution analysis (mean, median, percentiles)
2. Welch's t-test for timing differences between outcomes
3. Effect size computation (Cohen's d)
4. Timing distinguisher classifier
5. Minimum sample size estimation
"""

import argparse
import csv
import os
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

import numpy as np
from scipy import stats as scipy_stats
from scipy.stats import norm


def load_timings(filepath: str) -> Dict[str, Dict[str, List[int]]]:
    """Load timing data from CSV. Returns {resolver: {outcome: [times]}}."""
    data = defaultdict(lambda: defaultdict(list))

    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            resolver = row["resolver"]
            outcome = row["outcome"]
            time_ns = int(row["query_time_ns"])
            error = row.get("error", "")

            if not error and time_ns > 0:
                data[resolver][outcome].append(time_ns)

    return dict(data)


def compute_statistics(times: List[int]) -> Dict:
    """Compute descriptive statistics for a list of timings."""
    arr = np.array(times)
    return {
        "n": len(arr),
        "mean": np.mean(arr),
        "median": np.median(arr),
        "std": np.std(arr),
        "min": np.min(arr),
        "max": np.max(arr),
        "p5": np.percentile(arr, 5),
        "p25": np.percentile(arr, 25),
        "p75": np.percentile(arr, 75),
        "p95": np.percentile(arr, 95),
        "p99": np.percentile(arr, 99),
    }


def welch_ttest(group1: List[int], group2: List[int]) -> Tuple[float, float]:
    """Perform Welch's t-test. Returns (t-statistic, p-value)."""
    t_stat, p_value = scipy_stats.ttest_ind(group1, group2, equal_var=False)
    return t_stat, p_value


def cohens_d(group1: List[int], group2: List[int]) -> float:
    """Compute Cohen's d effect size."""
    arr1 = np.array(group1)
    arr2 = np.array(group2)

    n1, n2 = len(arr1), len(arr2)
    var1, var2 = np.var(arr1, ddof=1), np.var(arr2, ddof=1)

    # Pooled standard deviation
    pooled_std = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))

    if pooled_std == 0:
        return 0.0

    return (np.mean(arr1) - np.mean(arr2)) / pooled_std


def estimate_min_samples(
    group1: List[int],
    group2: List[int],
    target_power: float = 0.95,
    alpha: float = 0.05,
) -> int:
    """Estimate minimum sample size needed for statistical significance."""
    if len(group1) < 2 or len(group2) < 2:
        return 0

    arr1, arr2 = np.array(group1, dtype=np.float64), np.array(group2, dtype=np.float64)

    var1, var2 = np.var(arr1, ddof=1), np.var(arr2, ddof=1)
    pooled_var = (var1 + var2) / 2

    if pooled_var == 0:
        return 0

    effect_size = abs(np.mean(arr1) - np.mean(arr2)) / np.sqrt(pooled_var)

    if effect_size == 0:
        return 0

    # Using power analysis approximation
    z_alpha = norm.ppf(1 - alpha / 2)
    z_beta = norm.ppf(target_power)

    n = 2 * ((z_alpha + z_beta) / effect_size) ** 2
    return int(np.ceil(n))


def analyze_resolver(resolver: str, data: Dict[str, List[int]]) -> None:
    """Perform full analysis for a single resolver."""
    print(f"\n{'='*70}")
    print(f"Resolver: {resolver}")
    print(f"{'='*70}")

    outcomes = list(data.keys())

    # 1. Descriptive statistics
    print("\n--- Descriptive Statistics ---")
    print(f"{'Outcome':<20} {'N':>8} {'Mean(ms)':>10} {'Median(ms)':>10} {'Std(ms)':>10} {'P5-P95(ms)':>15}")
    print("-" * 75)

    outcome_stats = {}
    for outcome in sorted(outcomes):
        times = data[outcome]
        s = compute_statistics(times)
        outcome_stats[outcome] = s
        print(f"{outcome:<20} {s['n']:>8} {s['mean']/1e6:>10.3f} {s['median']/1e6:>10.3f} {s['std']/1e6:>10.3f} {s['p5']/1e6:>7.3f}-{s['p95']/1e6:.3f}")

    # 2. Pairwise comparisons
    print("\n--- Pairwise Comparisons (Welch's t-test) ---")
    print(f"{'Comparison':<40} {'t-stat':>10} {'p-value':>12} {'Cohen d':>10} {'Sig?':>6}")
    print("-" * 82)

    comparisons = []
    for i, o1 in enumerate(outcomes):
        for o2 in outcomes[i+1:]:
            t_stat, p_val = welch_ttest(data[o1], data[o2])
            d = cohens_d(data[o1], data[o2])
            sig = "***" if p_val < 0.001 else "**" if p_val < 0.01 else "*" if p_val < 0.05 else ""

            comparison_name = f"{o1} vs {o2}"
            print(f"{comparison_name:<40} {t_stat:>10.3f} {p_val:>12.2e} {d:>10.3f} {sig:>6}")
            comparisons.append({
                "comparison": comparison_name,
                "t_stat": t_stat,
                "p_value": p_val,
                "cohens_d": d,
                "significant": p_val < 0.05,
            })

    # 3. Minimum sample size estimation
    print("\n--- Minimum Sample Size Estimation (power=0.95, alpha=0.05) ---")
    for comp in comparisons:
        o1, o2 = comp["comparison"].split(" vs ")
        if o1 in data and o2 in data:
            min_n = estimate_min_samples(data[o1], data[o2])
            print(f"  {comp['comparison']}: {min_n} samples needed")


def main():
    parser = argparse.ArgumentParser(description="Analyze DNSSEC timing data")
    parser.add_argument(
        "--input",
        default="../results/raw_timings.csv",
        help="Path to raw timings CSV",
    )
    parser.add_argument(
        "--output",
        default="../results/analysis_report.txt",
        help="Path to output report",
    )

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        print("Run timing_harness.py first to collect data.")
        sys.exit(1)

    print("Loading timing data...")
    data = load_timings(args.input)

    # Redirect output to file
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        sys.stdout = f

        print("=" * 70)
        print("DNSSEC Timing Side-Channel Analysis Report")
        print("=" * 70)

        for resolver, resolver_data in data.items():
            analyze_resolver(resolver, resolver_data)

        print("\n" + "=" * 70)
        print("Analysis complete.")
        print("=" * 70)

    sys.stdout = sys.__stdout__
    print(f"Analysis report saved to: {args.output}")


if __name__ == "__main__":
    main()
