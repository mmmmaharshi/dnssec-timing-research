#!/usr/bin/env python3
"""
leakage_quantification.py - Quantify information leakage in DNSSEC cache timing data

Computes:
1. Per-cache-set mutual information with algorithm label
2. Channel capacity bound (max MI across cache sets)
3. Template attack distinguisher (per-set mean difference)
4. Entropy analysis of cache patterns
5. Leakage rate (bits per measurement)

Usage:
    python leakage_quantification.py --input ../results_cache_attack/combined_cache.csv

Author: DNSSEC Timing Research
"""

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import entropy as scipy_entropy


def load_cache_data(csv_path: str) -> tuple:
    """Load cache timing CSV. Returns (timing_matrix, labels, cache_set_indices)."""
    print(f"[*] Loading data from {csv_path}")
    df = pd.read_csv(csv_path)

    labels = df["label"].values
    timing_data = df.drop(columns=["round", "label"], errors="ignore")
    cache_cols = [c for c in timing_data.columns if c.startswith("cache_")]
    cache_indices = [int(c.split("_")[1]) for c in cache_cols]

    X = timing_data[cache_cols].values.astype(np.float64)
    print(f"[*] Loaded {X.shape[0]} samples, {X.shape[1]} cache sets")
    print(f"[*] Classes: {np.unique(labels)}")

    return X, labels, np.array(cache_indices)


def clip_outliers(X: np.ndarray, max_cycles: int = 1000) -> np.ndarray:
    """Clip extreme measurement outliers (cache hits < 1000 cycles typical)."""
    clipped = np.clip(X, 0, max_cycles)
    n_clipped = np.sum(X > max_cycles)
    if n_clipped > 0:
        print(f"[*] Clipped {n_clipped} outlier values > {max_cycles} cycles")
    return clipped


def compute_label_entropy(labels: np.ndarray) -> float:
    """Compute entropy of the label distribution (max possible information)."""
    unique, counts = np.unique(labels, return_counts=True)
    probs = counts / counts.sum()
    H = scipy_entropy(probs, base=2)
    print(f"\n[*] Label distribution: {dict(zip(unique, counts))}")
    print(f"[*] Label entropy H(Y): {H:.4f} bits (max information about algorithm)")
    return H


def compute_mutual_information_per_set(
    X: np.ndarray, labels: np.ndarray, n_bins: int = 20
) -> np.ndarray:
    """
    Compute mutual information I(X_i; Y) for each cache set i.

    Uses histogram-based MI estimation with discretized timing values.
    """
    n_sets = X.shape[1]
    mi_per_set = np.zeros(n_sets)
    unique_labels = np.unique(labels)
    n_labels = len(unique_labels)

    # Discretize timing values into bins per cache set
    print(f"\n[*] Computing per-cache-set mutual information ({n_sets} sets)...")

    for i in range(n_sets):
        timings = X[:, i]

        # Create bins for this cache set
        bins = np.linspace(timings.min(), timings.max() + 1, n_bins + 1)
        digitized = np.digitize(timings, bins) - 1
        digitized = np.clip(digitized, 0, n_bins - 1)

        # Compute joint and marginal probabilities
        mi = 0.0
        for y_idx, label in enumerate(unique_labels):
            y_mask = labels == label
            p_y = np.sum(y_mask) / len(labels)

            for bin_idx in range(n_bins):
                # P(X_i in bin, Y=y)
                p_xy = np.sum((digitized == bin_idx) & y_mask) / len(labels)
                # P(X_i in bin)
                p_x = np.sum(digitized == bin_idx) / len(labels)

                if p_xy > 0 and p_x > 0:
                    mi += p_xy * np.log2(p_xy / (p_x * p_y))

        mi_per_set[i] = mi

    return mi_per_set


def compute_template_leakage(
    X: np.ndarray, labels: np.ndarray
) -> tuple:
    """
    Compute template attack leakage: per-cache-set mean difference between classes.

    Returns:
        mean_per_class: Mean timing per class per cache set
        std_per_class: Std timing per class per cache set
        snr_per_set: Signal-to-noise ratio per cache set
    """
    unique_labels = np.unique(labels)
    n_sets = X.shape[1]
    n_classes = len(unique_labels)

    mean_per_class = np.zeros((n_classes, n_sets))
    std_per_class = np.zeros((n_classes, n_sets))

    for i, label in enumerate(unique_labels):
        mask = labels == label
        mean_per_class[i] = np.mean(X[mask], axis=0)
        std_per_class[i] = np.std(X[mask], axis=0)

    # SNR: between-class variance / within-class variance
    overall_mean = np.mean(X, axis=0)
    between_class_var = np.var(mean_per_class, axis=0)
    within_class_var = np.mean(std_per_class ** 2, axis=0)

    snr_per_set = np.where(within_class_var > 0,
                           between_class_var / within_class_var, 0)

    return mean_per_class, std_per_class, snr_per_set, unique_labels


def identify_leaky_cache_sets(
    mi_per_set: np.ndarray,
    snr_per_set: np.ndarray,
    cache_indices: np.ndarray,
    top_k: int = 20,
) -> pd.DataFrame:
    """Identify the cache sets with highest leakage."""
    # Top sets by mutual information
    top_mi_idx = np.argsort(mi_per_set)[::-1][:top_k]

    # Top sets by SNR
    top_snr_idx = np.argsort(snr_per_set)[::-1][:top_k]

    print(f"\n[***] TOP {top_k} LEAKY CACHE SETS (by Mutual Information):")
    print(f"{'Rank':<6} {'Cache Set':<12} {'MI (bits)':<12} {'SNR':<10}")
    print("-" * 40)
    for rank, idx in enumerate(top_mi_idx, 1):
        print(f"{rank:<6} {cache_indices[idx]:<12} {mi_per_set[idx]:<12.6f} {snr_per_set[idx]:<10.4f}")

    # Create summary dataframe
    leak_df = pd.DataFrame({
        "cache_set": cache_indices[top_mi_idx],
        "mutual_info_bits": mi_per_set[top_mi_idx],
        "snr": snr_per_set[top_mi_idx],
    })

    return leak_df


def compute_channel_capacity_bound(mi_per_set: np.ndarray) -> dict:
    """
    Compute bounds on information leakage rate.

    Returns capacity estimates based on per-set MI.
    """
    max_mi = np.max(mi_per_set)
    mean_mi = np.mean(mi_per_set)
    total_mi_bound = np.sum(mi_per_set)  # Union bound (overestimate)
    n_leaky = np.sum(mi_per_set > 0.001)  # Sets with > 1 mbit leakage

    # Fraction of cache sets that leak
    leak_fraction = n_leaky / len(mi_per_set)

    results = {
        "max_mi_per_set": max_mi,
        "mean_mi_per_set": mean_mi,
        "total_mi_union_bound": total_mi_bound,
        "n_leaky_sets": n_leaky,
        "leak_fraction": leak_fraction,
    }

    print(f"\n[***] CHANNEL CAPACITY BOUND:")
    print(f"    Max MI (single cache set): {max_mi:.6f} bits")
    print(f"    Mean MI (per cache set):   {mean_mi:.6f} bits")
    print(f"    Union bound (total):        {total_mi_bound:.4f} bits")
    print(f"    Leaky sets (>1 mbit):       {n_leaky} / {len(mi_per_set)} ({leak_fraction:.1%})")

    return results


def evaluate_ct_countermeasure(
    X: np.ndarray, labels: np.ndarray, threshold: float = 120
) -> dict:
    """
    Evaluate constant-time countermeasure effectiveness.

    A perfect CT implementation should have:
    - No correlation between cache pattern and algorithm
    - Uniform miss rates across algorithms
    """
    unique_labels = np.unique(labels)
    n_sets = X.shape[1]

    # Compute miss rate per algorithm (fraction of sets above threshold)
    miss_rates = {}
    for label in unique_labels:
        mask = labels == label
        misses = np.mean(X[mask] > threshold, axis=1)  # Per-sample miss rate
        miss_rates[label] = {
            "mean": np.mean(misses),
            "std": np.std(misses),
        }

    # CT effectiveness: variance of miss rates across algorithms (lower = better)
    miss_rate_means = [miss_rates[l]["mean"] for l in unique_labels]
    ct_score = np.var(miss_rate_means)

    print(f"\n[***] CONSTANT-TIME COUNTERMEASURE EVALUATION:")
    print(f"    Miss rates (threshold={threshold} cycles):")
    for label in unique_labels:
        mr = miss_rates[label]
        print(f"      {label:<12}: {mr['mean']:.4f} +/- {mr['std']:.4f}")
    print(f"    CT score (variance across algorithms): {ct_score:.6f}")
    print(f"    Interpretation: {'GOOD' if ct_score < 0.001 else 'POOR'} (lower is better)")

    return miss_rates, ct_score


def main():
    parser = argparse.ArgumentParser(
        description="Quantify information leakage in DNSSEC cache timing data"
    )
    parser.add_argument(
        "--input", "-i",
        default="../results_cache_attack/combined_cache.csv",
        help="Path to combined cache timing CSV",
    )
    parser.add_argument(
        "--output", "-o",
        default="../results_cache_attack/leakage_analysis.csv",
        help="Output path for leakage results",
    )
    parser.add_argument(
        "--bins", type=int, default=20,
        help="Number of bins for MI estimation",
    )
    parser.add_argument(
        "--top-k", type=int, default=20,
        help="Number of top leaky sets to report",
    )

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)

    # Load and preprocess
    X, labels, cache_indices = load_cache_data(args.input)
    X = clip_outliers(X, max_cycles=1000)

    # 1. Label entropy (max possible information)
    H_Y = compute_label_entropy(labels)

    # 2. Per-cache-set mutual information
    mi_per_set = compute_mutual_information_per_set(X, labels, n_bins=args.bins)

    # 3. Template leakage (SNR)
    mean_per_class, std_per_class, snr_per_set, unique_labels = \
        compute_template_leakage(X, labels)

    # 4. Identify leaky cache sets
    leak_df = identify_leaky_cache_sets(
        mi_per_set, snr_per_set, cache_indices, top_k=args.top_k
    )

    # 5. Channel capacity bound
    capacity = compute_channel_capacity_bound(mi_per_set)

    # 6. CT countermeasure evaluation
    miss_rates, ct_score = evaluate_ct_countermeasure(X, labels)

    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Save per-set leakage
    leakage_df = pd.DataFrame({
        "cache_set": cache_indices,
        "mutual_info_bits": mi_per_set,
        "snr": snr_per_set,
    })
    leakage_df = leakage_df.sort_values("mutual_info_bits", ascending=False)
    leakage_df.to_csv(output_path, index=False)
    print(f"\n[*] Leakage analysis saved to {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"LEAKAGE QUANTIFICATION SUMMARY")
    print(f"{'='*60}")
    print(f"Label entropy H(Y):          {H_Y:.4f} bits (max recoverable)")
    print(f"Max MI (single cache set):   {capacity['max_mi_per_set']:.6f} bits")
    print(f"Mean MI (per cache set):     {capacity['mean_mi_per_set']:.6f} bits")
    print(f"Leaky sets (>1 mbit):        {capacity['n_leaky_sets']} / {len(mi_per_set)}")
    print(f"CT countermeasure score:     {ct_score:.6f}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
