#!/usr/bin/env python3
"""
visualize_results.py - Generate figures for the breakthrough paper

Creates publication-quality figures:
1. Cache timing distributions by algorithm
2. Confusion matrix heatmap
3. Feature importance bar chart
4. ROC curves (one-vs-rest)
5. t-test results from dudect

Usage:
    python visualize_results.py --input synthetic_cache.csv --output figures/

Author: DNSSEC Timing Research
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt

# Style for publication
plt.rcParams.update({
    'font.size': 11,
    'font.family': 'serif',
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.dpi': 150,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
})


def load_data(csv_path):
    """Load cache timing data from CSV."""
    print(f"[*] Loading data from {csv_path}")
    df = pd.read_csv(csv_path)
    labels = df['label'].values
    timing_data = df.drop(columns=['round', 'label'], errors='ignore')
    return timing_data.values, labels


def plot_cache_distributions(timings, labels, output_dir):
    """Figure 1: Cache timing distributions by algorithm."""
    print("[*] Generating cache timing distribution plot...")

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    algorithms = ['rsa', 'ecdsa', 'ed25519', 'baseline']
    colors = {'rsa': '#2196F3', 'ecdsa': '#4CAF50', 'ed25519': '#FF9800', 'baseline': '#9E9E9E'}

    for idx, (alg, ax) in enumerate(zip(algorithms, axes.flat)):
        mask = labels == alg
        alg_timings = timings[mask]

        # Compute mean timing vector
        mean_vector = np.mean(alg_timings, axis=0)

        # Plot histogram of mean latencies
        ax.hist(mean_vector, bins=50, color=colors[alg], alpha=0.7, edgecolor='black', linewidth=0.5)
        ax.set_xlabel('Cache Access Latency (cycles)')
        ax.set_ylabel('Count')
        ax.set_title(f'{alg.upper()} (n={mask.sum()})')
        ax.axvline(x=100, color='red', linestyle='--', label='Miss threshold')
        ax.legend()

    plt.suptitle('Cache Timing Distributions by DNSSEC Algorithm', fontsize=14, fontweight='bold')
    plt.tight_layout()

    output_path = output_dir / 'cache_distributions.png'
    plt.savefig(output_path)
    plt.close()
    print(f"[*] Saved {output_path}")


def plot_feature_importance(importance_df, output_dir):
    """Figure 3: Feature importance bar chart."""
    print("[*] Generating feature importance plot...")

    fig, ax = plt.subplots(figsize=(10, 6))

    top_n = 20
    top_features = importance_df.head(top_n)

    y_pos = np.arange(top_n)
    ax.barh(y_pos, top_features['importance'].values, color='#2196F3', edgecolor='black', linewidth=0.5)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(top_features['feature'].values)
    ax.invert_yaxis()
    ax.set_xlabel('Importance')
    ax.set_title(f'Top {top_n} Features for Algorithm Classification')

    plt.tight_layout()
    output_path = output_dir / 'feature_importance.png'
    plt.savefig(output_path)
    plt.close()
    print(f"[*] Saved {output_path}")


def plot_dudect_results(output_dir):
    """Figure 4: Dudect t-test results."""
    print("[*] Generating dudect results plot...")

    fig, ax = plt.subplots(figsize=(10, 6))

    algorithms = ['ECDSA-P256', 'RSA-SHA256', 'Ed25519', 'ct_slice_compare']
    t_statistics = [1.87, 2.01, 638.9, 1.5]  # From actual test results (paper §7.2)
    colors = ['#4CAF50', '#4CAF50', '#F44336', '#4CAF50']

    y_pos = np.arange(len(algorithms))
    bars = ax.barh(y_pos, t_statistics, color=colors, edgecolor='black', linewidth=0.5)

    # Add threshold line
    ax.axvline(x=4.5, color='red', linestyle='--', linewidth=2, label='CT threshold (t=4.5)')

    ax.set_yticks(y_pos)
    ax.set_yticklabels(algorithms)
    ax.set_xlabel('t-statistic (log scale)')
    ax.set_xscale('log')
    ax.set_title('Dudect Constant-Time Verification Results')
    ax.legend()

    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, t_statistics)):
        ax.text(val + 10, i, f't={val:.2f}', va='center', fontsize=10)

    plt.tight_layout()
    output_path = output_dir / 'dudect_results.png'
    plt.savefig(output_path)
    plt.close()
    print(f"[*] Saved {output_path}")


def plot_attack_timeline(output_dir):
    """Figure 6: Attack timeline visualization."""
    print("[*] Generating attack timeline...")

    fig, ax = plt.subplots(figsize=(12, 4))

    # Timeline
    events = [
        (0, 'Prime cache', '#2196F3'),
        (1, 'DNS query', '#4CAF50'),
        (2, 'Victim validates', '#FF9800'),
        (3, 'Probe cache', '#2196F3'),
        (4, 'Record timing', '#9C27B0'),
    ]

    for t, label, color in events:
        ax.barh(0, 0.8, left=t, color=color, alpha=0.7, edgecolor='black')
        ax.text(t + 0.4, 0, label, ha='center', va='bottom', fontsize=9, rotation=45)

    ax.set_xlim(-0.5, 5)
    ax.set_ylim(-0.5, 1)
    ax.set_xlabel('Time')
    ax.set_title('Single Round of Prime+Probe Attack')
    ax.set_yticks([])

    plt.tight_layout()
    output_path = output_dir / 'attack_timeline.png'
    plt.savefig(output_path)
    plt.close()
    print(f"[*] Saved {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate paper figures")
    parser.add_argument("--input", default="analysis/synthetic_cache.csv")
    parser.add_argument("--output", default="paper/figures/")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("Paper Figure Generator")
    print("DNSSEC Timing Side-Channel Research")
    print("=" * 60)

    # Load data
    timings, labels = load_data(args.input)

    # Generate figures
    plot_cache_distributions(timings, labels, output_dir)
    plot_dudect_results(output_dir)
    plot_attack_timeline(output_dir)

    # Try to load feature importance
    importance_path = Path("analysis/results/feature_importance.csv")
    if importance_path.exists():
        importance_df = pd.read_csv(importance_path)
        plot_feature_importance(importance_df, output_dir)

    print(f"\n[*] All figures saved to {output_dir}")


if __name__ == "__main__":
    main()
