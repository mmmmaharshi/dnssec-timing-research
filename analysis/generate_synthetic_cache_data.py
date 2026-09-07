#!/usr/bin/env python3
"""
generate_synthetic_cache_data.py - Generate synthetic cache timing data for classifier demonstration

Since we cannot run the actual Docker attack lab without Docker Desktop WSL integration,
this script generates realistic synthetic cache timing data that simulates what we would
measure from a real Prime+Probe attack.

The synthetic data models:
- RSA: Montgomery multiplication (irregular access, more cache misses)
- ECDSA: Point multiplication (moderate regularity)
- Ed25519: Fixed-base scalar mult + SHA-512 (distinct pattern)

Usage:
    python generate_synthetic_cache_data.py --samples 1000 --output synthetic_cache.csv

Author: DNSSEC Timing Research
"""

import argparse
import os
import sys
import numpy as np
from pathlib import Path

# Cache line parameters
NUM_CACHE_LINES = 8192  # Subset of 131072 for manageable file size
BASELINE_CYCLES = 30     # Cache hit latency
MISS_CYCLES = 200        # Cache miss latency


def generate_rsa_pattern(rng, num_lines=NUM_CACHE_LINES):
    """
    Simulate RSA-SHA256 cache access pattern.

    RSA uses Montgomery multiplication with sliding window exponentiation.
    This creates irregular access patterns with clusters of cache misses
    due to table lookups.

    Characteristics:
    - Higher miss rate (~15-20%)
    - Clustered misses (table lookups)
    - Irregular spatial distribution
    """
    # Base pattern: mostly hits
    pattern = rng.normal(BASELINE_CYCLES, 5, num_lines).astype(np.uint64)

    # Add clusters of misses (simulating table lookups)
    n_clusters = int(rng.random() * 12) + 8  # 8-20 clusters
    for _ in range(n_clusters):
        center = int(rng.random() * num_lines)
        width = int(rng.random() * 25) + 5  # 5-30 width
        start = max(0, center - width // 2)
        end = min(num_lines, center + width // 2)
        pattern[start:end] = rng.normal(MISS_CYCLES, 30, end - start).astype(np.uint64)

    # Add scattered misses
    n_scattered = int(rng.random() * 100) + 50  # 50-150 scattered
    scattered_indices = rng.choice(num_lines, n_scattered, replace=False)
    pattern[scattered_indices] = rng.normal(MISS_CYCLES, 20, n_scattered).astype(np.uint64)

    return np.maximum(pattern, 10)  # Minimum 10 cycles


def generate_ecdsa_pattern(rng, num_lines=NUM_CACHE_LINES):
    """
    Simulate ECDSA-P256 cache access pattern.

    ECDSA uses point double-and-add with field arithmetic.
    More regular access patterns than RSA due to fixed curve parameters.

    Characteristics:
    - Moderate miss rate (~10-15%)
    - More uniform spatial distribution
    - Periodic patterns (point operations)
    """
    # Base pattern: mostly hits
    pattern = rng.normal(BASELINE_CYCLES, 5, num_lines).astype(np.uint64)

    # Add periodic misses (simulating point operations)
    period = int(rng.random() * 100) + 50  # 50-150 period
    for i in range(0, num_lines, period):
        width = int(rng.random() * 7) + 3  # 3-10 width
        end = min(num_lines, i + width)
        pattern[i:end] = rng.normal(MISS_CYCLES, 25, end - i).astype(np.uint64)

    # Add some scattered misses
    n_scattered = int(rng.random() * 50) + 30  # 30-80 scattered
    scattered_indices = rng.choice(num_lines, n_scattered, replace=False)
    pattern[scattered_indices] = rng.normal(MISS_CYCLES, 15, n_scattered).astype(np.uint64)

    return np.maximum(pattern, 10)


def generate_ed25519_pattern(rng, num_lines=NUM_CACHE_LINES):
    """
    Simulate Ed25519 cache access pattern.

    Ed25519 uses SHA-512 prehash followed by fixed-base scalar multiplication.
    Distinct pattern: initial burst (hash) then regular (scalar mult).

    Characteristics:
    - Lower miss rate (~8-12%)
    - Initial burst pattern (SHA-512)
    - Regular trailing pattern (scalar mult)
    """
    # Base pattern: mostly hits
    pattern = rng.normal(BASELINE_CYCLES, 5, num_lines).astype(np.uint64)

    # Initial burst (SHA-512 prehash)
    burst_end = int(rng.random() * 1000) + 500  # 500-1500 burst
    pattern[:burst_end] = rng.normal(MISS_CYCLES * 0.8, 20, burst_end).astype(np.uint64)

    # Regular trailing pattern (scalar multiplication)
    period = int(rng.random() * 100) + 100  # 100-200 period
    for i in range(burst_end, num_lines, period):
        width = int(rng.random() * 4) + 2  # 2-6 width
        end = min(num_lines, i + width)
        pattern[i:end] = rng.normal(MISS_CYCLES * 0.7, 15, end - i).astype(np.uint64)

    # Fewer scattered misses
    n_scattered = int(rng.random() * 30) + 20  # 20-50 scattered
    scattered_indices = rng.choice(num_lines, n_scattered, replace=False)
    pattern[scattered_indices] = rng.normal(MISS_CYCLES, 10, n_scattered).astype(np.uint64)

    return np.maximum(pattern, 10)


def generate_baseline_pattern(rng, num_lines=NUM_CACHE_LINES):
    """Generate baseline pattern (no victim activity)."""
    pattern = rng.normal(BASELINE_CYCLES, 3, num_lines).astype(np.uint64)
    # Very few misses
    n_misses = int(rng.random() * 15) + 5  # 5-20 misses
    miss_indices = rng.choice(num_lines, n_misses, replace=False)
    pattern[miss_indices] = rng.normal(MISS_CYCLES, 10, n_misses).astype(np.uint64)
    return np.maximum(pattern, 10)


def generate_dataset(samples_per_class=1000, seed=42):
    """
    Generate a full dataset with all algorithm classes.

    Returns:
        dict: Mapping algorithm name to list of timing vectors
    """
    rng = np.random.RandomState(seed)

    algorithms = {
        "rsa": generate_rsa_pattern,
        "ecdsa": generate_ecdsa_pattern,
        "ed25519": generate_ed25519_pattern,
        "baseline": generate_baseline_pattern,
    }

    dataset = {}
    for name, generator in algorithms.items():
        print(f"[*] Generating {samples_per_class} samples for {name}...")
        dataset[name] = [generator(rng) for _ in range(samples_per_class)]

    return dataset


def save_dataset(dataset, output_file):
    """Save dataset to CSV file."""
    print(f"[*] Saving dataset to {output_file}...")

    with open(output_file, "w") as f:
        # Header
        num_lines = len(next(iter(dataset.values()))[0])
        header = "round,label," + ",".join(f"cache_{i}" for i in range(num_lines))
        f.write(header + "\n")

        # Data
        for label, vectors in dataset.items():
            for round_num, vector in enumerate(vectors):
                row = f"{round_num},{label}," + ",".join(str(v) for v in vector)
                f.write(row + "\n")

    file_size = os.path.getsize(output_file) / (1024 * 1024)
    print(f"[*] Saved {output_file} ({file_size:.1f} MB)")


def print_statistics(dataset):
    """Print summary statistics for the dataset."""
    print("\n--- Dataset Statistics ---")
    print(f"{'Algorithm':<12} {'Samples':>8} {'Mean':>10} {'Std':>10} {'Miss Rate':>10}")
    print("-" * 55)

    threshold = 100  # Miss threshold
    for label, vectors in dataset.items():
        all_values = np.concatenate(vectors)
        mean = np.mean(all_values)
        std = np.std(all_values)
        miss_rate = np.mean(all_values > threshold) * 100
        print(f"{label:<12} {len(vectors):>8} {mean:>10.1f} {std:>10.1f} {miss_rate:>9.1f}%")


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic cache timing data for DNSSEC algorithm classification"
    )
    parser.add_argument(
        "--samples", type=int, default=1000,
        help="Samples per algorithm class (default: 1000)"
    )
    parser.add_argument(
        "--output", default="synthetic_cache.csv",
        help="Output CSV file (default: synthetic_cache.csv)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    parser.add_argument(
        "--lines", type=int, default=NUM_CACHE_LINES,
        help=f"Number of cache lines (default: {NUM_CACHE_LINES})"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Synthetic Cache Timing Data Generator")
    print("DNSSEC Timing Side-Channel Research")
    print("=" * 60)
    print(f"Samples per class: {args.samples}")
    print(f"Cache lines: {args.lines}")
    print(f"Output: {args.output}")
    print()

    # Generate dataset
    dataset = generate_dataset(samples_per_class=args.samples, seed=args.seed)

    # Print statistics
    print_statistics(dataset)

    # Save
    output_path = Path(args.output)
    save_dataset(dataset, str(output_path))

    print(f"\n[*] Done! Dataset ready for classifier training.")
    print(f"[*] Next step: python cache_classifier.py --input {args.output}")


if __name__ == "__main__":
    main()
