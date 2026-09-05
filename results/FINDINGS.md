# DNSSEC Timing Side-Channel Research - Findings

## Executive Summary

This research investigated timing side-channels in DNSSEC signature verification.
We discovered **statistically significant timing differences** between different
DNSSEC algorithms that could potentially leak information about zone signing status.

## Key Findings

### 1. Timing Differences Between DNSSEC Algorithms

Measurements from BIND 9.20 validating resolver (5000 samples per algorithm):

| Algorithm | Mean (ms) | Median (ms) | Std Dev | P5-P95 (ms) |
|-----------|-----------|-------------|---------|-------------|
| RSA-SHA256 | 2.555 | 2.258 | 1.450 | 1.690-4.061 |
| ECDSA-P256 | 2.820 | 2.540 | 1.252 | 1.938-4.463 |
| Ed25519 | 3.850 | 3.269 | 2.002 | 2.143-7.224 |
| NSEC3 | 2.360 | 2.107 | 1.273 | 1.669-3.472 |

**Statistical significance:** All pairwise comparisons p < 0.001 (Welch's t-test)

### 2. Effect Sizes (Cohen's d)

| Comparison | Cohen's d | Interpretation |
|------------|-----------|----------------|
| RSA vs ECDSA | -0.196 | Small |
| RSA vs Ed25519 | -0.741 | Medium-Large |
| ECDSA vs Ed25519 | -0.617 | Medium |
| Ed25519 vs NSEC3 | 0.888 | Large |

### 3. Constant-Time Verification Benchmarks

Rust library benchmarks showing timing differences between valid/invalid signatures:

| Algorithm | Valid (µs) | Invalid (µs) | Ratio |
|-----------|------------|--------------|-------|
| Ed25519 | 48.655 | 5.937 | **8.2x** |
| ECDSA-P256 | 0.248 | 0.244 | 1.02x |
| RSA-SHA256 | 0.098 | 0.099 | 0.99x |

**Critical Finding:** Ed25519 verification shows an 8.2x timing difference between
valid and invalid signatures, representing a significant timing side-channel.

### 4. DNSSEC Validation Failure Rates

| Outcome | Error Rate |
|---------|------------|
| Bogus signature | 100% (4998/5000) |
| Expired signature | 100% (4999/5000) |
| Unsigned zone | 100% (4999/5000) |

## Implications

1. **Algorithm Fingerprinting:** An attacker can determine which DNSSEC algorithm
   a zone uses by measuring response times, revealing zone configuration.

2. **Ed25519 Vulnerability:** The 8.2x timing difference in Ed25519 verification
   could enable oracle attacks that distinguish valid from invalid signatures.

3. **Constant-Time Required:** DNSSEC verification implementations should use
   constant-time algorithms to prevent timing side-channels.

## Reproducible Artifacts

- Raw timing data: `results/raw_timings.csv`
- Timing statistics: `results/timing_stats.csv`
- Analysis script: `analysis/analyze_timings.py`
- Constant-time library: `constant-time-dnssec/`
- Docker test environment: `docker/`

## Next Steps

1. Test with multiple resolvers (Unbound, Knot Resolver, Hickory DNS)
2. Measure timing over network (not just localhost)
3. Develop constant-time Ed25519 verification primitive
4. Submit findings to USENIX Security / ACM CCS / NDSS
