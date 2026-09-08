# Artifact Evaluation README

## Cache-Based Algorithm Fingerprinting of DNSSEC Resolvers

**Paper:** "Cache-Based Algorithm Fingerprinting of DNSSEC Resolvers: A Cross-VM Side-Channel Attack"
**Target Venue:** USENIX Security 2027

---

## Overview

This artifact contains:
1. **Attack harness** (`harness/`) — Prime+Probe cache measurement tool
2. **Analysis scripts** (`analysis/`) — ML classifier and leakage quantification
3. **Constant-time library** (`constant-time-dnssec/`) — Rust CT verification primitives
4. **Docker environment** (`docker/`) — Reproducible test setup with BIND/Unbound/Knot
5. **Results** (`results_cache_attack/`) — Raw data and analysis outputs

---

## Requirements

### Hardware
- x86-64 CPU with shared L3 cache (4+ cores recommended)
- Minimum 8GB RAM

### Software
- **Linux** (Ubuntu 22.04+ recommended) — required for `cache_probe.c`
- Docker Desktop with Docker Compose v2
- Python 3.10+ with pip/uv
- Rust 1.70+ (for constant-time library)
- GCC 9+ (for harness compilation)

---

## Quick Start

### 1. Build the Attack Harness

```bash
cd harness
gcc -O2 -o cache_probe cache_probe.c -lpthread
```

### 2. Set Up Docker Environment

```bash
cd docker
docker-compose up -d
# Wait for containers to start
sleep 15
```

This starts:
- `dnssec-auth` — Authoritative server with signed zones (port 15353)
- `dnssec-bind` — BIND resolver with DNSSEC validation (port 15354)
- `dnssec-unbound` — Unbound resolver (port 15355)
- `dnssec-knot` — Knot Resolver with DNSSEC validation (port 15356)

Verify all resolvers are running:

```bash
cd docker
python test_resolvers.py
```

### 3. Run Cache Attack Measurement

```bash
cd harness
./cache_probe --rounds 500 --label rsa -o rsa_timings.csv --trigger /tmp/trigger --done /tmp/done
```

### 4. Analyze Results

```bash
cd analysis
pip install -r requirements.txt

# Train classifier
python cache_classifier.py --input ../results_cache_attack/combined_cache.csv --output results/

# Quantify leakage
python leakage_quantification.py --input ../results_cache_attack/combined_cache.csv

# Generate figures
python visualize_results.py --input ../results_cache_attack/combined_cache.csv --output ../paper/figures/
```

### 5. Build Constant-Time Library

```bash
cd constant-time-dnssec
cargo build --release
cargo test
cargo bench
```

---

## Reproducing Key Results

### Classification Accuracy (82.0%)

```bash
python analysis/cache_classifier.py --input results_cache_attack/combined_cache.csv
```

Expected output: ~82% cross-validation accuracy (5-fold).

### Information Leakage (1.1 bits max MI)

```bash
python analysis/leakage_quantification.py --input results_cache_attack/combined_cache.csv
```

Expected output: Max MI ~1.1 bits for single cache set.

### Dudect CT Verification

```bash
cd constant-time-dnssec
cargo test --release
```

Expected: ECDSA/RSA pass (t < 4.5), Ed25519 fails (t >> 4.5).

---

## Data Format

### Cache Timing CSV (`results_cache_attack/combined_cache.csv`)

```
round,label,cache_0,cache_64,cache_128,...
0,baseline,396,586,262,...
1,rsa,1220,570,616,...
```

- `round`: Measurement round number
- `label`: Algorithm class (baseline/rsa/ecdsa/ed25519)
- `cache_N`: Access latency in cycles for cache set N (sampled every 64th set)

### Leakage Analysis CSV (`results_cache_attack/leakage_analysis.csv`)

```
cache_set,mutual_info_bits,snr
91136,1.101624,1.7830
67264,1.100290,1.3618
```

---

## Project Structure

```
dnssec-timing-research/
├── analysis/
│   ├── cache_classifier.py          # ML classifier (Random Forest, SVM, GB)
│   ├── leakage_quantification.py    # Mutual information analysis
│   ├── visualize_results.py         # Figure generation
│   ├── analyze_timings.py           # Statistical analysis (t-tests, Cohen's d)
│   └── generate_synthetic_cache_data.py  # Synthetic data for testing
├── constant-time-dnssec/
│   ├── src/
│   │   ├── lib.rs                   # Core CT types
│   │   ├── algorithms.rs            # Algorithm-specific CT verification
│   │   └── verify.rs                # High-level interface
│   └── benches/                     # Performance benchmarks
├── docker/
│   ├── docker-compose.yml           # Test environment
│   ├── bind-config/                 # BIND configuration
│   ├── unbound-config/              # Unbound configuration
│   └── zones/                       # Signed DNS zones
├── harness/
│   ├── cache_probe.c                # Prime+Probe measurement tool
│   ├── trigger_attack.py            # DNS query trigger
│   └── timing_harness.py            # Network timing harness
├── paper/
│   ├── FINAL_PAPER.md               # Paper draft
│   └── figures/                     # Generated figures
└── results_cache_attack/            # Measurement results
    ├── combined_cache.csv           # All measurements (4000 samples)
    ├── leakage_analysis.csv         # Per-set MI analysis
    └── classification_summary.csv   # Classifier performance
```

---

## Known Limitations

1. **Platform-specific**: `cache_probe.c` requires Linux (uses `rdtsc`, `clflush`, `sched_setaffinity`)
2. **Ed25519 CT**: Not yet constant-time (6x overhead required)
3. **Cloud co-location**: Tested on single host with Docker, not real cloud VMs

---

## Contact

For questions about this artifact, contact [authors].

---

*Last updated: 2026-09-08*
