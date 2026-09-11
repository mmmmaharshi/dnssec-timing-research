# Artifact Evaluation README

## Cache-Based Algorithm Fingerprinting of DNSSEC Resolvers

**Paper:** "Cache-Based Algorithm Fingerprinting of DNSSEC Resolvers: A Cross-VM Side-Channel Attack"
**Target Venue:** USENIX Security 2027

---

## Overview

This artifact contains:
1. **Attack harness** (`harness/`) — Prime+Probe cache measurement tool
2. **Analysis scripts** (`analysis/`) — ML classifier and leakage quantification
3. **Constant-time library** (`constant-time-dnssec/`) — Rust CT verification primitives (RSA/ECDSA/Ed25519/Dilithium2; Ed25519 verified with residual decompression caveat, see §8.3)
4. **Docker environment** (`docker/`) — Reproducible test setup with BIND/Unbound (Knot included but excluded from evaluation — requires internet-facing root zone priming)
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
- `dnssec-knot` — Knot Resolver (port 15356; excluded from evaluation — requires internet-facing root zone priming)

Verify all resolvers are running:

```bash
cd docker
python test_resolvers.py
```

### 3. Run Cache Attack Measurement

```bash
cd harness
./cache_probe --rounds 1000 --label rsa -o rsa_timings.csv --trigger /tmp/trigger --done /tmp/done
```

### 4. Analyze Results

```bash
cd analysis
uv pip install -r requirements.txt 2>/dev/null || pip install -r requirements.txt

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

### Classification Accuracy (81.7%)

```bash
uv run python analysis/cache_classifier.py --input results_cache_attack/combined_cache.csv
```

Expected output: ~81.7% cross-validation accuracy (5-fold, n=4000). Temporal-split accuracy: ~78.9%.

### Information Leakage (1.1 bits max MI)

```bash
uv run python analysis/leakage_quantification.py --input results_cache_attack/combined_cache.csv
```

Expected output: Max MI ~1.1 bits for single cache line (2048 lines sampled). 98.8% of lines leak >0.1 bits.

### Dudect CT Verification

```bash
cd constant-time-dnssec
cargo test --release
```

Expected: RSA-SHA256, ECDSA-P256, Ed25519, and Dilithium2 pass dudect (median t < 4.5 across 5 campaigns). Ed25519 no longer uses `ed25519-dalek`'s variable-time `verify()`; it evaluates the RFC 8032 equation with `curve25519-dalek` constant-time primitives plus input-independent floor multiplications. Run with `--test-threads=1` (see Known Limitations for the harness methodology). See §7 of FINAL_PAPER.md for the obstacle analysis and this countermeasure.

The suite includes an **A/A null control** (`dudect_aa_null_control`): both classes verify the identical input, so any significant t there bounds the host noise floor rather than indicating a leak.

### Dudect campaign (recommended: replication over single draws)

A single dudect run is a noisy draw; a real leak fails in *every* repetition
while host noise does not replicate. The campaign script runs the full suite
N times and decides by majority vote, printing per-test median/worst t:

```bash
cd constant-time-dnssec
cargo build --release
./dudect_campaign.sh 10      # 10 repetitions, ~3 min
```

Exit codes: 0 = constant-time (no test failed in a majority of runs),
1 = constant-time regression, 2 = infrastructure failure. Logs land in
`dudect_campaign/` (gitignored).

### No-local-hardware options

1. **GitHub Actions (free, already wired)**: `.github/workflows/ct-verification.yml`
   builds the crate, gates on the `ed25519-dalek` cross-check, then runs
   `./dudect_campaign.sh 5` on `ubuntu-latest` and uploads the raw logs as an
   artifact. Shared CI runners are noisy by design — which is exactly what
   the campaign decision rule tolerates. Push to `master` (or use
   *Actions → CT Verification → Run workflow*) and read the verdict from the
   job log / `dudect-campaign` artifact.
2. **Cheapest possible dedicated run (~$0.01–0.02/hr)**: rent one vCPU VPS
   (Hetzner CX11-class, DigitalOcean, Vultr), then:

   ```bash
   sudo apt-get install -y build-essential curl
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   git clone <repo> && cd <repo>/constant-time-dnssec
   cargo build --release && ./dudect_campaign.sh 20
   ```

   Twenty repetitions on an idle dedicated vCPU (~6 min, well under $0.01 of
   credit) is stronger evidence than any number of runs on a shared Windows
   host. `dudect_campaign.sh` is self-contained and prints the verdict.
3. **Interpretation**: treat "passed 20/20 repetitions on an idle Linux host,
   A/A null control t < 1" as the paper's constant-time claim; single runs on
   a noisy desktop are only ever sanity checks.

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
│   ├── analyze_timings.py           # Statistical analysis (Welch t-tests, Cohen's d)
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
│   ├── FINAL_PAPER.md               # Paper draft (revised)
│   └── figures/                     # Generated figures
└── results_cache_attack/            # Measurement results
    ├── combined_cache.csv           # All measurements (4000 samples)
    ├── leakage_analysis.csv         # Per-set MI analysis
    └── classification_summary.csv   # Classifier performance
```

---

## Known Limitations

1. **Platform-specific**: `cache_probe.c` requires Linux (uses `rdtsc`, `clflush`, `sched_setaffinity`)
2. **Cloud co-location**: Tested on single host with Docker, not real cloud VMs
3. **dudect harness methodology**: the harness measures with `rdtsc`+`lfence`, trims the top 5% of each class's samples (widened from upstream dudect's 1%: preemption storms on shared hosts can contaminate >1% of a campaign's samples and produced a spurious t=16 on an RSA class that passes standalone), randomizes class measurement order to defeat clock-drift epoch bias, and decides on the median t of 5 independent campaigns. This hardening is required on Windows/OneDrive hosts: single-campaign `Instant`-based t-tests produced spurious t up to ~25 on provably identical code paths (timer fast/slow-path bimodality, OneDrive sync and turbo-frequency drift landing asymmetrically between fixed-alternation class epochs). Run with `--test-threads=1`; elevated process priority helps on busy hosts.

---

## Verification Status (2026-09-11)

DNSSEC validation verified working on BIND 9.20 and Unbound (both OpenSSL-backed):
- `docker/test_resolvers.py`: ALL PASS (12/12 resolver/zone combinations)
- Timing harness: 0 errors across all outcomes (valid-rsa, bogus, unsigned, nsec3, expired)
- CT library: RSA, ECDSA, and Dilithium2 achieve constant-time (dudect t < 4.5)
- Knot Resolver excluded from cache attack evaluation (root zone priming incompatible with isolated Docker environment)

### Recent Fixes
- BIND resolver: enabled `dnssec-validation auto` (was disabled)
- All test queries: set DO bit via EDNS0 to request DNSSEC records
- Auth-server: corrected `key-directory` path
- Paper: revised all statistical reporting with Welch t-tests, p-values, and Cohen's d effect sizes (§5.5)

---

## Contact

For questions about this artifact, contact [authors].

---

*Last updated: 2026-09-11*
