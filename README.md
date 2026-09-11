# DNSSEC Timing Side-Channel Research

Research project investigating timing side-channels in DNSSEC signature verification
and developing constant-time verification primitives to reduce information leakage.

## Research Question

Do DNSSEC-validating resolvers leak information about signature validity through
timing side-channels? Can we build a constant-time verification primitive that
reduces this leakage?

## Project Structure

```
dnssec-timing-research/
├── analysis/                # Statistical analysis
│   ├── analyze_timings.py   # Timing analysis with Welch t-tests and effect sizes
│   ├── cache_classifier.py  # ML classifier (Random Forest, SVM, Gradient Boosting)
│   └── leakage_quantification.py  # Mutual information analysis
├── constant-time-dnssec/    # Rust constant-time verification library
│   ├── src/
│   │   ├── lib.rs           # Core types and utilities
│   │   ├── algorithms.rs    # Algorithm-specific verification
│   │   └── verify.rs        # High-level verification interface
│   └── benches/             # Performance benchmarks
├── docker/                  # Docker Compose for test environment
│   ├── docker-compose.yml   # BIND DNS server with DNSSEC zones
│   ├── bind-config/         # BIND configuration
│   ├── unbound-config/      # Unbound configuration
│   └── zones/               # Zone generation script
├── harness/                 # Timing measurement tools
│   ├── cache_probe.c        # Prime+Probe cache measurement tool
│   ├── trigger_attack.py    # DNS query trigger
│   └── timing_harness.py    # Network timing harness
├── paper/                   # Paper draft and figures
│   ├── FINAL_PAPER.md       # Main manuscript
│   └── figures/             # Generated figures
├── results/                 # Measurement results (generated)
├── results_cache_attack/    # Cache attack results
│   ├── combined_cache.csv   # All measurements
│   ├── leakage_analysis.csv # Per-set MI analysis
│   └── classification_summary.csv  # Classifier performance
├── pyproject.toml           # Python project config (uv)
└── README.md
```

## Quick Start

### 1. Install dependencies (using [uv](https://docs.astral.sh/uv/))

```powershell
uv sync
```

### 2. Set up the test environment

```powershell
cd docker
docker-compose up -d
```

This starts a BIND server with DNSSEC-signed zones on port 15353.

### 3. Run timing measurements

```powershell
# Single measurement
uv run python harness/timing_harness.py --resolver bind --outcome valid-rsa --samples 10000

# Full measurement suite
uv run python harness/timing_harness.py --all --samples 10000
```

### 4. Analyze results

```powershell
uv run python analysis/analyze_timings.py --input results/raw_timings.csv
```

### 5. Build and test constant-time library

```powershell
cd constant-time-dnssec
cargo test
cargo bench
```

### 6. Reproduce cache attack results

```bash
cd analysis
uv run python cache_classifier.py --input results_cache_attack/combined_cache.csv --output results/
uv run python leakage_quantification.py --input results_cache_attack/combined_cache.csv
```

## Test Outcomes

The harness measures timing for these DNSSEC validation outcomes:

| Outcome | Description |
|---------|-------------|
| `valid-rsa` | Valid RSA-SHA256 signature |
| `valid-ecdsa` | Valid ECDSA P-256 signature |
| `valid-ed25519` | Valid Ed25519 signature |
| `bogus` | Intentionally broken signature |
| `expired` | Expired signature |
| `unsigned` | Unsigned zone (no DNSSEC) |
| `nsec3` | NSEC3 proof of non-existence |

## Constant-Time Verification Library

The `constant-time-dnssec` Rust library provides:

- **CtVerificationResult**: Constant-time verification result type
- **ct_slice_compare**: Constant-time byte slice comparison
- **verify_signature**: Unified verification interface for all DNSSEC algorithms

### Supported Algorithms

- RSA-SHA256 (Algorithm 8) — **Constant-time verified** (dudect t < 4.5)
- RSA-SHA512 (Algorithm 10) — **Constant-time verified** (dudect t < 4.5)
- ECDSA P-256 (Algorithm 13) — **Constant-time verified** (dudect t < 4.5)
- Dilithium2 (Post-quantum) — **Constant-time verified** (dudect t < 4.5)
- Ed25519 (Algorithm 15) — **Constant-time verified** (dudect t < 4.5 on both the signature-class and public-key-class tests on a quiet host)

## Key Findings

- **Cache-based fingerprinting achieves 81.7% accuracy** (5-fold CV, n=4000) across 4 algorithm classes using Prime+Probe on shared L3 cache, with individual cache lines leaking up to 1.1 bits of mutual information (98.8% of lines leak >0.1 bits)
- **RSA ~0.6ms faster than ECDSA** in BIND 9.20 with OpenSSL 3.x (median diff −0.650ms), likely due to more cache-efficient BIGNUM Montgomery multiplication
- **Constant-time verification achieved for RSA, ECDSA, Ed25519, and Dilithium2** (dudect median t < 3.2, threshold 4.5); Ed25519 verified with residual decompression caveat (see §8.3)
- **Network timing differences are impractical over WAN** (> 50ms jitter drowns out ~0.6ms signal) but cache-based attacks remain viable on co-located infrastructure

## Verified Working (2026-09-11)

DNSSEC validation confirmed working on BIND 9.20 and Unbound:

```
cd docker
docker-compose up -d
python test_resolvers.py  # ALL PASS
```

Timing harness verified with 0 errors across all outcomes (valid-rsa, bogus, unsigned, nsec3, expired).

Note: Knot Resolver was excluded from cache attack evaluation due to root zone priming requirements incompatible with our isolated Docker testbed. Both BIND and Unbound use OpenSSL-backed implementations.

## References

- DNSSECVerif: "Proving DNSSEC Correctness" (arxiv 2512.11431)
- Almeida et al., "SoK: The Impact of Uninitialized Cipher State on Cryptographic Code" (IEEE S&P 2022)
- RFC 4033/4034/4035 — DNSSEC specifications
- RFC 8080 — Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC (2017)
- "On timing side channels in constant-time implementations" (Springer 2026)
