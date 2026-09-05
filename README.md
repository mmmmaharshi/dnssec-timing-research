# DNSSEC Timing Side-Channel Research

Research project investigating timing side-channels in DNSSEC signature verification
and developing constant-time verification primitives to eliminate information leakage.

## Research Question

Do DNSSEC-validating resolvers leak information about signature validity through
timing side-channels? Can we build a constant-time verification primitive that
eliminates this leakage?

## Project Structure

```
dnssec-timing-research/
├── analysis/                # Statistical analysis
│   └── analyze_timings.py   # Timing analysis with t-tests and effect sizes
├── constant-time-dnssec/    # Rust constant-time verification library
│   ├── src/
│   │   ├── lib.rs           # Core types and utilities
│   │   ├── algorithms.rs    # Algorithm-specific verification
│   │   └── verify.rs        # High-level verification interface
│   └── benches/             # Performance benchmarks
├── docker/                  # Docker Compose for test environment
│   ├── docker-compose.yml   # BIND DNS server with DNSSEC zones
│   └── zones/               # Zone generation script
├── harness/                 # Timing measurement tools
│   └── timing_harness.py    # Main timing harness
├── results/                 # Measurement results (generated)
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

- RSA-SHA256 (Algorithm 8)
- RSA-SHA512 (Algorithm 10)
- ECDSA P-256 (Algorithm 13)
- Ed25519 (Algorithm 15)

## Key Findings

- **Ed25519 has an 8.2x timing difference** between valid and invalid signatures
- All DNSSEC algorithms show statistically significant timing differences (p < 0.01)
- RSA-SHA256: 2.555 ms, ECDSA-P256: 2.820 ms, Ed25519: 3.850 ms

## References

- DNSSECVerif: "Proving DNSSEC Correctness" (arxiv 2512.11431)
- Almeida et al., "Verifying Constant-Time Implementations" (USENIX Security 2016)
- RFC 4033/4034/4035 — DNSSEC specifications
- "On timing side channels in constant-time implementations" (Springer 2026)
