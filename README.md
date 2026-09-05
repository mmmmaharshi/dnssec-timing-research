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
├── docker/                  # Docker Compose for test environment
│   ├── docker-compose.yml   # Resolver containers (Unbound, BIND, Knot)
│   ├── bind-config/         # Authoritative server config
│   ├── bind-resolver-config/# BIND resolver config
│   ├── unbound-config/      # Unbound resolver config
│   └── knot-config/         # Knot Resolver config
├── zones/                   # DNSSEC-signed test zones
│   └── generate_zones.py    # Zone generation script
├── harness/                 # Timing measurement tools
│   └── timing_harness.py    # Main timing harness
├── analysis/                # Statistical analysis
│   └── analyze_timings.py   # Timing analysis and distinguisher
├── constant-time-dnssec/    # Rust constant-time verification library
│   ├── src/
│   │   ├── lib.rs           # Core types and utilities
│   │   ├── algorithms.rs    # Algorithm-specific verification
│   │   └── verify.rs        # High-level verification interface
│   └── benches/             # Performance benchmarks
├── results/                 # Measurement results (generated)
└── README.md
```

## Quick Start

### 1. Set up the test environment

```powershell
cd docker
docker-compose up -d
```

This starts:
- Authoritative DNS server with signed zones (port 5353)
- Unbound resolver with DNSSEC validation (port 5354)
- BIND resolver with DNSSEC validation (port 5355)
- Knot Resolver with DNSSEC validation (port 5356)

### 2. Generate test zones

```powershell
cd zones
python generate_zones.py
```

### 3. Run timing measurements

```powershell
cd harness
pip install dnspython

# Single measurement
python timing_harness.py --resolver unbound --outcome valid-rsa --samples 10000

# Full measurement suite
python timing_harness.py --all --samples 10000
```

### 4. Analyze results

```powershell
cd analysis
pip install numpy scipy

python analyze_timings.py --input ../results/raw_timings.csv
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
- **verify_with_padding**: Verification with dummy work to mask timing variations

### Supported Algorithms

- RSA-SHA256 (Algorithm 8)
- RSA-SHA512 (Algorithm 10)
- ECDSA P-256 (Algorithm 13)
- ECDSA P-384 (Algorithm 14)
- Ed25519 (Algorithm 15)

## Research Plan

See the full research plan in the project root for detailed methodology,
timeline, and expected deliverables.

## References

- DNSSECVerif: "Proving DNSSEC Correctness" (arxiv 2512.11431)
- Almeida et al., "Verifying Constant-Time Implementations" (USENIX Security 2016)
- RFC 4033/4034/4035 — DNSSEC specifications
- "On timing side channels in constant-time implementations" (Springer 2026)
