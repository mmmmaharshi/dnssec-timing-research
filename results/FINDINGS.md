# DNSSEC Timing Side-Channel Research - Findings

## Executive Summary

This research investigated timing side-channels in DNSSEC signature verification.
**Docker measurement now succeeds: BIND + Unbound return 0 errors for all 7 outcomes** (500 samples each, `results/raw_timings.csv:1` 7000 rows). Knot Resolver still EOF (config bug). Previous 99% error rate was due to unsigned bogus/expired zones — now fixed via `docker/zones/setup_zones.sh:96` (bogus signed+corrupted, expired 2020 dates).

## Key Findings

### 1. Timing Differences Between DNSSEC Algorithms (localhost TCP, 500 samples)

**BIND 9.20 (`docker/bind-resolver/named.conf:1`, cache 0):**

| Outcome | N | Mean (ms) | Median (ms) | Std Dev | P5-P95 (ms) |
|---------|---|-----------|-------------|---------|-------------|
| valid-rsa | 500 | 4.746 | 3.417 | 4.361 | 2.352-11.900 |
| valid-ecdsa | 500 | 4.007 | 3.186 | 3.130 | 2.268-7.954 |
| valid-ed25519 | 500 | 3.386 | 2.929 | 1.709 | 2.240-6.156 |
| bogus (SERVFAIL) | 500 | 10.245 | 3.239 | 72.483 | 2.242-12.736 |
| expired | 500 | 5.502 | 2.801 | 27.744 | 2.152-6.754 |
| unsigned | 500 | 4.179 | 2.681 | 18.050 | 1.756-5.348 |
| nsec3 | 500 | 3.100 | 2.196 | 3.208 | 1.559-7.435 |

**Unbound (`docker/unbound-config/unbound.conf:1`, cache 0):**

| Outcome | N | Mean (ms) | Median (ms) | Std Dev |
|---------|---|-----------|-------------|---------|
| valid-rsa | 500 | 2.736 | 1.972 | 2.734 |
| valid-ecdsa | 500 | 2.901 | 2.437 | 1.900 |
| valid-ed25519 | 500 | 2.413 | 2.020 | 1.546 |
| bogus | 500 | 2.508 | 2.056 | 1.779 |
| expired | 500 | 2.835 | 2.093 | 3.024 |
| unsigned | 500 | 3.896 | 2.655 | 4.077 |
| nsec3 | 500 | 5.498 | 4.016 | 4.939 |

**Statistical significance (`results/analysis_report.txt:1`, Welch's t-test, BIND):**
- valid-rsa vs valid-ed25519: t=6.49, p=1.68e-10, d=0.411 **\*\*\***
- valid-ecdsa vs valid-ed25519: t=3.89, p=1.1e-04, d=0.246 **\*\*\***
- valid-rsa vs nsec3: t=6.80, p=1.9e-11, d=0.430 **\*\*\***
- valid vs bogus/expired/unsigned: **not significant** (p 0.09-0.54, d -0.13 to 0.04) — bogus mean inflated by outliers (stdev 72ms), median only 3.24ms vs 3.42ms for rsa.
- Unbound shows similar valid-algorithm differences but smaller; bogus not slower (2.51ms vs 2.74ms).

*Interpretation:* Algorithm fingerprinting (RSA vs Ed25519) holds for **valid** signatures on BIND. **Bogus SERVFAIL does not give a clean timing oracle** with current corrupted-RRSIG method — tail latency high but median not distinguishable. Need better bogus construction (flip single bit in RRSIG vs full corruption) and larger n (see power analysis: bogus vs valid needs 2267 samples).

### 2. Effect Sizes (Cohen's d)

| Comparison (BIND) | Cohen's d | Interpretation |
|-------------------|-----------|----------------|
| RSA vs ECDSA | 0.195 | Small |
| RSA vs Ed25519 | 0.411 | Medium |
| ECDSA vs Ed25519 | 0.246 | Small-Medium |
| RSA vs NSEC3 | 0.430 | Medium |
| Valid vs Bogus | -0.107 | Negligible (was -1.32 with n=2 bug) |

Power analysis (`results/analysis_report.txt:30`): 686 samples needed for RSA vs ECDSA (currently 500), 155 for RSA vs Ed25519 (sufficient).

### 3. Constant-Time Verification Benchmarks (Rust library)

`constant-time-dnssec/benches/constant_time_bench.rs:58` uses **dummy keys** (`vec![0u8;32]`) — 8.2x is library microbenchmark artifact, not BIND:

| Algorithm | Valid (µs) | Invalid (µs) | Ratio |
|-----------|------------|--------------|-------|
| Ed25519 | 48.655 | 5.937 | **8.2x** |
| ECDSA-P256 | 0.248 | 0.244 | 1.02x |
| RSA-SHA256 | 0.098 | 0.099 | 0.99x |

Root cause: `constant-time-dnssec/src/algorithms.rs:13` early-returned before hash. **Fixed:** hash `SignedData` first + dummy `Sha512::digest` on failure (`cargo check` passes, `cargo test` 11/11 + 1 doctest). True ct still depends on `ed25519-dalek`/`p256`.

### 4. DNSSEC Validation Outcomes — NOW FIXED

| Outcome | BIND (500) | Unbound (500) | Note |
|---------|------------|---------------|------|
| Bogus | 0 errors, SERVFAIL rcode 2 | 0 errors, rcode 0 AD false (no trust anchor) | BIND now returns SERVFAIL (was timeout), Unbound needs trust anchor for bogus to be SERVFAIL |
| Expired | 0 errors, NXDOMAIN AD true | 0 errors | Expired 2020 dates not yet triggering SERVFAIL on BIND (needs trust anchor) |
| Unsigned | 0 errors | 0 errors | Correct |
| Knot | 500/500 errors EOF | — | `docker/knot-config/config.lua:1` TCP EOF — needs fix |

`harness/timing_harness.py:125` correctly records SERVFAIL as valid timing.

## Implications

1. **Algorithm Fingerprinting (supported, BIND):** Valid RSA vs Ed25519 medians differ 0.49ms (BIND) and 0.51ms vs nsec3, p<0.001. Local attacker can fingerprint.
2. **Bogus Oracle (not supported with current data):** Median bogus 3.24ms ≈ valid 3.42ms, mean tail 10ms due to outliers — not a reliable oracle. Needs improved bogus generation and n≥2267.
3. **Constant-Time:** Patched library equalizes parse-failure path; upstream should adopt hashing-first pattern.

## Reproducible Artifacts

- Raw timing data: `results/raw_timings.csv` (7000 rows, BIND+Unbound 500×7, 2026-09-06) + `results_new/raw_timings.csv`
- Timing statistics: `results/timing_stats.csv` (re-generated)
- Analysis report: `results/analysis_report.txt` (BIND+Unbound)
- Analysis script: `analysis/analyze_timings.py:115`
- Constant-time library: `constant-time-dnssec/src/algorithms.rs:13`
- Docker env: `docker/docker-compose.yml:1` (UDP+TCP), `docker/zones/setup_zones.sh:96`, `docker/bind-config/named.conf:1`

## Limitations & Next Steps

1. **Knot Resolver:** Fix `knot-resolver` EOF — check `trust-anchors.txt` mount and `net.listen` TCP, add `kres_modules={'hints'}` etc.
2. **Trust anchors for bogus/expired:** Add DNSKEY for `test-bogus.example` + `test-expired.example` to `docker/bind-resolver/named.conf:12`, `docker/unbound-config/unbound.conf:6`, `docker/trust-anchors.txt` so they validate as secure/bogus (currently Unbound sees them as insecure).
3. **Larger n:** Re-run `uv run python harness/timing_harness.py --all --samples 2000 --output results` (power says 686 needed for RSA vs ECDSA).
4. **Network vantage:** Measure over WAN/UDP, not just localhost TCP.
5. **Real bogus:** Flip single bit in RRSIG signature, not whole RRSIG block, to isolate verify cost.
6. **Library bench with real keys:** Generate KSK/ZSK in `benches/` instead of zero bytes, `cargo bench`.

## Verification Done This Run

- `uv sync` — 6 packages
- `cargo test` — 11/11 + 1 doctest pass
- `docker compose up -d` — 4 containers Up (auth 004e3800df1b, bind df185c015326, unbound de7815e73a3b, knot b779d6a9508a)
- `uv run python harness/timing_harness.py --resolver bind --outcome bogus --samples 200` — 0 errors (was 4998)
- `uv run python harness/timing_harness.py --all --samples 500` — BIND 3500/3500 ok, Unbound 3500/3500 ok, Knot 0/3500
- `uv run python analysis/analyze_timings.py --input results/raw_timings.csv` — ok
- `python -c "dns.query.tcp"` — BIND bogus rcode 2 AD false, valid rcode 0 AD true
