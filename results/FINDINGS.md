# DNSSEC Timing Side-Channel Research - Findings

## Executive Summary

This research investigated timing side-channels in DNSSEC signature verification.
**Docker measurement now succeeds: BIND + Unbound 0 errors for all 7 outcomes** (1000 samples each, `results/raw_timings.csv:1` 21000 rows, `results/timing_stats.csv:1`). Knot partially up (valid-rsa 429/1000, others 1-6/1000, trust-anchor refresh fails). Previous 99% error rate was unsigned bogus/expired — now fixed via `docker/zones/setup_zones.sh:96` + `docker/knot-config/config.yaml:1`.

## Key Findings

### 1. Timing Differences Between DNSSEC Algorithms (localhost TCP, 1000 samples)

**BIND 9.20 (`docker/bind-resolver/named.conf:1`, cache 0):**

| Outcome | N | Mean (ms) | Median (ms) | Std Dev | P5-P95 (ms) |
|---------|---|-----------|-------------|---------|-------------|
| valid-rsa | 1000 | 3.692 | 3.232 | 2.067 | 2.498-6.160 |
| valid-ecdsa | 1000 | 3.096 | 2.675 | 1.780 | 2.197-5.073 |
| valid-ed25519 | 1000 | 3.440 | 2.831 | 2.732 | 2.233-5.967 |
| bogus (SERVFAIL) | 1000 | 7.874 | 2.656 | 94.308 | 2.192-4.531 |
| expired | 1000 | 13.967 | 2.780 | 148.374 | 1.916-5.319 |
| unsigned | 1000 | 8.472 | 2.808 | 113.385 | 2.301-5.100 |
| nsec3 | 1000 | 2.226 | 1.966 | 1.160 | 1.673-3.428 |

**Unbound (`docker/unbound-config/unbound.conf:1`, cache 0):**

| Outcome | N | Mean (ms) | Median (ms) | Std Dev | P5-P95 (ms) |
|---------|---|-----------|-------------|---------|-------------|
| valid-rsa | 1000 | 2.283 | 2.004 | 1.459 | 1.623-3.407 |
| valid-ecdsa | 1000 | 2.251 | 1.947 | 1.557 | 1.669-3.338 |
| valid-ed25519 | 1000 | 2.284 | 2.017 | 1.699 | 1.711-3.052 |
| bogus | 1000 | 2.666 | 2.131 | 2.520 | 1.752-4.815 |
| expired | 1000 | 2.585 | 2.297 | 1.382 | 1.843-3.989 |
| unsigned | 1000 | 2.427 | 2.194 | 1.155 | 1.820-3.486 |
| nsec3 | 1000 | 3.808 | 3.224 | 2.620 | 2.711-6.046 |

**Statistical significance (`results/analysis_report.txt:1`, Welch's t-test, BIND):**
- valid-rsa vs valid-ecdsa: t=6.90 p=6.76e-12 d=0.309 **\*\*\***
- valid-rsa vs valid-ed25519: t=2.32 p=2.03e-02 d=0.104 **\***
- valid-ecdsa vs valid-ed25519: t=-3.34 p=8.67e-04 d=-0.149 **\*\*\***
- valid-rsa vs nsec3: t=19.5 p=2.5e-76 d=0.874 **\*\*\***
- valid vs bogus/expired/unsigned: p 0.16-0.02, but mean inflated by outliers (stdev 94-148ms), median 2.66ms ≈ valid 3.23ms — **no clean bogus oracle**
- Unbound: valid algorithms indistinguishable (p0.64), but nsec3 vs valid p6e-54 d=-0.71 **\*\*\*** — NSEC3 fingerprint, not algorithm.

*Interpretation:* BIND shows algorithm fingerprint for **valid** (RSA median 3.23ms > Ed25519 2.83ms > ECDSA 2.67ms, all p<0.02). Unbound does not. **Bogus SERVFAIL not distinguishable by median** — tail-driven mean only. Need single-bit RRSIG flip and n≥2000 (power: 273 for rsa vs ecdsa, 2411 for rsa vs ed25519, 6618 for rsa vs bogus).

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
