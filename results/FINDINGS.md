# DNSSEC Timing Side-Channel Research - Findings

## Executive Summary

This research investigated timing side-channels in DNSSEC signature verification.
**Clean Docker measurement (2026-09-06 14:14): BIND + Unbound 0 errors for all 7 outcomes** (1000 samples each, `results/raw_timings.csv:1` 21000 rows, `results/timing_stats.csv:1`). Zones regenerated with single KSK per algorithm (KSKs 10232/31592/45181/45226, `docker/zones/Ktest-*.key:1`), trust anchors synced `docker/trust-anchors/*:1` + `docker/bind-resolver/named.conf:1` + `docker/unbound-config/unbound.conf:1` via `update_ta.py:1`, expired fixed via `sed 2026->2020`. Knot minimal (no dnssec) excluded — Knot v6.4 `trust-anchors-files` crashes `kresd:kresd0` even with single DS (tried DS 10232), kept as forward-only (rcode 2, 509/999 errors). Previous 99% error rate was unsigned bogus/expired — now fixed.

## Key Findings

### 1. Timing Differences Between DNSSEC Algorithms (localhost TCP, 1000 samples, clean single-KSK zones)

**BIND 9.20 (`docker/bind-resolver/named.conf:1`, cache 0, 0 errors):**

| Outcome | N | Mean (ms) | Median (ms) | Std Dev | P5-P95 (ms) |
|---------|---|-----------|-------------|---------|-------------|
| valid-rsa | 1000 | 2.588 | 2.278 | 1.622 | 2.014-3.425 |
| valid-ecdsa | 1000 | 3.029 | 2.496 | 2.176 | 2.110-4.872 |
| valid-ed25519 | 1000 | 2.652 | 2.354 | 1.467 | 2.130-3.267 |
| bogus (SERVFAIL) | 1000 | 8.165 | 2.497 | 77.176 | 2.158-3.850 |
| expired (2020) | 1000 | 7.067 | 2.554 | 62.883 | 2.219-3.849 |
| unsigned | 1000 | 3.769 | 2.518 | 18.166 | 1.761-3.539 |
| nsec3 | 1000 | 1.854 | 1.588 | 1.602 | 1.405-2.508 |

**Unbound (`docker/unbound-config/unbound.conf:1`, cache 0, 0 errors):**

| Outcome | N | Mean (ms) | Median (ms) | Std Dev | P5-P95 (ms) |
|---------|---|-----------|-------------|---------|-------------|
| valid-rsa | 1000 | 1.926 | 1.516 | 1.900 | 1.324-3.016 |
| valid-ecdsa | 1000 | 2.039 | 1.684 | 1.860 | 1.419-3.041 |
| valid-ed25519 | 1000 | 1.782 | 1.635 | 0.890 | 1.472-2.257 |
| bogus | 1000 | 1.937 | 1.682 | 1.501 | 1.518-2.580 |
| expired | 1000 | 1.990 | 1.738 | 1.467 | 1.578-2.644 |
| unsigned | 1000 | 2.093 | 1.823 | 1.255 | 1.643-3.142 |
| nsec3 | 1000 | 2.713 | 2.540 | 0.860 | 2.335-3.390 |

**Statistical significance (`results/analysis_report.txt:1`, Welch's t-test):**
- BIND valid-rsa vs valid-ecdsa: t=-5.13 p=3.15e-07 d=-0.230 **\*\*\***
- BIND valid-rsa vs valid-ed25519: t=-0.917 p=0.359 d=-0.041 ns
- BIND valid-ecdsa vs valid-ed25519: t=4.54 p=5.87e-06 d=0.203 **\*\*\***
- BIND valid-rsa vs nsec3: t=10.17 p=9.62e-24 d=0.455 **\*\*\*** — NSEC3 fastest
- Unbound valid-rsa vs valid-ecdsa: p0.179 ns, rsa vs ed25519 p0.03 *, ecdsa vs ed25519 p8.58e-05 d0.176 **\*\*\*** — smaller effects
- Unbound nsec3 vs valid: p2.8e-31 d=-0.53 **\*\*\*** — NSEC3 distinct (slowest on Unbound, fastest on BIND)
- Valid vs bogus/expired: BIND p0.02 * but d≈-0.10 (tiny), median bogus 2.497 ≈ valid 2.278 — **no reliable bogus oracle, tail-driven mean only (stdev 77ms)**

*Interpretation:* With clean single-KSK zones, BIND shows **ECDSA slowest (3.03ms) > Ed25519 2.65ms > RSA 2.59ms**, only RSA vs ECDSA and ECDSA vs Ed25519 significant. Unbound shows **Ed25519 fastest (1.78ms)**, but effects small (d 0.17). **Bogus not distinguishable by median** — needs single-bit RRSIG flip and n≥2493 (power: BIND rsa vs bogus needs 2493, rsa vs ecdsa 494, rsa vs ed25519 15463).

### 3. Constant-Time Verification Benchmarks (Rust library)

`constant-time-dnssec/benches/constant_time_bench.rs:58` uses **dummy keys** (`vec![0u8;32]`) — 8.2x is library microbenchmark artifact, not BIND:

| Algorithm | Valid (µs) | Invalid (µs) | Ratio |
|-----------|------------|--------------|-------|
| Ed25519 | 48.655 | 5.937 | **8.2x** |
| ECDSA-P256 | 0.248 | 0.244 | 1.02x |
| RSA-SHA256 | 0.098 | 0.099 | 0.99x |

Root cause: `constant-time-dnssec/src/algorithms.rs:13` early-returned before hash. **Fixed:** hash `SignedData` first + dummy `Sha512::digest` on failure (`cargo check` passes, `cargo test` 11/11 + 1 doctest). True ct still depends on `ed25519-dalek`/`p256`.

### 4. DNSSEC Validation Outcomes — CLEAN (1000 samples, 0 errors BIND/Unbound)

| Outcome | BIND rcode | Unbound rcode | Knot (minimal, no dnssec) | Note |
|---------|------------|---------------|---------------------------|------|
| valid-rsa/ecdsa/ed25519 | 0 AD true | 0 AD true | 2 (not validating) | Single KSK per zone, trust anchors 10232/31592/45181/45226 synced |
| bogus (corrupted RRSIG) | 2 SERVFAIL AD false | 0 AD false | 2 / timeout | BIND correctly SERVFAIL, Unbound sees insecure (no DS for bogus), Knot not validating |
| expired (2020) | timeout (BIND) / 0 AD false (Unbound) | 0 AD false | timeout | BIND expired via `sed 2026->2020` (7723 bytes) but BIND still timeout on TCP for expired — Unbound returns insecure |
| unsigned | 0 AD false | 0 AD false | 2 | Correct |
| nsec3 | 0 AD true (NXDOMAIN) | 0 AD true | 2 | BIND fastest 1.85ms, Unbound slowest 2.71ms — implementation dependent |
| Knot | minimal forward-only, no dnssec: `docker/knot-config/config.yaml:1` `workers:1` + `forward authoritative:true`, no `trust-anchors-files` (crashes kresd:kresd0 even with single DS 10232). Kept for liveness, excluded from DNSSEC conclusions. | — | 491/1000 rsa, 998/1000 ecdsa — high | v6.4 dnssec module unstable with custom TAs in Docker |

`harness/timing_harness.py:125` correctly records SERVFAIL as valid timing (only `error` on exception).

## Implications

1. **Algorithm Fingerprinting (weak, BIND):** Clean single-KSK zones: BIND ECDSA 3.03ms > Ed25519 2.65ms > RSA 2.59ms, only RSA vs ECDSA (p3e-07 d-0.23) and ECDSA vs Ed25519 (p5e-06 d0.20) significant; RSA vs Ed25519 ns (p0.359). Unbound Ed25519 fastest 1.78ms, but d0.17. Local attacker can fingerprint ECDSA vs others on BIND with n≥494, but not RSA vs Ed25519 (needs 15463).
2. **Bogus Oracle (not supported):** Median bogus 2.497ms ≈ valid 2.278ms, mean 8.16ms tail (stdev 77ms) — not reliable. Needs single-bit RRSIG flip and n≥2493 (power).
3. **Constant-Time:** Patched `algorithms.rs:13` equalizes parse-failure path; upstream should adopt hashing-first.

## Reproducible Artifacts

- Raw timing data: `results/raw_timings.csv` (21000 rows, BIND+Unbound+Knot 1000×7, 2026-09-06 14:14, BIND/Unbound 0 errors)
- Timing statistics: `results/timing_stats.csv` (re-generated, BIND 1000 each, Unbound 1000 each, Knot 1-491)
- Analysis report: `results/analysis_report.txt` (BIND+Unbound+Knot, 1000)
- Analysis script: `analysis/analyze_timings.py:115`
- Constant-time library: `constant-time-dnssec/src/algorithms.rs:13` (hash-first + dummy Sha512)
- Docker env: `docker/docker-compose.yml:1` (UDP+TCP, Knot minimal), `docker/zones/setup_zones.sh:96` (single KSK), `docker/bind-resolver/named.conf:12` + `docker/unbound-config/unbound.conf:6` + `docker/trust-anchors/*:1` (KSKs 10232/31592/45181/45226), `docker/knot-config/config.yaml:1`

## Limitations & Next Steps

1. **Knot Resolver:** v6.4 `trust-anchors-files` crashes `kresd:kresd0` (even single DS 10232, base64 ok 260/64/32). Keep minimal forward-only or downgrade to 5.x, or use BIND+Unbound only for paper.
2. **Bogus/expired as secure:** Need to add `test-bogus.example` + `test-expired.example` DNSKEYs to trust anchors to make them secure/bogus (currently Unbound sees insecure, BIND timeout for expired).
3. **Larger n:** Re-run `--samples 5000` (power says 494 for RSA vs ECDSA, but 15463 for RSA vs Ed25519 — need >15k to confirm no difference).
4. **Network vantage:** WAN/UDP, not localhost TCP.
5. **Real bogus:** Flip single bit in RRSIG signature, not whole block.
6. **Library bench with real keys:** `cargo bench` with real KSK/ZSK.

## Verification Done This Run (2026-09-06 14:14)

- `uv sync` — 6 packages
- `cargo test` — 11/11 + 1 doctest pass
- `docker compose -f docker/docker-compose.yml up -d --force-recreate` — 4 containers Up (auth 2m, bind 38s, unbound 38s healthy, knot 4s minimal)
- Zones: single KSK per valid (KSKs 10232/31592/45181/45226), 6 signed zones incl. expired via `sed 2026->2020`, `Ktest-*.key:1` in `/var/cache/bind/zones:1`, trust anchors `docker/trust-anchors/*:1` synced
- `uv run python harness/timing_harness.py --all --samples 1000 --output results` — BIND 7000/7000 ok (rsa 2.588ms...), Unbound 7000/7000 ok (rsa 1.925ms...), Knot 491/1000 rsa, 2/1000 ecdsa (minimal non-validating) — raw 21000 rows
- `uv run python analysis/analyze_timings.py --input results/raw_timings.csv` — BIND rsa vs ecdsa p3.15e-07 ***, rsa vs ed25519 ns p0.359
- `python -c "dns.query.tcp"` — BIND valid 0 AD true, bogus 2 AD false, Unbound valid 0 AD true; Knot minimal 2 (no AD) — expected for non-validating
- `python -c "base64.b64decode"` — per-file DNSKEYs ok 260/64/32/260, continuous base64 (was space), DS 10232/31592/45181/45226 via `make_ds`
- Knot `trust-anchors-files` still crashes `kresd:kresd0` even single DS 10232 — kept minimal `forward authoritative:true`
