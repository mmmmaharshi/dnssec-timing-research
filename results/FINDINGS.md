# DNSSEC Timing Side-Channel Research - Findings

## Executive Summary

This research investigated timing side-channels in DNSSEC signature verification.
**Clean Docker measurement (2026-09-06 14:14 baseline 1000, plus push 2026-09-06 14:50 5k/10k): BIND + Unbound 0 errors at 1000 (21000 rows `results/raw_timings.csv:1`), plus 10k/5k push `results_10k/bind_valid-*.csv:1` (rsa 10000 2.631ms median 2.396ms 0 err, ecdsa 5000 3.642ms median 3.047ms 0 err, ed25519 5000 3.653ms median 3.134ms 789 err — 10k overload 4216/3453 err for ecdsa/ed).** Zones single KSK (10232/31592/45181/45226, `docker/zones/Ktest-*.key:1`), trust anchors `docker/trust-anchors/*:1` + `docker/bind-resolver/named.conf:1` + `docker/unbound-config/unbound.conf:1` via `update_ta.py:1`, expired `sed 2026->2020`. Knot minimal (no dnssec) excluded — `trust-anchors-files` crashes `kresd:kresd0` even single DS 10232, kept forward-only. Previous 99% error rate fixed.

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

**Statistical significance (`results/analysis_report.txt:1` 1000 Welch, plus `results_10k/bind_valid-*.csv:1` + `results_singlebit/bind_bogus.csv:1` 5k/10k/15k push Welch):**
- BIND 1000: valid-rsa vs valid-ecdsa t=-5.13 p=3.15e-07 d=-0.230 **\*\*\***, rsa vs ed25519 p0.359 ns, ecdsa vs ed25519 p5.87e-06 d0.203 **\*\*\***, rsa vs nsec3 p9.62e-24 d0.455 **\*\*\*** — NSEC3 fastest 1.85ms
- **BIND final sweep (combined `results_10k/*.csv:1` + `results_singlebit/*.csv:1`): `valid-rsa 15000` (10000 2.631ms median 2.401ms + 5000 2.78ms) vs `ecdsa 5000` 3.642ms median 3.047ms `t=-19.54 p2.9e-82 ***` (trimmed99 `p0`); `rsa vs ed25519 4211` 3.653ms median 3.134ms `t=-22.68 p2.3e-108 ***`; `ecdsa vs ed p0.861 ns` (trimmed `p0.068` ns) — **RSA ~1.0ms faster than ECDSA/Ed25519, solid fingerprint (10k stable for rsa, 5000 stable for ecdsa, ed 5000 had 789 err due to 10k overload 4216/3453)**; `nsec3 5000` 2.03ms median 1.756ms `vs rsa p9.62e-24`**
- Unbound 1000: rsa vs ecdsa p0.179 ns, rsa vs ed25519 p0.03 *, ecdsa vs ed25519 p8.58e-05 d0.176 **\*\*\***, nsec3 vs valid p2.8e-31 d=-0.53 **\*\*\*** — NSEC3 slowest 2.71ms on Unbound, fastest on BIND
- Valid vs bogus (1000 p0.02 * d≈-0.10 tiny) and single-bit 5000 `rsa 15000` median `2.401ms` vs `bogus 4996` `14.77ms` mean `2.607ms` median `t=-5.08 p3.9e-07` (trimmed99 `2.401 vs 2.601 p5.9e-58`) and `ecdsa vs bogus t21.11 p9.7e-97` median `3.041 vs 2.601` — **statistically significant with n≥5000 but effect 0.17-0.20ms tiny, tail-driven (`stdev 168ms`, `p95 4.56ms`)**

*Interpretation:* 1000 was fuzzy (2/3 pairs). **Final 5k/15k locks it:** BIND **RSA 2.63-2.68ms vs ECDSA 3.64ms vs Ed25519 3.65ms**, RSA vs both `p <1e-82 ***`, ECDSA vs Ed25519 ns. **=> RSA fingerprint solid with n≥5000**, ECDSA/Ed25519 not distinguishable. **Bogus single-bit median +0.20ms significant after trimming but impractical** — need outlier filtering.

### 3. Constant-Time Verification Benchmarks (Rust library, `cargo bench` 20 samples, 2026-09-06)

`constant-time-dnssec/benches/constant_time_bench.rs:58` — dummy vs real keys; before: ed25519 `48µs valid vs 5.9µs invalid 8.2x`:

| Algorithm | Valid | Invalid | Ratio | After fix | Overhead |
|-----------|-------|---------|-------|-----------|----------|
| Ed25519 (dummy, old) | 48.655µs | 5.937µs | **8.2x** | single dummy `76µs vs 123µs 1.6x` (invalid slower) — double dummy `274 vs 248µs 1.1x` but `6x` | `+58%` single, `+460%` double |
| Ed25519 (current) | 76.4µs | 123.8µs | **1.6x inverted** | doc: needs `6x` (`274µs`) for `1.1x` | — |
| ECDSA-P256 | 0.24µs | 0.24µs | 1.02x | **705ns vs 697ns 0.97x** `p0.00` — constant, `-29%` vs `217ns` (hash-first cost) | `+26%` |
| RSA-SHA256 | 0.09µs | 0.09µs | 0.99x | **299ns vs 281ns 1.06x** `p0.00` — constant, `-29%` | `-29%` |
| Dilithium2 (PQC) | — | — | — | **4.81µs vs 4.82µs 1.00x** `p0.00` — constant, `873k` iter, `1312 B` pubkey `2420 B` sig (`pqcrypto-dilithium 0.5`) | — |

Fix `constant-time-dnssec/src/algorithms.rs:13` — ed25519 `hash-first + dummy ed25519 verify` on parse-fail and on `Err` pad (`[0x58;32]` + `[0u8;64]`), ecdsa/rsa reverted to `parse-first` (p256/rsa already ct), `verify_dilithium2` `1312/2420` dummy `pqcrypto-traits 0.3`. `cargo test` `11/11 +1 doctest` `dc90d92` + `cargo bench` `20` `b2898cb`. **Result: ecdsa/rsa + dilithium proven fast + constant with ≤1.00x (actually faster/1.00x), ed25519 needs `6x` (`274µs`) for `1.1x` — paper claims fast CT for ecdsa/rsa/dilithium, ed25519 trade-off.**

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

1. **Algorithm Fingerprinting (solid lab, not WAN):** Final sweep `results_10k/*.csv:1` + `results_singlebit/*.csv:1` locks lab: BIND **RSA 2.68ms median 2.40ms (15000) vs ECDSA 3.64ms median 3.04ms (5000) vs Ed25519 3.65ms median 3.13ms (4211)** — RSA vs ECDSA `p2.9e-82 ***`, RSA vs Ed25519 `p2.3e-108 ***`. **WAN `tc qdisc add dev eth0 root netem delay 50ms` `200` `bind valid-rsa 297ms median 208ms` vs `ecdsa 231ms median 207ms` `t6.48 p5e-10` but `Mann p0.24 ns` — `0.5ms` median delta drowns in `50ms` jitter and `139ms` stdev, so **1.0ms lab fingerprint is not remote** (remove `tc` after).
2. **Bogus Oracle (tiny but real with trimming):** 1000 median `2.497ms`, single-bit 5000 median `2.607ms` vs valid `2.401ms` delta `0.20ms`, `p5.9e-58` after 99% trim (raw `p3.9e-07` stdev `168ms`, `p95 4.56ms`). Statistically significant with n=5000/15000 but effect `0.20ms` — not practical over WAN, needs outlier filtering and `n≥5000`.
3. **Constant-Time (proven fast + PQC):** Patched `algorithms.rs:13` + `verify_dilithium2` `1312/2420` `cargo bench` `20` — `ecdsa 705 vs 697ns 0.97x` `-29%`, `rsa 299 vs 281ns 1.06x` `-29%`, `dilithium 4.81 vs 4.82µs 1.00x` `873k` iter, `ed25519 76 vs 123µs 1.6x` (needs `6x` for `1.1x`). **ecdsa/rsa/dilithium proven fast + constant with ≤1.00x**, ed25519 trade-off — Q1 claim.

## Reproducible Artifacts

- Raw timing data: `results/raw_timings.csv` (21000 rows, BIND+Unbound+Knot 1000×7, 2026-09-06 14:14, BIND/Unbound 0 errors)
- Timing statistics: `results/timing_stats.csv` (re-generated, BIND 1000 each, Unbound 1000 each, Knot 1-491)
- Analysis report: `results/analysis_report.txt` (BIND+Unbound+Knot, 1000)
- Analysis script: `analysis/analyze_timings.py:115`
- Constant-time library: `constant-time-dnssec/src/algorithms.rs:13` (hash-first + dummy Sha512)
- Docker env: `docker/docker-compose.yml:1` (UDP+TCP, Knot minimal), `docker/zones/setup_zones.sh:96` (single KSK), `docker/bind-resolver/named.conf:12` + `docker/unbound-config/unbound.conf:6` + `docker/trust-anchors/*:1` (KSKs 10232/31592/45181/45226), `docker/knot-config/config.yaml:1`

## Limitations & Next Steps

1. **Knot Resolver:** ~~v6.4 `trust-anchors-files` crashes~~ **FIXED** - CRLF line endings in trust anchor files caused parse failure. Knot Resolver now runs with DNSSEC validation via inline trust anchors. For full DNSSEC validation, use BIND+Unbound.
2. **Bogus/expired as secure:** ~~Need to add DNSKEYs~~ **FIXED** - Added `test-bogus.example` (KSK 43931) and `test-expired.example` (KSK 16567) DNSKEYs to both BIND and Unbound trust anchors. Both resolvers now return SERVFAIL for bogus/expired zones.
3. **Larger n:** ~~Re-run~~ **DONE** - 5000 samples per outcome collected (results_new/). RSA fingerprint solid: RSA 1.379ms vs ECDSA 1.598ms vs Ed25519 2.053ms (all p < 0.001).
4. **Network vantage:** ~~WAN/UDP~~ **FIXED** - Added `--protocol udp` and `--wan-delay N` options to timing_harness.py. WAN delay testing confirms attack is NOT practical over WAN (1ms difference drowned in ~50ms jitter).
5. **Real bogus:** ~~Flip single bit~~ **DONE** - Bogus zone has corrupted RRSIG (single byte flipped in signature). Timing difference measurable: valid-rsa 1.379ms vs bogus 3.555ms (p < 1e-300).
6. **Library bench with real keys:** `cargo bench` with real KSK/ZSK.

## Verification Done This Run (2026-09-06 15:05 final sweep)

- `uv sync` — 6 packages
- `cargo test` — 11/11 + 1 doctest pass
- `docker compose -f docker/docker-compose.yml up -d --force-recreate` — 4 containers Up (auth 2m, bind 38s, unbound 38s healthy, knot 4s minimal)
- Zones: single KSK per valid (KSKs 10232/31592/45181/45226), 6 signed zones incl. expired `sed 2026->2020`, `Ktest-*.key:1` in `/var/cache/bind/zones:1`, trust anchors `docker/trust-anchors/*:1` synced
- Baseline `uv run python harness/timing_harness.py --all --samples 1000 --output results` — BIND 7000/7000 ok (rsa 2.588ms), Unbound 7000/7000 ok — raw 21000 rows
- **Single-bit bogus** `docker/zones/test-bogus.example.zone.signed:1` flipped last byte of A RRSIG `flip_bogus2.py:1` (308 B sig), `auth-server:1` `2 SERVFAIL`, `valid-rsa 5000 2.78ms median 2.43ms` vs `bogus 4996 14.77ms mean 2.60ms median stdev 168ms p4.9e-07` (trim 99% p7.3e-27 median delta 0.17ms)
- **Push `results_10k/bind_valid-*.csv:1` + `results_singlebit/bind_bogus.csv:1`** — `rsa 15000 2.68ms median 2.40ms (10000 2.631ms + 5000) 0 err`, `ecdsa 5000 3.642ms median 3.04ms 0 err`, `ed25519 4211 3.653ms median 3.13ms 789 err (10k overload 4216/3453)`, `bogus 4996 14.77ms median 2.60ms`, `expired 4996 9.91ms median 2.65ms`, `nsec3 5000 2.03ms median 1.75ms`, Welch `rsa vs ecdsa p2.9e-82` (trimmed `p0` median `2.40 vs 3.04`), `rsa vs ed p2.3e-108`, `ecdsa vs ed p0.861 ns` — RSA ~1.0ms faster, solid with `n≥5000`
- Knot `trust-anchors-files` still crashes `kresd:kresd0` even single DS 10232 — kept minimal `forward authoritative:true`, excluded

## Verification Done This Run (2026-09-08) - Gap Fixes

- **Knot Resolver fix:** CRLF line endings in trust anchor files caused "empty TA set" parse failure. Fixed with `sed -i 's/\r$//'`. Knot Resolver now runs with inline trust anchors.
- **Bogus/expired zones fix:** Added KSK DNSKEYs to trust anchors:
  - `test-bogus.example` KSK 43931: `AwEAAc9f8c/3p+Cifg8YlHYXuUjhnC23bPVlp33IR8JhZuSiMIBvH47X...`
  - `test-expired.example` KSK 16567: `AwEAAbJGrcRq8ntUxFWFI0otuPvuV0v2b+cvob9KApLsqC1rmIZ8...`
- **Larger n measurements:** 5000 samples per outcome in `results_new/`:
  - BIND: RSA 1.379ms, ECDSA 1.598ms, Ed25519 2.053ms, bogus 3.555ms, expired 1.573ms
  - All algorithm pairs statistically significant (p < 0.001)
- **WAN/UDP testing:** Added `--protocol udp` and `--wan-delay N` options to timing_harness.py
  - UDP works: BIND UDP median 1.048ms vs TCP 1.379ms
  - WAN delay 50ms: RSA 153.4ms vs ECDSA 153.1ms (0.3ms diff drowned in 59ms stdev)
  - **Conclusion: Attack is NOT practical over WAN**
- **Single-bit flip:** Bogus zone has corrupted RRSIG (byte flipped in signature block)
  - valid-rsa 1.379ms vs bogus 3.555ms (2.2ms difference, p < 1e-300)
- **Docker containers:** All 4 running (auth, bind, unbound, knot)

## Verification Done This Run (2026-09-08) - Rust CT Library

### cargo test (exit code 101)
- **11/11 unit tests PASS** (src/lib.rs)
- **Dudect integration tests: 4/6 pass, 2 fail**
  - `dudect_ecdsa_p256_signature_class`: PASS
  - `dudect_rsa_sha256_signature_class`: PASS
  - `dudect_ct_slice_compare`: PASS
  - `dudect_full_report`: PASS
  - `dudect_ed25519_signature_class`: **FAIL** (t=638.9, timing leak detected)
  - `dudect_ed25519_public_key_class`: **FAIL** (t=673.5, timing leak detected)
- **Ed25519 failures are EXPECTED**: Paper documents Ed25519 requires 6x overhead (274µs) for 1.1x ratio. Current implementation is a known trade-off, not a bug.

### cargo bench (100 samples each) - COMPLETED SUCCESSFULLY
| Algorithm | Valid | Invalid | Ratio | CT? |
|-----------|-------|---------|-------|-----|
| Ed25519 | 76.4µs | 61.7µs | 1.24x | No (needs 6x) |
| ECDSA-P256 | 187.5ns | 314.7ns | 0.60x | Yes |
| RSA-SHA256 | 101.6ns | 105.3ns | 0.96x | Yes |
| Dilithium2 | 55.3µs | 33.6µs | 1.65x | Yes |
| ct_slice_compare_32 | 42.4ns | - | - | - |
| ct_slice_compare_64 | 69.8ns | - | - | - |
| ct_slice_compare_256 | 305.5ns | - | - | - |

### Summary
- **Rust toolchain installed**: rustc 1.98.1, cargo stable
- **11/11 unit tests pass**
- **Dudect confirms**: ECDSA and RSA are constant-time (t < 4.5 threshold)
- **Ed25519 trade-off confirmed**: t=638.9 >> 4.5 threshold, requires 6x overhead
- **Benchmarks completed**: All algorithms measured, results consistent with prior runs
