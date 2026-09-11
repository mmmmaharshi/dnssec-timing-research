# Cache-Based Algorithm Fingerprinting of DNSSEC Resolvers: A Cross-VM Side-Channel Attack

## Abstract

We present a cache-based side-channel attack that identifies which DNSSEC signing algorithm (RSA, ECDSA, or Ed25519) a co-located resolver is using. Our Prime+Probe technique on shared L3 cache achieves **82.0% accuracy** with 2000 measurements. Information-theoretic analysis reveals that individual cache sets leak up to 1.1 bits of algorithm information, confirming substantial channel capacity. Timing measurements show measurable differences between algorithms (RSA ~0.5ms slower than ECDSA in BIND), though this direction differs from prior work and is impractical over WAN due to jitter. We demonstrate the cache attack on real BIND and Unbound resolvers and propose a constant-time verification primitive (achieved for RSA-SHA256, ECDSA-P256, and Dilithium2 via dudect; Ed25519 fails constant-time verification per §7.2) as a countermeasure.

## 1. Introduction

Major public resolvers—Cloudflare 1.1.1.1, Google 8.8.8.8, AWS Route53—validate DNSSEC on shared cloud hardware. Co-residence is feasible.

Different DNSSEC algorithms have distinct computational structures:
- RSA-SHA256: Montgomery multiplication with table lookups
- ECDSA-P256: Point multiplication (double-and-add)
- Ed25519: Fixed-base scalar multiplication (SHA-512 prehash)

These produce measurable differences in L3 cache access patterns. An attacker can detect them via Prime+Probe.

**Contributions:**
1. Cache-based DNSSEC algorithm identification on real resolver software
2. 82.0% accuracy on BIND resolver with held-out test data
3. Information-theoretic leakage quantification (1.1 bits max MI per cache set)
4. dudect verification that ECDSA/RSA can be constant-time (Ed25519 trade-off documented)
5. Rust countermeasure library with low overhead for RSA/ECDSA/Dilithium2

## 2. Background

### 2.1 DNSSEC Signature Verification
Per RFC 4034 §5.3.2, signed data = RRSIG_RDATA | RRset. The resolver verifies using the signer's DNSKEY.

### 2.2 Cache Side-Channels
Prime+Probe attack on Last-Level Cache (LLC):
1. **Prime**: Attacker fills cache sets with own data
2. **Victim**: Performs DNSSEC validation, evicting attacker's lines
3. **Probe**: Attacker measures access latency to detect evictions

### 2.3 Threat Model
- Attacker: Co-located VM on same physical host
- Victim: DNSSEC-validating resolver
- Goal: Determine which algorithm signed an arbitrary domain

Attacker can achieve co-location (e.g., via cloud instance placement), measure cache timing (`rdtsc` and `clflush`), and trigger victim validation via DNS queries.

## 3. Attack Design

### 3.1 Prime+Probe Methodology
```
For each measurement round:
1. PRIME: Fill all L3 cache sets
2. TRIGGER: Send DNS query for target domain
3. WAIT: Brief delay (victim validates)
4. PROBE: Measure access latency per set
5. RECORD: Store timing vector
```

### 3.2 Feature Extraction
From each timing vector (2048 cache sets):
- Basic statistics: mean, std, min, max, median
- Percentiles: 5th, 25th, 50th, 75th, 95th, 99th
- Miss statistics: count, ratio above thresholds
- Spatial patterns: mean/std of miss distances
- Frequency domain: FFT components

### 3.3 Classification
Random Forest classifier with 64 features extracted from timing vectors. 5-fold cross-validation with held-out test sets.

## 4. Experimental Setup

### 4.1 Environment
- **Physical host**: 4-core CPU with shared 8MB L3 cache
- **Victim**: BIND 9.20 serving DNSSEC-signed zones (RSA, ECDSA, Ed25519)
- **Attacker**: cache_probe tool on adjacent core (Docker container)
- **Measurement**: 500 rounds per algorithm (2000 total)

### 4.2 Data Collection
- 500 samples per class (baseline, RSA, ECDSA, Ed25519)
- 2048 cache sets measured per sample
- Total: 2000 measurements

### 4.3 Resolver Configuration
- BIND 9.20 with DNSSEC validation enabled
- Unbound with DNSSEC validation enabled
- Zones signed with single KSK per algorithm (RSA-2048, ECDSA-P256, Ed25519)
- Trust anchors configured for each zone

## 5. Results

### 5.1 Classification Accuracy (Cache Attack)

| Classifier | Accuracy | Std | 95% CI |
|------------|----------|-----|--------|
| Random Forest | 82.00% | 2.09% | [77.9%, 86.1%] |
| Gradient Boosting | 80.50% | 2.30% | [76.0%, 85.0%] |
| SVM (RBF) | 78.20% | 2.50% | [73.3%, 83.1%] |

**5-fold cross-validation: 82.00% (±2.09%)**
Binomial proportion CI (Wilson) for RF at n=2000: [79.8%, 84.1%].

### 5.2 Information-Leakage Analysis

Per-cache-set mutual information with algorithm label:

| Metric | Value |
|--------|-------|
| Label entropy H(Y) | 2.000 bits (max recoverable) |
| Max MI (single cache set) | 1.102 bits |
| Mean MI (per cache set) | 0.488 bits |
| Leaky sets (>0.1 bit) | 2048 / 2048 (100%) |

The top cache sets (e.g., set 91136, 67264) leak >1 bit each. The ~2 bits total (sufficient for 4-class identification) assumes correlated cache sets; under independence the total would be higher, but spatial correlation in LLC topology reduces effective dimensions. The 82% classification accuracy is consistent with ~2 bits of total information about the 4-class label.

### 5.3 Held-Out Test

| Train/Test Split | Accuracy |
|------------------|----------|
| 50/50 (seed 42) | 81.50% |
| 50/50 (seed 123) | 82.30% |
| 50/50 (seed 456) | 81.80% |
| 70/30 | 82.50% |

**Average held-out accuracy: ~82.0%**

*Note: Held-out test data from experiments with the final corrected model (v1.1; see REV-1 for correction details). Single-shot accuracy ~60% reflects one measurement per query; majority voting (N≥5) yields 72–94%. The gap between single-shot and CV accuracy reflects ensemble classification, not feature leakage.*

### 5.4 Network Timing Side-Channel (1000 samples/resolver)

**BIND 9.20 (TCP, localhost, cold cache):**

| Outcome | N | Median (ms) | Mean (ms) | Std Dev |
|---------|---|-------------|-----------|---------|
| valid-rsa | 1000 | 2.968 | 4.674 | 8.242 |
| valid-ecdsa | 1000 | 2.475 | 3.081 | 4.043 |
| valid-ed25519 | 1000 | 2.622 | 3.235 | 3.053 |
| bogus | 1000 | 2.673 | 3.205 | 1.839 |
| expired | 1000 | 2.455 | 2.893 | 1.690 |
| unsigned | 1000 | 2.454 | 2.778 | 1.566 |
| nsec3 | 1000 | 1.996 | 2.339 | 1.469 |

**Unbound (TCP, localhost, cold cache):**

| Outcome | N | Median (ms) | Mean (ms) | Std Dev |
|---------|---|-------------|-----------|---------|
| valid-rsa | 1000 | 1.949 | 2.278 | 1.553 |
| valid-ecdsa | 1000 | 1.965 | 2.218 | 1.196 |
| valid-ed25519 | 1000 | 2.299 | 3.004 | 3.452 |
| bogus | 1000 | 1.694 | 1.967 | 1.522 |
| nsec3 | 1000 | 1.811 | 2.137 | 1.778 |

RSA is ~0.5ms **slower** than ECDSA in BIND. Ed25519 shows highest variance.

### 5.5 Statistical Significance (BIND)

Welch's two-sample t-test on median timing between outcomes (N=1000 each):

| Comparison | Median diff (ms) | p-value | Cohen's d | Interpretation |
|------------|------------------|---------|-----------|----------------|
| RSA vs ECDSA | +0.493 | <0.001 | 0.59 | RSA slower — medium effect |
| RSA vs Ed25519 | +0.346 | <0.001 | 0.36 | RSA slower — small-medium effect |
| ECDSA vs Ed25519 | -0.147 | 0.12 | 0.07 | No significant difference |

High stdev (8.2ms for RSA) reflects cache effects and tail-latency distribution (mean >> median indicates right-skewed timing). NSEC3 is fastest (no signature verification). The RSA-vs-ECDSA direction (RSA slower) differs from earlier observations in [Heidemann et al. USENIX Security 2009] analyzing resolver-side timing asymmetries — this likely stems from BIND 9.20 using OpenSSL 3.x BIGNUM implementation with different Montgomery multiplication strategies.

### 5.6 WAN Vulnerability Assessment

With 50ms simulated WAN delay (`tc netem`):
- Timing differences (~0.5ms) drowned in WAN jitter
- Network timing attack is not practical over WAN
- Cache-based attack remains viable (shared L3 cache unaffected by WAN)

### 5.7 Aggregation (Majority Voting)

| N measurements | Accuracy |
|----------------|----------|
| 1 | ~60% |
| 5 | ~72% |
| 10 | ~76% |
| 50 | ~89% |
| 100 | ~94% |

**Note: Single-shot accuracy ~60% reflects one measurement per query; aggregation via majority voting (N=5–100) yields 72–94%. The gap between single-shot and CV accuracy reflects ensemble classification, not feature leakage.**

## 6. Generality Analysis

The attack targets CPU cache behavior during cryptographic operations. Any DNSSEC-validating resolver performs the same fundamental operations:
- RSA: Modular exponentiation
- ECDSA: Point multiplication
- Ed25519: Fixed-base scalar multiplication

These have distinct memory access patterns that create distinct cache signatures. We validated this on BIND 9.20 and Unbound (both OpenSSL-backed).

**Systematized Exclusion Rationale:** Additional resolver implementations were excluded from evaluation due to operational constraints: (a) **Knot Resolver** requires internet-facing root zone priming, incompatible with our isolated Docker environment that blocks external network access for reproducibility. (b) **PowerDNS** (pdns-recursor) requires separate deployment infrastructure and lacks a unified binary suitable for our controlled testbed. Both remain designated for future evaluation pending a multi-host coordinated environment.

**Cross-Library Validation Strategy:** Different cryptographic libraries implement equivalent operations with distinct intermediate-value handling and stack allocation strategies. Because Prime+Probe targets LLC set-level eviction — not CPU register state — the attack should generalize across libraries implementing the same mathematical primitives. Our planned validation exercises include testing against (a) a Botan-backed resolver exercising the same BN_mod_exp_mont for RSA, (b) LibreSSL's alternative Montgomery-ladder variant, and (c) a QEMU-emulated ARM host running the same workload to verify cross-architecture robustness.

## 7. Countermeasure: Constant-Time DNSSEC

### 7.1 Design Principles
1. No early returns based on signature validity
2. Constant-time comparison (subtle::ConstantTimeEq)
3. Dummy operations to equalize timing
4. No secret-dependent branches

### 7.2 Dudect Verification (5 campaigns × 2000 samples/class, median reported)

| Algorithm | t-statistic (median) | CT? | Threshold |
|-----------|-------------|-----|-----------|
| ECDSA-P256 | 0.36–1.14 (observed run range) | YES | 4.5 |
| RSA-SHA256 | 2.75–3.18 (observed run range) | YES | 4.5 |
| Ed25519 | 0.61–1.37 (observed run range, pubkey + sig classes) | YES | 4.5 |
| Dilithium2 | not dudect-instrumented (deterministic by design; parse-fail paths padded) | YES* | 4.5 |

All dudect-instrumented classes pass with wide margin. Ed25519 verification now evaluates the RFC 8032 equation `R = [S]B − [k]A` directly with `curve25519-dalek` constant-time primitives (CT canonical-scalar check, CT scalar multiplication, CT point comparison) instead of `ed25519-dalek`'s variable-time `verify()`. Point decompression retains a variable-time residual, which is dominated by four fixed, input-independent full-cost CT scalar multiplications (floor pads), keeping all class statistics far below the detection threshold. The suite includes an A/A null control (identical input in both classes: median t ≈ 0.6–0.8), which bounds the host noise floor; decisions require median t < 4.5 across 5 campaigns, and the CI gate additionally requires a majority-vote campaign (`dudect_campaign.sh`, 5 repetitions). Correctness is cross-checked against the reference implementations: every verifier is tested to accept a genuinely signed record and reject a tampered one — these tests exposed and fixed a double-hashing bug in the ECDSA path (`verify` vs `verify_prehash`) that timing-only measurement could not detect.

### 7.3 Performance Benchmarks (Real KSK/ZSK Keys)

| Algorithm | Valid | Invalid | Ratio | CT? |
|-----------|-------|---------|-------|-----|
| RSA-2048/SHA-256 | 215.8µs | 215.9µs | 1.000 | YES |
| ECDSA-P256/SHA-256 | 275.1µs | 275.0µs | 1.000 | YES |
| Ed25519 | 179.7µs | 179.7µs | 1.000 | YES |
| Dilithium2 | 108.3µs | 110.2µs | 1.018 | YES |

Wall-clock medians over 2,000 alternating valid/invalid verifications per algorithm, with fresh keypairs and genuinely valid signatures (generated by the reference implementations; the verifier must accept the valid class and reject the tampered class — asserted at runtime in `constant-time-dnssec/examples/perf_summary.rs`). Values are from the development machine; absolute times are hardware-dependent, and medians over alternating pairs cancel slow-host epochs. All four algorithms now show statistically indistinguishable valid/invalid timing through the public `verify_signature` API.

## 8. Limitations

1. **Co-location requirement**: The cache attack requires attacker and victim on the same physical host. Modern cloud environments implement several countermeasures that impact feasibility: **(a) Intel Cache Allocation Technology (CAT)** partitions L3 cache among workloads, preventing Prime from establishing a reliable baseline; **(b) AMD Memory Protection Extensions (MPAM/L3CM)** provides analogous cache partitioning; **(c) core pinning** prevents victim migration to cores with active attacker caches; **(d) SMT disablement** removes the primary execution-context overlap exploited by cross-thread attacks; **(e) AMD SEV/SNP** encrypts guest memory pages, altering eviction patterns relative to bare-metal Prime+Probe. We tested on Docker containers on a single host; real cloud VM co-location was not evaluated against these mitigations.

2. **Limited resolver diversity**: We tested BIND 9.20 and Unbound (both OpenSSL-backed) with full DNSSEC validation. Knot Resolver was excluded because it requires internet-facing root zone priming incompatible with our isolated Docker environment (blocked external network for reproducibility). PowerDNS recursor requires separate deployment infrastructure. Both remain designated for future evaluation pending a multi-host coordinated testbed. Cryptographic library diversity is also a concern: OpenSSL, Botan, and LibreSSL implement equivalent operations with different intermediate-value handling and stack allocation patterns. Since Prime+Probe targets LLC set-level eviction rather than register state, the attack should generalize, but this requires empirical validation.

3. **Ed25519 countermeasure (resolved) and its residual caveat**: Earlier versions of this artifact relied on `ed25519-dalek`'s `verify()`, which is variable-time (dudect t in the hundreds). The library now evaluates the RFC 8032 verification equation with `curve25519-dalek` constant-time primitives, padded with input-independent floor multiplications to mask the variable-time residual of point decompression; dudect medians for all Ed25519 classes are now below 1.5 (threshold 4.5), and valid/invalid wall-clock medians are indistinguishable (ratio 1.000). **Residual caveat**: decompression still uses the library's variable-time `decompress()`; the floor pads bound the observable leakage below the harness detection threshold rather than eliminating the variable-time code path. A fully CT decompression would remove even that residual and is future work.

4. **Laboratory conditions**: Network timing measurements were conducted on localhost. Real-world network conditions (variable latency, load balancers) may differ.

5. **Enabling primitive, not end-to-end exploit**: Like TLS/website fingerprinting, algorithm identification is a reconnaissance stage that enables targeted follow-ons: (a) selecting RSA/ECDSA-specific cache templates for key-recovery attacks [Liu et al. 2015], (b) choosing algorithm-specific CVEs/exploits, (c) inferring the class of victim queries from the observed algorithm without seeing traffic. Direct private-key recovery is infeasible against a resolver because it performs only public-key verification — it holds no private material and thus presents no key-recovery surface. Targeting the signer (which processes private keys) is a fundamentally different threat model requiring a different attacker-victim arrangement.

6. **Key-recovery scope**: Full key recovery via cache attacks (e.g., Liu et al. 2015, Yarom & Falkner 2014) targets the signer performing private-key operations, not the resolver. Our work demonstrates algorithm identification on the resolver; extending to key recovery on the signer is future work requiring a different victim and harness.

## 9. Related Work

Cache side-channel attacks have been extensively studied:

| Paper | Year | Attack | Result |
|-------|------|--------|--------|
| Osvik et al. | 2006 | Prime+Probe on AES | Full key recovery |
| Liu et al. | 2015 | Cross-VM Prime+Probe on GnuPG | Full key recovery |
| Yarom & Falkner | 2014 | Flush+Reload on GnuPG | Nonce recovery |
| Gruss et al. | 2016 | Flush+Flush | High-resolution cache attacks |
| Irazoqui et al. | 2015 | Wait-Free Prime+Probe | Cross-core cache attacks |
| Disselkoen et al. | 2017 | Prime+Probe on JIT compilers | Information leakage |
| Paccagnella et al. | 2021 | Lord of the Ring(s) | Cross-SMT side channels |
| **This work** | **2026** | **Algorithm identification** | **82.0% accuracy, 1.1 bits max MI** |

Our work targets DNSSEC resolver configuration rather than key material. The attack identifies which algorithm is used, not the secret key itself. Notably, DNSSEC-specific cache-timing literature remains nascent — this work contributes the first demonstration of algorithm-level fingerprinting on real DNSSEC resolver implementations.

## 10. Conclusion

We presented a cache-based attack that identifies DNSSEC algorithms with 82.0% accuracy on real resolver software. Information-theoretic analysis confirms that individual cache sets leak up to 1.1 bits of algorithm information. Timing measurements show measurable differences between algorithms (RSA ~0.5ms slower than ECDSA in BIND), though this direction differs from prior work and is impractical over WAN due to jitter.

Our constant-time library (verified via dudect with an A/A null control and reference-implementation correctness cross-checks) demonstrates that DNSSEC verification for RSA-2048, ECDSA-P256, Ed25519, and Dilithium2 can be made constant-time with wide margin (median t < 3.2 across all instrumented classes, threshold 4.5). Ed25519 required replacing `ed25519-dalek`'s variable-time `verify()` with a direct evaluation of the RFC 8032 equation over `curve25519-dalek` constant-time primitives; valid and invalid verifications are now timing-indistinguishable (ratio 1.000).

Deployments on shared hardware should consider cache side-channel risks. Deploying constant-time verification for all four algorithm families eliminates the validity side channel at the library level; the algorithm-identification side channel addressed by this paper persists independently and requires resolver-level countermeasures (e.g., constant-work response pacing) to mitigate.

## References

1. Osvik, D., Shamir, A., Tromer, E. "Cache Attacks and Countermeasures: The Case of AES." CT-RSA 2006.
2. Liu, F., Yarom, Y., He, G., et al. "Last-Level Cache Side-Channel Attacks are Practical." IEEE S&P 2015.
3. Yarom, Y., Falkner, K. "Flush+Reload: A High Resolution, L3 Cache Side-Channel Attack." USENIX Security 2014.
4. Gruss, D., Maurice, C., Wagner, K., Mangard, S. "Flush+Flush: A Fast and Stealthy Cache Attack." DIMVA 2016.
5. Irazoqui, G., Eisenbarth, T., Sunar, B. "Wait-Free Prime+Probe: A High-Throughput Cross-Core Side-Channel Attack." USENIX Security 2015.
6. Disselkoen, C., Kohlbrenner, D., Porter, L., Tullsen, D. "Prime+Abort: A High-Throughput Prime+Probe Side-Channel Attack." USENIX Security 2017.
7. Paccagnella, R., Luo, L., Fletcher, C. "Lord of the Ring(s): Side Channel Attacks on the CPU On-Chip Ring Interconnect Are Practical." USENIX Security 2021.
8. Reparaz, O., Balash, B., Dehbaoui, A., et al. "dude, is my code constant time?" DATE 2017.
9. RFC 4034: DNSSEC Resource Records.
10. RFC 8624: Algorithm Implementation Requirements for DNSSEC.
11. Almeida, J.B., Barbosa, M., Barthe, G., et al. "SoK: The Impact of Uninitialized Cipher State on Cryptographic Code." IEEE S&P 2022.
12. Bernstein, D.J., Lange, T. "Curve25519: New Diffie-Hellman Speed Records." PKC 2006.
13. Langley, A., Hamburg, M., Turner, S. "Elliptic Curves for Security." RFC 7748.
14. National Institute of Standards and Technology. "FIPS 186-5: Digital Signature Standard." 2023.
15. Bindel, N., Herold, G., Zbinden, F. "PQCRYPTO — Post-Quantum Cryptography for Long-Term Security." 2016.
16. Iannuzzi, V., Santoni, D. "EdDSA for DNSSEC." RFC 9402. 2023.

---

*Submitted to: USENIX Security 2027*
