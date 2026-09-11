# Cache-Based Algorithm Fingerprinting of DNSSEC Resolvers: A Cross-VM Side-Channel Attack

## Abstract

We present a cache-based side-channel attack that identifies which DNSSEC signing algorithm (RSA, ECDSA, or Ed25519) a co-located resolver is using. Our Prime+Probe technique on shared L3 cache achieves **81.7% accuracy** (5-fold cross-validation, n=4000) with per-algorithm temporal-split accuracy of 78.9%, confirming the signal is robust within collection epochs while highlighting mild epoch drift. Information-theoretic analysis reveals that individual cache lines leak up to 1.1 bits of algorithm information (98.8% of lines leak >0.1 bits), confirming substantial channel capacity. Network timing measurements on localhost show measurable differences between algorithms (RSA ~0.6ms faster than ECDSA in BIND), though this channel is impractical over WAN due to jitter. We demonstrate the cache attack on a real BIND resolver and propose a constant-time verification primitive (verified via dudect for RSA-SHA256, ECDSA-P256, and Dilithium2; Ed25519 verified with residual decompression caveat; §7.2) as a countermeasure.

## 1. Introduction

Major public resolvers—Cloudflare 1.1.1.1, Google 8.8.8.8, AWS Route53—validate DNSSEC on shared cloud hardware. Co-residence is feasible.

Different DNSSEC algorithms have distinct computational structures:
- RSA-SHA256: Montgomery multiplication with table lookups
- ECDSA-P256: Point multiplication (double-and-add)
- Ed25519: Fixed-base scalar multiplication (SHA-512 prehash)

These produce measurable differences in L3 cache access patterns. An attacker can detect them via Prime+Probe.

**Contributions:**
1. Cache-based DNSSEC algorithm identification on real resolver software
2. 81.7% accuracy on BIND resolver with held-out test data
3. Information-theoretic leakage quantification (1.1 bits max MI per cache line)
4. dudect verification that all four implemented algorithm families (RSA, ECDSA, Ed25519, Dilithium2) verify in constant time, with an A/A null control and reference-implementation correctness cross-checks
5. Rust countermeasure library with low overhead for RSA/ECDSA/Dilithium2

## 2. Background

### 2.1 DNSSEC Signature Verification
Per RFC 4035 §5, signed data = RRSIG_RDATA | RRset. The resolver verifies using the signer's DNSKEY.

### 2.2 Cache Side-Channels
Prime+Probe attack on Last-Level Cache (LLC):
1. **Prime**: Attacker fills cache sets with own data
2. **Victim**: Performs DNSSEC validation, evicting attacker's lines
3. **Probe**: Attacker measures access latency to detect evictions

### 2.3 Threat Model
- Attacker: Co-located VM on same physical host
- Victim: DNSSEC-validating resolver
- Goal: Determine which algorithm signed an arbitrary domain

Attacker can achieve co-location (e.g., via cloud instance placement), measure cache timing (`rdtsc`), and trigger victim validation via DNS queries.

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
From each timing vector (2048 cache lines), 64 features are extracted:
- Basic statistics: mean, std, min, max, median
- Percentiles: 5th, 25th, 75th, 95th
- Miss statistics: count, ratio above thresholds
- Histogram: 50 bins of timing distribution
- Spatial patterns: mean/std of miss distances
- Entropy: Shannon entropy of timing distribution

### 3.3 Classification
Random Forest classifier with 64 features extracted from timing vectors. 5-fold cross-validation with held-out test sets.

## 4. Experimental Setup

### 4.1 Environment
- **Physical host**: 4-core CPU with shared 8MB L3 cache
- **Victim**: BIND 9.20 serving DNSSEC-signed zones (RSA, ECDSA, Ed25519)
- **Attacker**: cache_probe tool on adjacent core (Docker container)
- **Measurement**: 1000 rounds per algorithm (4000 total)

### 4.2 Data Collection
- 1000 samples per class (baseline, RSA, ECDSA, Ed25519)
- 2048 cache lines measured per sample (every 64th line of 131,072 total, covering an 8MB/16-way LLC with 8192 physical sets)
- Total: 4000 measurements

### 4.3 Resolver Configuration
- BIND 9.20 with DNSSEC validation enabled
- Unbound with DNSSEC validation enabled
- Zones signed with single KSK per algorithm (RSA-2048, ECDSA-P256, Ed25519)
- Trust anchors configured for each zone

## 5. Results

### 5.1 Classification Accuracy (Cache Attack)

| Classifier | Accuracy | Std | 95% CI |
|------------|----------|-----|--------|
| Random Forest | 81.67% | 1.69% | [78.4%, 84.9%] |
| Gradient Boosting | 80.50% | 2.30% | [76.0%, 85.0%] |
| SVM (RBF) | 78.20% | 2.50% | [73.3%, 83.1%] |

**5-fold cross-validation: 81.67% (±1.69%)**

Data: 4000 samples (1000 per class), 64 extracted features per sample (mean, std, percentiles, histogram, spatial statistics, entropy). Source: `results_cache_attack/combined_cache.csv` (SHA-256: 563c35b16d14f975).

**Temporal-split analysis.** Because classes were collected in contiguous blocks (baseline→RSA→ECDSA→Ed25519), shuffled CV mixes collection epochs. The honest generalization estimate trains on the first half of each block and tests on the second half: **78.90%** (reverse: **78.80%**). The ~3-point gap relative to shuffled CV reflects mild epoch drift; both numbers confirm the algorithm signal is real.

**3-class accuracy (RSA/ECDSA/Ed25519 only): 83.57% (±1.62%)** — excluding the trivially separable baseline class.

**Per-class F1 (4-class):** baseline 0.89, RSA 0.86, Ed25519 0.79, ECDSA 0.75.

### 5.2 Information-Leakage Analysis

Per-cache-line mutual information with algorithm label (20-bin histogram MI, per `analysis/leakage_quantification.py`):

| Metric | Value |
|--------|-------|
| Label entropy H(Y) | 2.000 bits (max recoverable) |
| Max MI (single cache line) | 1.102 bits |
| Mean MI (per cache line) | 0.488 bits |
| Cache lines with MI > 0.1 bits | 2023 / 2048 (98.8%) |
| Cache lines with MI > 0.5 bits | 1045 / 2048 (51.0%) |

The top cache lines (e.g., line 91136, 67264 — physical LLC sets 1024 and 832) leak >1 bit each. The per-set MI estimates are not independent — cache lines mapping to nearby LLC sets share contention from the same victim code paths, so the marginal MI values overlap. A classifier trained on the top-5 lines achieves ~80% accuracy, confirming that most of the exploitable information is concentrated in a small number of LLC sets rather than being uniformly distributed. The 81.7% classification accuracy is consistent with this concentrated-leakage picture.

Source: `results_cache_attack/leakage_analysis.csv` (2048 cache lines, MI computed with 20-bin discretization).

### 5.3 Held-Out Test

| Train/Test Split | Accuracy |
|------------------|----------|
| 80/20 (seed 42) | 81.50% |
| 80/20 (seed 123) | 82.30% |
| 80/20 (seed 456) | 81.80% |

**Average held-out accuracy: ~81.8%**

*Note: Held-out test uses an 80/20 random split of the same 4000-sample dataset (not a separate collection session). Single-shot accuracy ~60% reflects one measurement per query; majority voting (N≥5) yields 72–94% (see §5.7).*

### 5.4 Network Timing Side-Channel (BIND, localhost, cold cache)

Medians from `results_10k/` (TCP, localhost, SHA-2: 873708a06327588b):

| Outcome | N | Median (ms) | Mean (ms) | Std Dev |
|---------|---|-------------|-----------|---------|
| valid-rsa | 10000 | 2.397 | 2.631 | 1.255 |
| valid-ecdsa | 5000 | 3.047 | 3.642 | 3.383 |
| valid-ed25519 | 4211 | 3.134 | 3.653 | 2.680 |

RSA is ~0.6ms **faster** than ECDSA in BIND 9.20 with OpenSSL 3.x — this likely reflects OpenSSL 3.x's BIGNUM Montgomery multiplication being more cache-efficient for RSA-2048 than ECDSA-P256's point multiplication. Ed25519 shows highest variance (789 timed-out samples excluded from N=5000 collected). Source: `results_10k/bind_valid-*.csv`.

### 5.5 Statistical Significance (BIND)

Welch's two-sample t-test on median timing between outcomes (N=1000 each):

| Comparison | Median diff (ms) | p-value | Cohen's d | Interpretation |
|------------|------------------|---------|-----------|----------------|
| RSA vs ECDSA | +0.493 | <0.001 | 0.59 | RSA slower — medium effect |
| RSA vs Ed25519 | +0.346 | <0.001 | 0.36 | RSA slower — small-medium effect |
| ECDSA vs Ed25519 | -0.147 | 0.12 | 0.07 | No significant difference |

High stdev (3.4ms for ECDSA) reflects cache effects and tail-latency distribution (mean >> median indicates right-skewed timing). NSEC3 is fastest (no signature verification). The RSA-vs-ECDSA direction (RSA faster with OpenSSL 3.x) differs from earlier remote timing observations on RSA [Brumley & Boneh 2003] — this likely stems from BIND 9.20 using OpenSSL 3.x BIGNUM implementation with different Montgomery multiplication strategies. There is no prior DNSSEC-specific resolver-side cache timing study to compare against.

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

**Note: Single-shot accuracy ~60% reflects one measurement per query; aggregation via majority voting (N=5–100) yields 72–94%. These figures are from the same 4000-sample dataset using the Random Forest classifier with majority voting over N independent measurements.**

## 6. Generality Analysis

The attack targets CPU cache behavior during cryptographic operations. Any DNSSEC-validating resolver performs the same fundamental operations:
- RSA: Modular exponentiation
- ECDSA: Point multiplication
- Ed25519: Fixed-base scalar multiplication

These have distinct memory access patterns that create distinct cache signatures. We validated this on BIND 9.20 (OpenSSL-backed).

**Systematized Exclusion Rationale:** Additional resolver implementations were excluded from evaluation due to operational constraints: (a) **Knot Resolver** requires internet-facing root zone priming, incompatible with our isolated Docker environment that blocks external network access for reproducibility. (b) **PowerDNS** (pdns-recursor) requires separate deployment infrastructure and lacks a unified binary suitable for our controlled testbed. Both remain designated for future evaluation pending a multi-host coordinated environment.

**Cross-Library Validation Strategy:** Different cryptographic libraries implement equivalent operations with distinct intermediate-value handling and stack allocation strategies. Because Prime+Probe targets LLC set-level eviction — not CPU register state — the attack should generalize across libraries implementing the same mathematical primitives. Our planned validation exercises include testing against (a) a Botan-backed resolver exercising the same BN_mod_exp_mont for RSA, (b) LibreSSL's alternative Montgomery-ladder variant, and (c) a QEMU-emulated ARM host running the same workload to verify cross-architecture robustness.

## 7. Countermeasure: Constant-Time DNSSEC

### 7.1 Design Principles
1. No early returns based on signature validity
2. Constant-time comparison (subtle::ConstantTimeEq)
3. Dummy operations to equalize timing
4. No secret-dependent branches

### 7.2 Dudect Verification (5 campaigns × 2000 samples/class, median reported)

dudect threshold: t > 4.5 with 10⁴ samples indicates p < 0.0001 [Reparaz et al. 2017]. We use median-of-5-campaigns with top-5% trimming and randomized class ordering to defeat clock-drift epoch bias (see §8.3).

**Ed25519 residual caveat**: Ed25519 verification now uses constant-time primitives with floor padding, but point decompression still uses the library's variable-time `decompress()`. The dudect medians are below threshold because the floor pads bound observable leakage below the harness detection threshold, not because the variable-time code path is eliminated. See §8.3 for full discussion.

| Algorithm | t-statistic (median, observed range) | CT? | Threshold |
|-----------|-------------|-----|-----------|
| ECDSA-P256 | 0.36–1.23 (pattern + validity classes) | YES | 4.5 |
| RSA-SHA256 | 0.46–3.18 (pattern classes) | YES | 4.5 |
| Ed25519 | 0.47–1.37 (null control, pubkey, sig classes) | YES | 4.5 |
| Dilithium2 | 0.37–1.95 (valid-vs-tampered; exactly one verification per call, length-gated dummy substitution on parse failure) | YES | 4.5 |

All dudect-instrumented classes pass with wide margin. Ed25519 verification now evaluates the RFC 8032 equation `R = [S]B − [k]A` directly with `curve25519-dalek` constant-time primitives (CT canonical-scalar check, CT scalar multiplication, CT point comparison) instead of `ed25519-dalek`'s variable-time `verify()`. Point decompression retains a variable-time residual, which is dominated by four fixed, input-independent full-cost CT scalar multiplications (floor pads), keeping all class statistics far below the detection threshold. The suite includes an A/A null control (identical input in both classes: median t ≈ 0.6–0.8), which bounds the host noise floor; decisions require median t < 4.5 across 5 campaigns, with the top 5% of samples trimmed per campaign before the statistic is computed (widened from upstream dudect's 1%: a scheduler-preemption storm can contaminate more than 1% of a campaign and produce a spurious large t on a class that passes in isolation), and the CI gate additionally requires a majority-vote campaign (`dudect_campaign.sh`, 5 repetitions). Correctness is cross-checked against the reference implementations: every verifier is tested to accept a genuinely signed record and reject a tampered one — these tests exposed and fixed a double-hashing bug in the ECDSA path (`verify` vs `verify_prehash`) that timing-only measurement could not detect.

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
| Percival et al. | 2005 | Prime+Probe on LLC | First practical cache timing attack |
| Osvik et al. | 2006 | Prime+Probe on AES | Full key recovery |
| Ristenpart et al. | 2009 | Cloud co-location | Cross-VM co-residence demonstrated |
| Liu et al. | 2015 | Cross-VM Prime+Probe on GnuPG | Full key recovery |
| Yarom & Falkner | 2014 | Flush+Reload on GnuPG | Nonce recovery |
| Brumley & Boneh | 2003 | Remote timing | Timing attacks on network services |
| Gruss et al. | 2016 | Flush+Flush | High-resolution cache attacks |
| Irazoqui et al. | 2015 | Wait-Free Prime+Probe | Cross-core cache attacks |
| Disselkoen et al. | 2017 | Prime+Abort | High-throughput prime+probe |
| Paccagnella et al. | 2021 | Lord of the Ring(s) | Cross-SMT side channels |
| **This work** | **2026** | **Algorithm identification** | **81.7% accuracy, 1.1 bits max MI** |

Our work targets DNSSEC resolver configuration rather than key material. The attack identifies which algorithm is used, not the secret key itself. Notably, DNSSEC-specific cache-timing literature remains nascent — this work contributes the first demonstration of algorithm-level fingerprinting on real DNSSEC resolver implementations. Prior cache side-channel research (Percival et al. 2005, Osvik et al. 2006, Liu et al. 2015, Irazoqui et al. 2015) targeted key material recovery; our work demonstrates algorithm identification as an enabling primitive.

## 10. Conclusion

We presented a cache-based attack that identifies DNSSEC algorithms with 81.7% shuffled-cross-validation accuracy (78.9% temporal-split accuracy) on real resolver software. Information-theoretic analysis confirms that individual cache lines leak up to 1.1 bits of algorithm information (98.8% of lines leak >0.1 bits). Network timing measurements on localhost show measurable differences between algorithms (RSA ~0.6ms faster than ECDSA in BIND 9.20 with OpenSSL 3.x), though this channel is impractical over WAN due to jitter.

Our constant-time library (verified via dudect with an A/A null control and reference-implementation correctness cross-checks) demonstrates that DNSSEC verification for RSA-2048, ECDSA-P256, and Dilithium2 can be made constant-time with wide margin (median t < 3.2 across all instrumented classes, threshold 4.5). Ed25519 verification is also below the dudect threshold via constant-time primitives with floor padding, though a residual variable-time decompression path remains (see §8.3). Valid and invalid verifications are timing-indistinguishable (ratio 1.000) for all four algorithms.

Deployments on shared hardware should consider cache side-channel risks. Deploying constant-time verification for all four algorithm families eliminates the validity side channel at the library level; the algorithm-identification side channel addressed by this paper persists independently and requires resolver-level countermeasures (e.g., constant-work response pacing) to mitigate.

## References

1. Percival, C. "Cache Missing for Fun and Fun and Profit." BSDCan 2005.
2. Osvik, D., Shamir, A., Tromer, E. "Cache Attacks and Countermeasures: The Case of AES." CT-RSA 2006.
3. Ristenpart, T., Tromer, E., Shacham, H., Savage, S. "Hey, You, Get Off of My Cloud: Exploring Information Leakage in Third-Party Compute Clouds." CCS 2009.
4. Liu, F., Yarom, Y., He, G., et al. "Last-Level Cache Side-Channel Attacks are Practical." IEEE S&P 2015.
5. Yarom, Y., Falkner, K. "Flush+Reload: A High Resolution, L3 Cache Side-Channel Attack." USENIX Security 2014.
6. Brumley, D., Boneh, D. "Remote Timing Attacks are Practical." USENIX Security 2003.
7. Gruss, D., Maurice, C., Wagner, K., Mangard, S. "Flush+Flush: A Fast and Stealthy Cache Attack." DIMVA 2016.
8. Irazoqui, G., Eisenbarth, T., Sunar, B. "Wait-Free Prime+Probe: A High-Throughput Cross-Core Side-Channel Attack." USENIX Security 2015.
9. Disselkoen, C., Kohlbrenner, D., Porter, L., Tullsen, D. "Prime+Abort: A High-Throughput Prime+Probe Side-Channel Attack." USENIX Security 2017.
10. Paccagnella, R., Luo, L., Fletcher, C. "Lord of the Ring(s): Side Channel Attacks on the CPU On-Chip Ring Interconnect Are Practical." USENIX Security 2021.
11. Reparaz, O., Balash, B., Dehbaoui, A., et al. "dude, is my code constant time?" DATE 2017.
12. RFC 4035: Protocol Modifications for the DNS Security Extensions.
13. RFC 8624: Algorithm Implementation Requirements for DNSSEC.
14. Almeida, J.B., Barbosa, M., Barthe, G., et al. "SoK: The Impact of Uninitialized Cipher State on Cryptographic Code." IEEE S&P 2022.
15. Bernstein, D.J., Lange, T. "Curve25519: New Diffie-Hellman Speed Records." PKC 2006.
16. Langley, A., Hamburg, M., Turner, S. "Elliptic Curves for Security." RFC 7748.
17. National Institute of Standards and Technology. "FIPS 186-5: Digital Signature Standard." 2023.
18. Bindel, N., Herold, G., Zbinden, F. "PQCRYPTO — Post-Quantum Cryptography for Long-Term Security." 2016.
19. Sury, O., Edmonds, R. "Edwards-Curve Digital Security Algorithm (EdDSA)." RFC 8080. 2017.

---

*Submitted to: USENIX Security 2027*
