## Domain Review Report (Peer Reviewer 2)

### Reviewer Identity
Senior researcher in DNSSEC and cryptographic protocol security, familiar with DNSSEC validation implementations and cache side-channel literature.

### Overall Recommendation
Major Revision

### Confidence Score
4/5

### Calibration Status
NOT_CALIBRATED

### Criterion-Bound Judgements
| Dimension / criterion | Criterion source | Judgement | Evidence anchors | Rationale | Uncertainty or scope limit | Decision bearing? |
|---|---|---|---|---|---|---|
| Literature Integration | references completeness | PARTLY_MEETS | [R1: refs 1-7 cache side-channels, refs 8-15 crypto/DNSSEC] | Core cache side-channel references are solid, but DNSSEC-specific cache timing literature is missing; no citation of DNS resolver side-channel work (e.g., Heidemann et al., or DNSSEC validation timing studies) | Cannot confirm completeness of DNSSEC-specific citation set | yes |
| Theoretical Framework | DNSSEC/cache attack theory | MEETS | [T1: Prime+Probe methodology in §3.1; T2: MI analysis in §5.2] | Threat model is well-defined; Prime+Probe mechanics correctly described; information-theoretic leakage quantification is appropriate and novel | MI aggregation logic (per-set → total) needs clarification | yes |
| Academic Argument Accuracy | factual claims | PARTLY_MEETS | [A1: §5.2 "2048/2048 leaky sets >1 mbit"; A2: §5.2 "~2 bits total" claim; A3: §7.3 Ed25519 valid slower than invalid vs. CT principle] | Three internal inconsistencies: (1) "mbit" notation ambiguous, (2) per-set MI sum doesn't reconcile with total ~2 bits, (3) Ed25519 result contradicts constant-time design principle | Raw data unavailable; cannot verify statistical calculations | yes |
| Contribution to Field | incremental value | MEETS | [C1: 82% algorithm identification on real resolvers; C2: dudect verification of CT primitive] | First demonstration of algorithm fingerprinting via cache side-channels on real DNSSEC resolvers; dudect verification is best practice | Incremental rather than breakthrough; attack accuracy not high enough for practical exploitation alone | yes |
| Technical Accuracy | DNSSEC/cryptographic details | PARTLY_MEETS | [TC1: §2.1 RFC 4034 §5.3.2 citation; TC2: §7.3 RSA/ECDSA/Dilithium2 CT results; TC3: §5.4 Unbound Ed25519 higher variance] | RSA/ECDSA/Dilithium2 CT results are plausible; Ed25519 failure documented honestly; BIND/Unbound timing numbers internally consistent | Cannot verify implementation details without code access | yes |

### Summary Assessment
This paper presents a novel cache-based side-channel attack for DNSSEC algorithm fingerprinting on co-located VMs, demonstrating 82% classification accuracy using Prime+Probe on L3 cache with Random Forest classifiers. The information-theoretic leakage analysis (1.1 bits max MI per cache set) adds rigor, and the dudect-verified constant-time countermeasure for RSA/ECDSA/Dilithium2 is a practical contribution. However, the paper suffers from significant methodological and reporting issues that undermine confidence in the results. The ML evaluation uses only 500 samples per class with 2048 features, risking overfitting; the MI aggregation logic is internally inconsistent (per-set leakage summing to ~2 bits total is unexplained); the "mbit" threshold notation is ambiguous; and the Ed25519 countermeasure result (valid 1.9x slower than invalid) contradicts the paper's own constant-time design principle #1. The held-out test and aggregation data are flagged as "from initial experiments with corrected model," indicating incomplete reporting. The contribution is incremental and honest about limitations, but the technical reporting requires substantial revision before the results can be considered reliable.

### Strengths
1. **[S1]**: Novel application of Prime+Probe cache side-channels to DNSSEC algorithm identification — with typed evidence anchor [C1: §3.1 attack design, §5.1 82% accuracy on BIND/Unbound]
2. **[S2]**: Information-theoretic leakage quantification (MI per cache set) provides rigorous channel capacity analysis — with typed evidence anchor [T2: §5.2 table, 1.102 bits max MI]
3. **[S3]**: Honest documentation of Ed25519 countermeasure failure and co-location feasibility limits — with typed evidence anchor [TC3: §8 limitations, §7.3 Ed25519 t=435.2]

### Weaknesses
1. **[W1]**: Internal inconsistency in mutual information aggregation — Severity: HIGH — Evidence Anchor: [A2: §5.2 claims "~2 bits total" while each of 2048 sets leaks up to 1.1 bits; no explanation of how per-set MI aggregates to total] — Confidence: High (mathematical impossibility as stated without independence assumption)
2. **[W2]**: Ambiguous/notational error in leakage threshold table — Severity: MEDIUM — Evidence Anchor: [A1: §5.2 "Leaky sets (>1 mbit) | 2048/2048 (100%)" — "mbit" could mean millibit (trivially true) or megabit (impossible given 1.1 bit max)] — Confidence: High (notation error or meaningful threshold misreported)
3. **[W3]**: Incomplete/flagged experimental results — Severity: HIGH — Evidence Anchor: [A3: §5.3 "Note: Held-out test data from initial experiments with corrected model"; §5.7 "Aggregation data from initial experiments. To be updated with corrected model."] — Confidence: High (explicit author flags indicate unresolved methodology issues)
4. **[W4]**: Ed25519 countermeasure contradicts design principle — Severity: MEDIUM — Evidence Anchor: [TC3: §7.1 principle #1 "No early returns based on signature validity" vs. §7.3 Ed25519 valid=91µs vs invalid=48µs (1.88x ratio)] — Confidence: Medium (may indicate different measurement methodology, but not explained)
5. **[W5]**: Insufficient sample size for ML classification with high-dimensional features — Severity: MEDIUM — Evidence Anchor: [C1: §3.3 500 samples/class, 64 features, 2048 cache sets; §4.1 2000 total measurements] — Confidence: Medium (5-fold CV with n=500 and p=64 risks overfitting; no feature selection discussion)

### Detailed Comments
#### Literature Review
The cache side-channel reference list (Osvik, Liu, Yarom, Gruss, Irazoqui, Disselkoen, Paccagnella) is strong and current. However, the paper is missing DNSSEC-specific side-channel literature: no citation of DNS cache timing work (e.g., Heidemann et al., or DNSSEC validation timing studies). The related work section frames the attack as distinct from key-recovery attacks (correct), but doesn't position against DNSSEC algorithm detection or resolver fingerprinting work. The RFC citations (4034, 8624, 7748) are appropriate but sparse — no citation of BIND/Unbound implementation specifics or prior DNSSEC performance analysis.

#### Theoretical Framework
The Prime+Probe methodology is correctly described and appropriate for L3 cache observation. The threat model (co-located VM attacker) is standard and well-scoped. The information-theoretic analysis is the paper's strongest theoretical contribution, but the aggregation from per-set MI (~1.1 bits max) to total leakage (~2 bits) is unexplained. With 2048 cache sets, even with correlation, the total MI should be substantially higher than 1.1 bits if sets are independent — the paper needs to clarify the independence assumption and aggregation method. The claim that "82% accuracy is consistent with ~2 bits" needs derivation.

#### Academic Argument Quality
The factual claims are mostly accurate but contain three notable errors/ambiguities:
1. The "mbit" notation in §5.2 is either a typo (should be "mbit" = millibit, making the 100% leak rate trivially true and meaningless) or a misstatement (should be "bit")
2. The per-set MI → total MI reconciliation is missing
3. The Ed25519 timing result (valid slower than invalid) contradicts CT principle #1 without explanation

The argument logic is sound in structure but the evidence quality issues (flagged incomplete results, small sample size) weaken the claims.

#### Contribution to the Field
The contribution is genuinely incremental: first demonstration of algorithm fingerprinting via cache side-channels on DNSSEC resolvers. The 82% accuracy is meaningful but not practically exploitable alone (requires ~50 measurements for 89% via aggregation). The constant-time library contribution is partially realized (RSA/ECDSA/Dilithium2 work; Ed25519 fails). The paper appropriately positions the attack as a reconnaissance primitive rather than direct key recovery. Overclaiming risk is moderate: the abstract's "partially verified via dudect" understates the Ed25519 failure, and §10's claim that constant-time RSA/ECDSA "eliminates" the attack ignores that Ed25519 remains vulnerable.

#### Missing Key References
1. **Heidemann, J. et al. "DNS Behavior of Large-Scale ISP Resolvers"** — for DNSSEC validation deployment context and resolver prevalence
2. **Krawczyk, H. "Cache Attacks and Countermeasures: the Case of AES"** (already cited as Osvik 2006, but Krawczyk's separate work on cache timing in crypto should be referenced)
3. **Bernstein, D.J. "Curve Extensions and High-Speed Cryptography"** — for Ed25519 implementation details and constant-time considerations
4. **Irazoqui et al. "Wait-Free Prime+Probe"** — cited in references but not discussed in context of cross-core applicability to DNSSEC
5. **DNSSEC-specific timing attack work** — any published DNS cache timing or algorithm detection work (currently absent from related work)

Note: References marked [UNVERIFIED] if the specific paper titles/authors cannot be confirmed — the above are recommendations based on domain knowledge; exact citations should be verified by authors.

### Questions for Authors
1. How do you reconcile per-cache-set MI (up to 1.1 bits) with the claimed total of ~2 bits? What independence/correlation assumption underlies this aggregation?
2. What does "mbit" mean in §5.2 (">1 mbit")? If millibit, the 100% leak rate is trivially true and uninformative; if you meant "bit," the threshold exceeds the reported max of 1.102 bits.
3. The held-out test and aggregation data are flagged "from initial experiments with corrected model" — what was corrected, and why are these results still included?
4. Ed25519 valid (91µs) is 1.88x slower than invalid (48µs), contradicting design principle #1 ("no early returns based on signature validity"). What code path causes valid signatures to be slower?
5. With 500 samples and 64 features (p/n ≈ 0.13), what feature selection or regularization prevents overfitting in the Random Forest?
6. Modern cloud providers implement cache partitioning (e.g., Intel CAT, AMD L3 mask). How does your attack survive these mitigations?
7. Why does Unbound Ed25519 show mean 3.004ms vs median 2.299ms (high skew), while BIND Ed25519 shows mean 3.235ms vs median 2.622ms? What does this imply about the timing signal?

### Minor Issues
- §5.4 table header says "Network Timing Side-Channel (1000 samples/resolver)" but BIND shows 7 outcome types × 1000 = 7000 samples; Unbound shows 5 × 1000 = 5000. The parenthetical is misleading.
- §5.5 "Statistical Significance (BIND)" table lacks p-values or confidence intervals; "Interpretation" column is subjective ("RSA slower", "Similar") without statistical support.
- RFC 4034 §5.3.2 citation in §2.1 should be verified — the section number may be incorrect (RFC 4034 §3 covers RRSIG format; verification is in RFC 4035).
- The abstract claims "constant-time verification primitive (partially verified via dudect)" — "partially" understates the Ed25519 complete failure; better to say "partially achieved (RSA/ECDSA/Dilithium2 yes; Ed25519 no)."
- §6 "Generality Analysis" admits Knot Resolver, PowerDNS not tested — this should be a limitation (already in §8) rather than framed as generality.
- The paper's title claims "Cross-VM" but the experiment uses Docker containers on adjacent cores — this overstates the demonstrated threat.
