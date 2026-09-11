## Methodology Review Report (Peer Reviewer 1)

### Reviewer Identity
Research methodology expert specializing in experimental security research and statistical analysis of timing side-channels.

### Overall Recommendation
Major Revision

### Confidence Score
4

### Calibration Status
NOT_CALIBRATED

### Criterion-Bound Judgements
| Dimension / criterion | Criterion source | Judgement | Evidence anchors | Rationale | Uncertainty or scope limit | Decision bearing? |
|---|---|---|---|---|---|---|
| Methodological Rigor | research design execution | PARTLY_MEETS | §3.1 Prime+Probe protocol; §4.1 single-host Docker setup | Attack methodology is clearly specified, but lacks controls for CPU frequency scaling, background load, and Docker overhead; no blinding of classification. | Single-host lab only; cloud co-location not empirically validated. | yes |
| Evidence Sufficiency | data supporting claims | PARTLY_MEETS | §5.1 82% accuracy on 2000 measurements; §5.3 "corrected model" note | Accuracy claim rests on 500 samples/class — underpowered for cross-VM generalization; aggregation figures (§5.7) explicitly labeled "initial experiments," undermining consistency. | No power analysis or sample-size justification provided. | yes |
| Statistical Reporting | APA 7.0 compliance | DOES_NOT_MEET | §5.2 MI table lacks CIs; §5.5 "median diff" without p-values or test names; no multiplicity correction for 2048 cache sets | Effect sizes, CIs, test statistics, and adjusted p-values are absent; MI threshold ">1 mbit" unexplained. | Reviewer can partially reconstruct tests from medians. | yes |
| Reproducibility | method description detail | PARTLY_MEETS | §3.2 64 features listed; §4.1 hardware vague ("4-core CPU, 8MB L3") | Cache-set IDs (e.g., set 91136) exceed 2048 sets — internal inconsistency; "corrected model" undefined; no data/code repository referenced. | Code availability unknown. | yes |
| Internal Validity | confounds addressed | PARTLY_MEETS | §4.1 single-host; §5.4 localhost timing | No randomization of measurement order, no control for CPU freq scaling (Intel Turbo / AMD P-states), no isolation from co-resident noise; Docker container adds unquantified overhead. | Confounds likely inflate accuracy estimates. | yes |
| External Validity | generalization claims | DOES_NOT_MEET | §6 generality "any resolver" vs. §8 limited to BIND/Unbound (OpenSSL) | Generalization asserted in §6 but evidence limited to two OpenSSL-backed resolvers; Knot/PowerDNS untested; cloud VM co-location never empirically demonstrated. | Claims exceed data. | yes |

### Summary Assessment
The paper presents a well-motivated Prime+Probe cache side-channel that fingerprints DNSSEC resolver algorithms with 82% accuracy and quantifies leakage via mutual information. The attack design (§3) and countermeasure verification via dudect (§7.2) are methodologically sound contributions. However, the evidence base is weakened by several methodological shortcomings: (1) no power analysis or sample-size justification for N=500/class, (2) statistical reporting omits p-values, confidence intervals, and multiplicity correction across 2048 cache sets, (3) internal inconsistencies (cache-set IDs exceeding declared set count; aggregation results sourced from an undefined "initial experiments" dataset), (4) confounders (CPU frequency scaling, Docker overhead, background load) uncontrolled, and (5) external-generalization claims ("any resolver") unsupported by the two OpenSSL-backed resolvers tested. The held-out test and 5-fold CV partially mitigate overfitting concerns, but the absence of blinding, randomization, and a pre-registered analysis plan limits internal validity. The paper can be accepted after major revisions addressing statistical rigor, reproducibility artifacts, and tempered generalization language.

### Strengths
1. **[S1]**: Clear, repeatable Prime+Probe protocol (§3.1) with explicit prime/trigger/wait/probe sequencing — supports replication; anchor: §3.1 protocol listing.
2. **[S2]**: Information-theoretic leakage quantification (max MI 1.1 bits, mean 0.488 bits) complements accuracy metrics and strengthens the channel-capacity argument; anchor: §5.2 table.
3. **[S3]**: Honest limitation framing (co-location requirement, Ed25519 incomplete countermeasure, laboratory conditions) — anchors at §8 items 1–5.
4. **[S4]**: Multiple classifiers compared (RF, GB, SVM) with CV + held-out test, reducing single-model overstatement risk; anchor: §5.1, §5.3 tables.

### Weaknesses
1. **[W1]**: No sample-size justification or power analysis (N=2000, 500/class) — Severity: High; Evidence Anchor: §4.2, §5.1; Confidence: High.
2. **[W2]**: Statistical reporting omits p-values, CIs, test names, and multiplicity correction for 2048 MI tests — Severity: High; Evidence Anchor: §5.2, §5.5; Confidence: High.
3. **[W3]**: Internal inconsistency: cache-set IDs 91136/67264 cited as "top sets" but only 2048 sets exist — Severity: Medium; Evidence Anchor: §5.2; Confidence: High.
4. **[W4]**: Aggregation results (§5.7) attributed to "initial experiments" while main results claim "corrected model" — two unstated datasets; Severity: High; Evidence Anchor: §5.3 note, §5.7 note; Confidence: High.
5. **[W5]**: Confounders uncontrolled: CPU frequency scaling, Docker overhead, background processes, no measurement randomization — Severity: Medium; Evidence Anchor: §4.1; Confidence: Medium.
6. **[W6]**: External validity overclaimed: "any DNSSEC-validating resolver" (§6) vs. BIND+Unbound only (§8) — Severity: Medium; Evidence Anchor: §6, §8; Confidence: High.

### Detailed Comments
#### Research Questions & Hypotheses
The primary RQ (algorithm identification via cache timing) is well-defined, but no formal hypotheses (directional or nil) are stated; MI thresholds (">1 mbit") are arbitrary.

#### Research Design
Quasi-experimental single-host design. No randomization of measurement order, no control group beyond "baseline," no blinding of the classifier trainer. 5-fold CV is appropriate but leaks no information about temporal ordering — suspicious if samples are i.i.d. across folds.

#### Sampling & Data Collection
500 measurements per class collected sequentially. No mention of warm-up runs, outlier exclusion, or stopping rules. Docker container on "adjacent core" — core assignment and CPU isolation unspecified.

#### Analysis Methods
Random Forest with 64 features from 2048 sets — feature selection procedure not reported. FFT components included without justification. MI computed per set independently; no FDR correction (2048 tests). dudect t-statistic threshold of 4.5 cited without reference.

#### Statistical Reporting Adequacy
Accuracy reported as point estimate ± std (bootstrap?); held-out test uses three seeds only, no CI. Median differences (§5.5) lack test names and p-values. Network timing table reports mean/median/std but no normality assessment; Welch's t-test or Mann-Whitney not named.

#### Results Integrity
"Corrected model" referenced in §5.3 and §5.7 notes but never defined — potential replication blocker. Cache-set ID error (91136 > 2048) suggests carelessness. Aggregation accuracy (~60%→~94%) lacks variance estimates.

#### Reproducibility
Hardware description too vague ("4-core CPU, 8MB L3"). No repository, no raw timing vectors, no feature-extraction code citation. Docker image unspecified. dudec configurations not archived.

#### Methodological Fallacies Detected
- **p-hacking risk**: 2048 MI tests without correction; "top sets" cherry-picked.
- **Overgeneralization**: laboratory localhost results → "any resolver."
- **Dataset inconsistency**: "corrected model" vs. "initial experiments" without clarification.
- **Selection bias**: only OpenSSL-backed resolvers tested.

### Questions for Authors
1. What power analysis or effect-size justification supports N=500 per class?
2. Which statistical tests generated the §5.5 median differences, and were multiplicity corrections applied?
3. How are cache-set IDs 91136 and 67264 valid when only 2048 sets exist?
4. What exactly is the "corrected model," and why do §5.3/§5.7 notes cite different source datasets?
5. Please archive code, raw timing vectors, and Docker image to enable reproducibility.
6. What CPU isolation measures (frequency scaling, core pinning, cache partitioning) were in place?
7. Why is the dudect threshold 4.5, and was it pre-registered?

### Minor Issues
- Reference 1 misspelled "Osvig" (should be Osvik).
- Abstract claims "partially verified via dudect" — Ed25519 failure should be foregrounded.
- "Baseline" class undefined (§4.2) — is this no-validation traffic?
- FFT feature rationale absent from §3.2.
- Table 5.2 header says "Leaky sets (>1 mbit)" but MI is in bits, not mbit — unit inconsistency.
- No ethical approval or responsible-disclosure statement for the attack.
- Submission target USENIX Security 2027 — formatting/style guide compliance unverified.
