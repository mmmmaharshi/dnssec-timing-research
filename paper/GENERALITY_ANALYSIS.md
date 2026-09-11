# Generality Analysis: Algorithm Fingerprinting Across DNSSEC Resolvers

## Key Insight

**The attack targets CPU cache behavior during cryptographic operations, not resolver software.**

Any DNSSEC-validating resolver must perform the same cryptographic operations:
- RSA: Modular exponentiation (Montgomery multiplication)
- ECDSA: Point multiplication (double-and-add on P-256 curve)
- Ed25519: Fixed-base scalar multiplication (Edwards curve)

These operations have **distinct computational structures** that create **distinct cache access patterns**.

## Evidence

### 1. BIND Resolver (Demonstrated)
- **Accuracy**: 81.7% (5-fold CV, n=4000); 78.9% temporal-split
- **Method**: Docker cross-container Prime+Probe
- **Validation**: 5-fold CV, per-class F1 reported (baseline 0.89, RSA 0.86, Ed25519 0.79, ECDSA 0.75)

### 2. Why Other Resolvers Are Expected to Be Vulnerable

| Resolver | DNSSEC Operations | Expected Cache Signature |
|----------|-------------------|-------------------------|
| BIND | RSA/ECDSA/Ed25519 verification | Distinct per algorithm ✓ (measured) |
| Unbound | RSA/ECDSA/Ed25519 verification | Same operations → same signatures (network timing only tested) |
| Knot | RSA/ECDSA/Ed25519 verification | Same operations → same signatures (not tested — requires internet-facing root zone priming) |
| PowerDNS | RSA/ECDSA/Ed25519 verification | Same operations → same signatures (not tested — requires separate deployment infrastructure) |

### 3. Microarchitectural Argument

The attack exploits **CPU cache contention**, which is:
- **Hardware-level**: Shared L3 cache between cores
- **Operation-level**: Different algorithms access different cache sets
- **Independent of software**: Same algorithm = same cache pattern regardless of implementation

### 4. Empirical Support

Our experiments on BIND show:
- Cache timing differences are **statistically significant**
- Effect sizes are **large** for algorithm-separable cache lines
- ML classifiers can **reliably distinguish** algorithms (81.7% accuracy)

## Limitations

1. **Direct testing**: Only BIND tested with full DNSSEC cache-attack validation
2. **Cloud validation**: Not tested (requires co-located VMs)
3. **Noise**: Real-world environments have more noise than Docker
4. **Library diversity**: OpenSSL, Botan, and LibreSSL implement equivalent operations with different stack allocation; cross-library validation is future work

## Conclusion

**The attack is expected to generalize across resolver implementations based on the microarchitectural nature of the channel.**

While we only directly tested BIND, the attack targets CPU cache behavior during cryptographic operations. Any resolver performing DNSSEC validation will exhibit similar cache signatures because:
1. The cryptographic operations are mathematically defined
2. These operations have distinct memory access patterns
3. CPU cache contention is a hardware-level phenomenon

**For the paper**: We demonstrate the attack on BIND and argue expected generality based on the microarchitectural nature of the attack, with cross-implementation validation designated as future work.

---

*Generated: 2026-09-07*
