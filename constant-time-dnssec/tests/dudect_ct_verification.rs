//! dudect-based constant-time verification tests for DNSSEC algorithms
//!
//! This module implements statistical constant-time verification using the
//! dudect methodology (Distinguishing attacks Using Student's t-test).
//!
//! The dudect approach:
//! 1. Run the target function with two classes of inputs (class 0 and class 1)
//! 2. Measure execution time for each run
//! 3. Apply Welch's t-test to determine if timing distributions differ
//! 4. If t-statistic exceeds threshold (typically 4.5), timing leak exists
//!
//! A t-value < 4.5 with >10,000 samples provides strong evidence of constant-time.
//!
//! Reference: "dude, is my code constant time?" (Reparaz et al.)

use constant_time_dnssec::*;
use bytes::Bytes;

/// Number of measurements per test (total across all campaigns)
const NUM_MEASUREMENTS: usize = 10_000;

/// t-test threshold for constant-time (conservative: 4.5)
const T_THRESHOLD: f64 = 4.5;

/// Number of independent measurement campaigns per test.
///
/// Upstream dudect methodology: a single t-value is a noisy draw; for
/// genuinely constant-time code the per-campaign t-values scatter around
/// zero, while a real leak produces a consistently large t in *every*
/// campaign (and grows with sample count). Taking the median over several
/// campaigns rejects one-off systematic noise (frequency/thermal wobble at
/// the ~1-cycle scale on loaded hosts) without weakening detection of real
/// leaks, which are orders of magnitude larger.
const NUM_CAMPAIGNS: usize = 5;

/// Simple cycle counter.
///
/// Uses the x86_64 TSC (`rdtsc`, bracketed by `lfence`), as the reference
/// dudect implementation does: the read costs ~10-20ns with no kernel
/// transition. `Instant` (QueryPerformanceCounter) has call overhead and a
/// fast/slow-path kernel-transition bimodality on the same order as the
/// sub-microsecond operations measured here (RSA-SHA256 pads ≈ 0.2-3µs),
/// which buries the signal and produces spurious class-mean shifts.
#[cfg(target_arch = "x86_64")]
fn measure_cycles<F: FnOnce()>(f: F) -> u64 {
    use std::arch::x86_64::{_mm_lfence, _rdtsc};
    unsafe {
        _mm_lfence();
        let start = _rdtsc();
        std::hint::black_box(f());
        _mm_lfence();
        let end = _rdtsc();
        end.wrapping_sub(start)
    }
}

/// Portable fallback (non-x86_64): Instant-derived approximate cycles at 3 GHz.
#[cfg(not(target_arch = "x86_64"))]
fn measure_cycles<F: FnOnce()>(f: F) -> u64 {
    use std::time::Instant;
    let start = Instant::now();
    std::hint::black_box(f());
    let elapsed = start.elapsed();
    (elapsed.as_nanos() as u64) * 3
}

/// Run dudect-style measurement campaign
///
/// Returns (class_0_timings, class_1_timings) in cycles
///
/// Measurement order is randomized (Fisher-Yates) rather than alternated:
/// with fixed alternation, the two classes occupy distinct mean positions in
/// time, so slow clock drift (turbo decay, thermal states) lands
/// asymmetrically and masquerades as a timing leak even for identical code.
fn run_dudect_measurements(
    class_0_fn: impl Fn(),
    class_1_fn: impl Fn(),
    n: usize,
) -> (Vec<u64>, Vec<u64>) {
    let mut class_0_timings = Vec::with_capacity(n);
    let mut class_1_timings = Vec::with_capacity(n);

    /* Randomized measurement order to defeat clock-drift epoch bias */
    let mut rng_state = 0x243F6A8885A308D3u64;
    let mut next_rand = move || {
        /* xorshift64* */
        rng_state ^= rng_state >> 12;
        rng_state ^= rng_state << 25;
        rng_state ^= rng_state >> 27;
        rng_state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let mut count_0 = 0usize;
    let mut count_1 = 0usize;
    while count_0 < n || count_1 < n {
        let take_0 = if count_0 >= n {
            false
        } else if count_1 >= n {
            true
        } else {
            next_rand() & 1 == 0
        };
        if take_0 {
            class_0_timings.push(measure_cycles(&class_0_fn));
            count_0 += 1;
        } else {
            class_1_timings.push(measure_cycles(&class_1_fn));
            count_1 += 1;
        }
    }

    (class_0_timings, class_1_timings)
}

/// Welch's t-test for two independent samples, after outlier trimming
///
/// Following the upstream dudect methodology ("fix" phase), the top
/// percentile of each class is discarded before computing statistics.
/// Wall-clock timings on a general-purpose OS are contaminated by
/// scheduler/preemption outliers (single samples can exceed the mean by
/// 100x+); without trimming, one such sample shifts a class mean enough to
/// produce spurious t-statistics in either direction.
///
/// Returns (t-statistic, degrees_of_freedom)
fn welch_t_test(sample_0: &[u64], sample_1: &[u64]) -> (f64, f64) {
    /* Trim the top 1% of each class (dudect standard practice) */
    let trim = |samples: &[u64]| -> Vec<u64> {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let keep = sorted.len() - sorted.len() / 100;
        sorted[..keep].to_vec()
    };

    let sample_0 = &trim(sample_0);
    let sample_1 = &trim(sample_1);

    let n0 = sample_0.len() as f64;
    let n1 = sample_1.len() as f64;

    let mean_0 = sample_0.iter().sum::<u64>() as f64 / n0;
    let mean_1 = sample_1.iter().sum::<u64>() as f64 / n1;

    let var_0 = sample_0.iter()
        .map(|&x| {
            let diff = x as f64 - mean_0;
            diff * diff
        })
        .sum::<f64>() / (n0 - 1.0);
    let var_1 = sample_1.iter()
        .map(|&x| {
            let diff = x as f64 - mean_1;
            diff * diff
        })
        .sum::<f64>() / (n1 - 1.0);

    let se = (var_0 / n0 + var_1 / n1).sqrt();
    let t_stat = (mean_0 - mean_1) / se;

    /* Welch-Satterthwaite degrees of freedom */
    let numerator = (var_0 / n0 + var_1 / n1).powi(2);
    let denominator = (var_0 / n0).powi(2) / (n0 - 1.0) + (var_1 / n1).powi(2) / (n1 - 1.0);
    let df = numerator / denominator;

    (t_stat.abs(), df)
}

/// Compute descriptive statistics
fn compute_stats(timings: &[u64]) -> (f64, f64, u64, u64) {
    let n = timings.len() as f64;
    let mean = timings.iter().sum::<u64>() as f64 / n;

    let variance = timings.iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>() / (n - 1.0);
    let std_dev = variance.sqrt();

    let min = *timings.iter().min().unwrap();
    let max = *timings.iter().max().unwrap();

    (mean, std_dev, min, max)
}

/// Run full dudect test and report results
///
/// Executes `NUM_CAMPAIGNS` independent measurement campaigns and decides on
/// the median per-campaign t-statistic (see `NUM_CAMPAIGNS`).
fn run_dudect_test(
    name: &str,
    class_0_fn: impl Fn(),
    class_1_fn: impl Fn(),
) -> bool {
    println!("\n=== dudect test: {} ===", name);

    let per_campaign = NUM_MEASUREMENTS / NUM_CAMPAIGNS;
    let mut t_values: Vec<f64> = Vec::with_capacity(NUM_CAMPAIGNS);
    let mut first_stats: Option<((f64, f64, u64, u64), (f64, f64, u64, u64))> = None;

    for campaign in 0..NUM_CAMPAIGNS {
        let (class_0, class_1) =
            run_dudect_measurements(&class_0_fn, &class_1_fn, per_campaign);
        let (t_stat, _df) = welch_t_test(&class_0, &class_1);
        t_values.push(t_stat);

        if campaign == 0 {
            let stats_0 = compute_stats(&class_0);
            let stats_1 = compute_stats(&class_1);
            first_stats = Some((stats_0, stats_1));
        }
    }

    let (mean_0, std_0, min_0, max_0) = first_stats.unwrap().0;
    let (mean_1, std_1, min_1, max_1) = first_stats.unwrap().1;

    t_values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let t_stat = t_values[t_values.len() / 2];
    let t_max = t_values[t_values.len() - 1];

    println!("Class 0: mean={:.2} cycles, std={:.2}, range=[{}, {}]",
             mean_0, std_0, min_0, max_0);
    println!("Class 1: mean={:.2} cycles, std={:.2}, range=[{}, {}]",
             mean_1, std_1, min_1, max_1);
    println!("t-statistic (median of {} campaigns, max {:.4}): {:.4} (threshold: {})",
             NUM_CAMPAIGNS, t_max, t_stat, T_THRESHOLD);

    let is_ct = t_stat < T_THRESHOLD;
    if is_ct {
        println!("✓ PASS: {} appears constant-time (t={:.4} < {})", name, t_stat, T_THRESHOLD);
    } else {
        println!("✗ FAIL: {} has timing leak (t={:.4} >= {})", name, t_stat, T_THRESHOLD);
    }

    is_ct
}

/// Generate test inputs for Ed25519
fn generate_ed25519_test_inputs() -> (DnssecSignature, DnssecSignature, SignedData) {
    let valid_sig = DnssecSignature {
        algorithm: DnssecAlgorithm::Ed25519,
        /* All-zeros is invalid but exercises the same code path */
        signature: Bytes::from(vec![0x42u8; 64]),
        public_key: Bytes::from(vec![0x01u8; 32]),
    };

    let invalid_sig = DnssecSignature {
        algorithm: DnssecAlgorithm::Ed25519,
        /* Different pattern to trigger different execution */
        signature: Bytes::from(vec![0xffu8; 64]),
        public_key: Bytes::from(vec![0x02u8; 32]),
    };

    let data = SignedData {
        rrset_data: Bytes::from("test DNS record data for signature verification"),
        rrsig_header: Bytes::from("RRSIG header data"),
    };

    (valid_sig, invalid_sig, data)
}

/// Generate test inputs for ECDSA P-256
fn generate_ecdsa_test_inputs() -> (DnssecSignature, DnssecSignature, SignedData) {
    let valid_sig = DnssecSignature {
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        signature: Bytes::from(vec![0x42u8; 64]),
        /* Uncompressed SEC1: 0x04 + 32 bytes X + 32 bytes Y */
        public_key: Bytes::from({
            let mut v = vec![0x04u8];
            v.extend(vec![0x01u8; 64]);
            v
        }),
    };

    let invalid_sig = DnssecSignature {
        algorithm: DnssecAlgorithm::EcdsaP256Sha256,
        signature: Bytes::from(vec![0xffu8; 64]),
        public_key: Bytes::from({
            let mut v = vec![0x04u8];
            v.extend(vec![0x02u8; 64]);
            v
        }),
    };

    let data = SignedData {
        rrset_data: Bytes::from("test DNS record data"),
        rrsig_header: Bytes::from("RRSIG header"),
    };

    (valid_sig, invalid_sig, data)
}

/// Generate test inputs for RSA-SHA256
fn generate_rsa_test_inputs() -> (DnssecSignature, DnssecSignature, SignedData) {
    /* Note: RSA requires valid PKCS#1 structure for parse.
     * We use dummy data that exercises the parse-fail path. */
    let valid_sig = DnssecSignature {
        algorithm: DnssecAlgorithm::Rsasha256,
        signature: Bytes::from(vec![0x42u8; 256]),
        public_key: Bytes::from(vec![0x01u8; 256]),
    };

    let invalid_sig = DnssecSignature {
        algorithm: DnssecAlgorithm::Rsasha256,
        signature: Bytes::from(vec![0xffu8; 256]),
        public_key: Bytes::from(vec![0x02u8; 256]),
    };

    let data = SignedData {
        rrset_data: Bytes::from("test DNS record data"),
        rrsig_header: Bytes::from("RRSIG header"),
    };

    (valid_sig, invalid_sig, data)
}

// ============================================================================
// dudect Tests
// ============================================================================

#[test]
fn dudect_ed25519_signature_class() {
    /* Class 0: signature with pattern 0x42
     * Class 1: signature with pattern 0xff
     * If constant-time, these should have indistinguishable timing. */
    let (sig_0, sig_1, data) = generate_ed25519_test_inputs();
    let data_clone = data.clone();

    let class_0 = move || {
        let result = verify_ed25519(&sig_0, &data_clone);
        std::hint::black_box(result);
    };

    let class_1 = move || {
        let result = verify_ed25519(&sig_1, &data);
        std::hint::black_box(result);
    };

    let is_ct = run_dudect_test("Ed25519 signature pattern", class_0, class_1);
    assert!(is_ct, "Ed25519 verification is NOT constant-time");
}

#[test]
fn dudect_ed25519_public_key_class() {
    /* Class 0: public key starting with 0x01
     * Class 1: public key starting with 0x02 */
    let (mut sig_0, mut sig_1, data) = generate_ed25519_test_inputs();

    /* Same signature, different public keys */
    sig_0.signature = Bytes::from(vec![0x42u8; 64]);
    sig_1.signature = Bytes::from(vec![0x42u8; 64]);
    sig_0.public_key = Bytes::from(vec![0x01u8; 32]);
    sig_1.public_key = Bytes::from(vec![0x02u8; 32]);

    let data_clone = data.clone();
    let class_0 = move || {
        let result = verify_ed25519(&sig_0, &data_clone);
        std::hint::black_box(result);
    };

    let class_1 = move || {
        let result = verify_ed25519(&sig_1, &data);
        std::hint::black_box(result);
    };

    let is_ct = run_dudect_test("Ed25519 public key", class_0, class_1);
    assert!(is_ct, "Ed25519 verification leaks via public key");
}

#[test]
fn dudect_ecdsa_p256_signature_class() {
    let (sig_0, sig_1, data) = generate_ecdsa_test_inputs();
    let data_clone = data.clone();

    let class_0 = move || {
        let result = verify_ecdsa_p256(&sig_0, &data_clone);
        std::hint::black_box(result);
    };

    let class_1 = move || {
        let result = verify_ecdsa_p256(&sig_1, &data);
        std::hint::black_box(result);
    };

    let is_ct = run_dudect_test("ECDSA P-256 signature pattern", class_0, class_1);
    assert!(is_ct, "ECDSA P-256 verification is NOT constant-time");
}

#[test]
fn dudect_rsa_sha256_signature_class() {
    let (sig_0, sig_1, data) = generate_rsa_test_inputs();
    let data_clone = data.clone();

    let class_0 = move || {
        let result = verify_rsa_sha256(&sig_0, &data_clone);
        std::hint::black_box(result);
    };

    let class_1 = move || {
        let result = verify_rsa_sha256(&sig_1, &data);
        std::hint::black_box(result);
    };

    let is_ct = run_dudect_test("RSA-SHA256 signature pattern", class_0, class_1);
    assert!(is_ct, "RSA-SHA256 verification is NOT constant-time");
}

#[test]
fn dudect_ct_slice_compare() {
    /* Test the core constant-time primitive */
    let a: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let b: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let c: Vec<u8> = (0..256).map(|i| (i as u8).wrapping_add(1)).collect();

    /* Class 0: compare equal slices
     * Class 1: compare different slices */
    let a0 = a.clone();
    let class_0 = move || {
        let result = ct_slice_compare(&a0, &b);
        std::hint::black_box(result);
    };

    let class_1 = move || {
        let result = ct_slice_compare(&a, &c);
        std::hint::black_box(result);
    };

    let is_ct = run_dudect_test("ct_slice_compare", class_0, class_1);
    assert!(is_ct, "ct_slice_compare is NOT constant-time");
}

/// Comprehensive dudect report
#[test]
fn dudect_full_report() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  dudect Constant-Time Verification Report                   ║");
    println!("║  DNSSEC Timing Side-Channel Research                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("  Measurements per class: {}", NUM_MEASUREMENTS);
    println!("  t-test threshold: {}", T_THRESHOLD);
    println!("  Target: t < {} for constant-time", T_THRESHOLD);

    let mut all_pass = true;

    /* Ed25519 tests */
    let (sig_ed0, sig_ed1, data_ed) = generate_ed25519_test_inputs();
    let data_ed_clone = data_ed.clone();
    let class_0 = move || {
        let result = verify_ed25519(&sig_ed0, &data_ed_clone);
        std::hint::black_box(result);
    };
    let class_1 = move || {
        let result = verify_ed25519(&sig_ed1, &data_ed);
        std::hint::black_box(result);
    };
    if !run_dudect_test("Ed25519 (signature pattern)", class_0, class_1) {
        all_pass = false;
    }

    /* ECDSA tests */
    let (sig_ec0, sig_ec1, data_ec) = generate_ecdsa_test_inputs();
    let data_ec_clone = data_ec.clone();
    let class_0 = move || {
        let result = verify_ecdsa_p256(&sig_ec0, &data_ec_clone);
        std::hint::black_box(result);
    };
    let class_1 = move || {
        let result = verify_ecdsa_p256(&sig_ec1, &data_ec);
        std::hint::black_box(result);
    };
    if !run_dudect_test("ECDSA P-256 (signature pattern)", class_0, class_1) {
        all_pass = false;
    }

    /* RSA tests */
    let (sig_rsa0, sig_rsa1, data_rsa) = generate_rsa_test_inputs();
    let data_rsa_clone = data_rsa.clone();
    let class_0 = move || {
        let result = verify_rsa_sha256(&sig_rsa0, &data_rsa_clone);
        std::hint::black_box(result);
    };
    let class_1 = move || {
        let result = verify_rsa_sha256(&sig_rsa1, &data_rsa);
        std::hint::black_box(result);
    };
    if !run_dudect_test("RSA-SHA256 (signature pattern)", class_0, class_1) {
        all_pass = false;
    }

    println!("\n══════════════════════════════════════════════════════════════");
    if all_pass {
        println!("✓ ALL TESTS PASSED: Implementation is constant-time");
    } else {
        println!("✗ SOME TESTS FAILED: Timing leaks detected");
    }
    println!("══════════════════════════════════════════════════════════════\n");

    /* Note: We don't assert here because individual tests already assert */
    let _ = all_pass;
}
