//! Wall-clock performance summary for constant-time verification.
//!
//! Generates fresh keypairs and *genuinely* valid signatures for each
//! algorithm (the criterion bench fixtures do not actually verify), then
//! measures valid vs invalid verification pairwise to cancel clock drift.
//!
//! Run: `cargo run --release --example perf_summary`

use bytes::Bytes;
use constant_time_dnssec::{
    DnssecAlgorithm, DnssecSignature, SignedData, prepare_signed_data, verify_dilithium2,
    verify_ecdsa_p256, verify_ed25519, verify_rsa_sha256,
};
use std::time::Instant;

fn signed_data() -> SignedData {
    SignedData {
        rrset_data: Bytes::from("perf-summary rrset real data for timing analysis"),
        rrsig_header: Bytes::from("perf-summary rrsig header"),
    }
}

fn make(algorithm: DnssecAlgorithm, sig: Vec<u8>, pk: Vec<u8>) -> DnssecSignature {
    DnssecSignature {
        algorithm,
        signature: Bytes::from(sig),
        public_key: Bytes::from(pk),
    }
}

/// Median of a list of nanosecond durations, in microseconds.
fn median_us(durs_ns: &mut [u128]) -> f64 {
    durs_ns.sort_unstable();
    let n = durs_ns.len();
    if n % 2 == 1 {
        durs_ns[n / 2] as f64 / 1000.0
    } else {
        (durs_ns[n / 2 - 1] + durs_ns[n / 2]) as f64 / 2000.0
    }
}

fn mean_us(durs_ns: &[u128]) -> f64 {
    durs_ns.iter().sum::<u128>() as f64 / durs_ns.len() as f64 / 1000.0
}

/// Measure one algorithm: N alternating valid/invalid verifications.
fn measure(
    name: &str,
    valid: &DnssecSignature,
    invalid: &DnssecSignature,
    data: &SignedData,
    verify: impl Fn(&DnssecSignature, &SignedData) -> constant_time_dnssec::CtVerificationResult,
) {
    assert!(
        verify(valid, data).is_valid(),
        "{name}: valid signature must verify"
    );
    assert!(
        !verify(invalid, data).is_valid(),
        "{name}: invalid signature must fail"
    );

    let n = 2000;
    let mut t_valid: Vec<u128> = Vec::with_capacity(n);
    let mut t_invalid: Vec<u128> = Vec::with_capacity(n);

    // Warmup: allocator, caches, branch predictors.
    for _ in 0..200 {
        std::hint::black_box(verify(valid, data));
        std::hint::black_box(verify(invalid, data));
    }

    // Pairwise alternation so slow host epochs hit both classes equally.
    for _ in 0..n {
        let t0 = Instant::now();
        std::hint::black_box(verify(valid, data));
        t_valid.push(t0.elapsed().as_nanos());

        let t1 = Instant::now();
        std::hint::black_box(verify(invalid, data));
        t_invalid.push(t1.elapsed().as_nanos());
    }

    let (mv, mi) = (median_us(&mut t_valid), median_us(&mut t_invalid));
    println!(
        "{name:<12} valid: mean {:>9.1}us  median {:>9.1}us | invalid: mean {:>9.1}us  median {:>9.1}us | ratio(med): {:>5.3}",
        mean_us(&t_valid),
        mv,
        mean_us(&t_invalid),
        mi,
        mi / mv
    );
}

fn main() {
    println!("constant-time-dnssec wall-clock summary (release build)");
    println!("method: 2000 alternating valid/invalid verifications each, median reported");
    println!();

    let data = signed_data();
    let prepared = prepare_signed_data(data.rrsig_header.as_ref(), &[data.rrset_data.as_ref()]);

    // --- Ed25519 (fresh keypair, sign the exact canonical bytes) ---
    {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        let sig = sk.sign(prepared.as_slice());
        let valid = make(
            DnssecAlgorithm::Ed25519,
            sig.to_bytes().to_vec(),
            sk.verifying_key().to_bytes().to_vec(),
        );
        let mut bad = sig.to_bytes();
        bad[0] ^= 0x01;
        let invalid = make(
            DnssecAlgorithm::Ed25519,
            bad.to_vec(),
            sk.verifying_key().to_bytes().to_vec(),
        );
        measure("Ed25519", &valid, &invalid, &data, verify_ed25519);
    }

    // --- ECDSA P-256 (fresh keypair, raw 64-byte signature) ---
    {
        use p256::ecdsa::signature::Signer as _;
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let sig: Signature = sk.sign(prepared.as_slice());
        let pk = VerifyingKey::from(&sk).to_encoded_point(false);
        let valid = make(
            DnssecAlgorithm::EcdsaP256Sha256,
            sig.to_bytes().to_vec(),
            pk.as_bytes().to_vec(),
        );
        let mut bad = sig.to_bytes().to_vec();
        bad[0] ^= 0x01;
        let invalid = make(DnssecAlgorithm::EcdsaP256Sha256, bad, pk.as_bytes().to_vec());
        measure("ECDSA-P256", &valid, &invalid, &data, verify_ecdsa_p256);
    }

    // --- RSA-2048 PKCS#1 v1.5 / SHA-256 (fresh keypair) ---
    {
        use rsa::pkcs1::EncodeRsaPublicKey as _;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{Keypair as _, SignatureEncoding as _, Signer as _};
        let private_key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("RSA keygen");
        let pk = private_key
            .to_public_key()
            .to_pkcs1_der()
            .expect("DER")
            .as_bytes()
            .to_vec();
        let sk = SigningKey::<sha2::Sha256>::new(private_key);
        let sig = sk.sign(prepared.as_slice());
        let valid = make(DnssecAlgorithm::Rsasha256, sig.to_vec(), pk.clone());
        let mut bad = sig.to_vec();
        bad[10] ^= 0x01;
        let invalid = make(DnssecAlgorithm::Rsasha256, bad, pk);
        measure("RSA-2048", &valid, &invalid, &data, verify_rsa_sha256);
    }

    // --- Dilithium2 (fresh keypair from pqcrypto) ---
    {
        use pqcrypto_dilithium::dilithium2::{detached_sign, keypair};
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
        let (pk, sk) = keypair();
        let sig = detached_sign(prepared.as_slice(), &sk);
        let valid = make(
            DnssecAlgorithm::Dilithium2,
            sig.as_bytes().to_vec(),
            pk.as_bytes().to_vec(),
        );
        let mut bad = sig.as_bytes().to_vec();
        bad[100] ^= 0x01;
        let invalid = make(DnssecAlgorithm::Dilithium2, bad, pk.as_bytes().to_vec());
        measure("Dilithium2", &valid, &invalid, &data, verify_dilithium2);
    }
}


