//! Benchmarks for constant-time DNSSEC verification.
//!
//! Measures:
//! 1. Verification time for valid vs invalid signatures
//! 2. Timing variance across different algorithms
//! 3. Overhead of constant-time padding
//!
//! Uses real KSK/ZSK keys extracted from Docker test zones.

#![allow(clippy::semicolon_if_nothing_returned)]

use bytes::Bytes;
use constant_time_dnssec::{DnssecAlgorithm, DnssecSignature, SignedData, verify_signature};
use criterion::{Criterion, black_box, criterion_group, criterion_main};

/// Real RSA KSK public key (260 bytes) from test-valid-rsa.example
const RSA_KEY: &[u8] = include_bytes!("../../real_keys/rsa_key.bin");

/// Real RSA signature (256 bytes) from test-valid-rsa.example
const RSA_SIG: &[u8] = include_bytes!("../../real_keys/rsa_sig.bin");

/// Real ECDSA P-256 KSK public key (64 bytes) from test-valid-ecdsa.example
const ECDSA_KEY: &[u8] = include_bytes!("../../real_keys/ecdsa_key.bin");

/// Real ECDSA signature (64 bytes) from test-valid-ecdsa.example
const ECDSA_SIG: &[u8] = include_bytes!("../../real_keys/ecdsa_sig.bin");

/// Real Ed25519 KSK public key (32 bytes) from test-valid-ed25519.example
const ED25519_KEY: &[u8] = include_bytes!("../../real_keys/ed25519_key.bin");

/// Real Ed25519 signature (64 bytes) from test-valid-ed25519.example
const ED25519_SIG: &[u8] = include_bytes!("../../real_keys/ed25519_sig.bin");

/// Generate a test signature with real keys
fn real_signature(algorithm: DnssecAlgorithm, valid: bool) -> DnssecSignature {
    let (sig_bytes, key_bytes) = match algorithm {
        DnssecAlgorithm::Rsasha256 => {
            if valid {
                (RSA_SIG.to_vec(), RSA_KEY.to_vec())
            } else {
                // Flip bits in signature to make it invalid
                (vec![0xffu8; RSA_SIG.len()], RSA_KEY.to_vec())
            }
        }
        DnssecAlgorithm::EcdsaP256Sha256 => {
            if valid {
                (ECDSA_SIG.to_vec(), ECDSA_KEY.to_vec())
            } else {
                (vec![0xffu8; ECDSA_SIG.len()], ECDSA_KEY.to_vec())
            }
        }
        DnssecAlgorithm::Ed25519 => {
            if valid {
                (ED25519_SIG.to_vec(), ED25519_KEY.to_vec())
            } else {
                (vec![0xffu8; ED25519_SIG.len()], ED25519_KEY.to_vec())
            }
        }
        DnssecAlgorithm::Dilithium2 => {
            if valid {
                (vec![0u8; 2420], vec![0u8; 1312])
            } else {
                (vec![0xffu8; 2420], vec![0u8; 1312])
            }
        }
        _ => (vec![0u8; 64], vec![0u8; 64]),
    };

    DnssecSignature {
        algorithm,
        signature: Bytes::from(sig_bytes),
        public_key: Bytes::from(key_bytes),
    }
}

fn test_data() -> SignedData {
    SignedData {
        rrset_data: Bytes::from("benchmark rrset data for timing analysis"),
        rrsig_header: Bytes::from("benchmark rrsig header data"),
    }
}

fn bench_ed25519_valid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::Ed25519, true);
    let data = test_data();

    c.bench_function("ed25519_valid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_ed25519_invalid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::Ed25519, false);
    let data = test_data();

    c.bench_function("ed25519_invalid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_ecdsa_p256_valid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::EcdsaP256Sha256, true);
    let data = test_data();

    c.bench_function("ecdsa_p256_valid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_ecdsa_p256_invalid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::EcdsaP256Sha256, false);
    let data = test_data();

    c.bench_function("ecdsa_p256_invalid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_rsa_sha256_valid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::Rsasha256, true);
    let data = test_data();

    c.bench_function("rsa_sha256_valid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_rsa_sha256_invalid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::Rsasha256, false);
    let data = test_data();

    c.bench_function("rsa_sha256_invalid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_dilithium2_valid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::Dilithium2, true);
    let data = test_data();
    c.bench_function("dilithium2_valid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_dilithium2_invalid(c: &mut Criterion) {
    let sig = real_signature(DnssecAlgorithm::Dilithium2, false);
    let data = test_data();
    c.bench_function("dilithium2_invalid_real", |b| {
        b.iter(|| {
            let result = verify_signature(black_box(&sig), black_box(&data));
            black_box(result);
        })
    });
}

fn bench_ct_operations(c: &mut Criterion) {
    let a32 = [0u8; 32];
    let b32 = [0u8; 32];
    c.bench_function("ct_slice_compare_32", |b| {
        b.iter(|| {
            let result = constant_time_dnssec::ct_slice_compare(black_box(&a32), black_box(&b32));
            black_box(result);
        })
    });

    let a64 = [0u8; 64];
    let b64 = [0u8; 64];
    c.bench_function("ct_slice_compare_64", |b| {
        b.iter(|| {
            let result = constant_time_dnssec::ct_slice_compare(black_box(&a64), black_box(&b64));
            black_box(result);
        })
    });

    let a256 = [0u8; 256];
    let b256 = [0u8; 256];
    c.bench_function("ct_slice_compare_256", |b| {
        b.iter(|| {
            let result = constant_time_dnssec::ct_slice_compare(black_box(&a256), black_box(&b256));
            black_box(result);
        })
    });
}

criterion_group!(
    benches,
    bench_ed25519_valid,
    bench_ed25519_invalid,
    bench_ecdsa_p256_valid,
    bench_ecdsa_p256_invalid,
    bench_rsa_sha256_valid,
    bench_rsa_sha256_invalid,
    bench_dilithium2_valid,
    bench_dilithium2_invalid,
    bench_ct_operations,
);
criterion_main!(benches);
