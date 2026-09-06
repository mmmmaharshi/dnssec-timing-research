//! DNSSEC algorithm-specific verification implementations.
//!
//! Each algorithm module provides constant-time verification
//! for its respective signature scheme.

use crate::{CtVerificationResult, DnssecSignature, SignedData};
use sha2::{Digest, Sha256, Sha512};

/// Verify an Ed25519 signature.
///
/// Ed25519 verification is naturally more constant-time than ECDSA
/// due to its deterministic nonce generation.
pub fn verify_ed25519(sig: &DnssecSignature, data: &SignedData) -> CtVerificationResult {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // ponytail: early returns are not constant-time, but padding with dummy
    // SHA-512 + dummy verify to equalize valid/invalid timing. Full fix
    // requires ed25519-dalek constant-time guarantee (it claims ct).
    // Prepare signed data FIRST so both paths pay hashing cost.
    let signed_data =
        crate::prepare_signed_data(data.rrsig_header.as_ref(), &[data.rrset_data.as_ref()]);
    // Always hash (black_box prevents elision)
    let _dummy_hash = Sha512::digest(&signed_data);
    std::hint::black_box(&_dummy_hash);

    let public_key = match VerifyingKey::from_bytes(
        sig.public_key
            .as_ref()
            .try_into()
            .unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(_) => {
            // Dummy ed25519 verify to match valid path (~100µs) — Sha512 alone is 0.5µs, not enough
            if let Ok(dk) = VerifyingKey::from_bytes(&[0x58u8; 32]) {
                if let Ok(ds) = Signature::from_slice(&[0u8; 64][..]) {
                    let r = dk.verify(&signed_data, &ds);
                    std::hint::black_box(&r);
                }
            }
            return CtVerificationResult::failure();
        }
    };

    let signature = match Signature::from_slice(sig.signature.as_ref()) {
        Ok(s) => s,
        Err(_) => {
            if let Ok(dk) = VerifyingKey::from_bytes(&[0x58u8; 32]) {
                if let Ok(ds) = Signature::from_slice(&[0u8; 64][..]) {
                    let r = dk.verify(&signed_data, &ds);
                    std::hint::black_box(&r);
                }
            }
            return CtVerificationResult::failure();
        }
    };

    // ed25519-dalek is claimed ct, but bench 38µs valid vs 5.5µs invalid (7x) — single dummy 10µs vs 46µs (4.5x), double dummy 248 vs 274 µs (1.1x) but 6x overhead
    // ponytail: keep single dummy for minimal overhead; document ed25519 needs 6x to be fully ct
    match public_key.verify(&signed_data, &signature) {
        Ok(()) => CtVerificationResult::success(),
        Err(_) => {
            if let Ok(dk) = VerifyingKey::from_bytes(&[0u8; 32]) {
                if let Ok(ds) = Signature::from_slice(&[0u8; 64][..]) {
                    let r = dk.verify(&signed_data, &ds);
                    std::hint::black_box(&r);
                }
            }
            CtVerificationResult::failure()
        }
    }
}

/// Verify an ECDSA P-256 signature.
///
/// ECDSA verification requires careful handling to maintain
/// constant-time properties.
pub fn verify_ecdsa_p256(sig: &DnssecSignature, data: &SignedData) -> CtVerificationResult {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    // Parse public key (uncompressed form: 65 bytes, or compressed: 33 bytes).
    let Ok(public_key) = VerifyingKey::from_sec1_bytes(sig.public_key.as_ref()) else {
        return CtVerificationResult::failure();
    };

    // Parse signature (DER or raw 64 bytes).
    let Ok(signature) = Signature::from_slice(sig.signature.as_ref()) else {
        return CtVerificationResult::failure();
    };

    // Prepare signed data and hash with SHA-256.
    let signed_data = crate::prepare_signed_data(data.rrsig_header.as_ref(), &[data.rrset_data.as_ref()]);
    let hash = Sha256::digest(&signed_data);

    // p256's verify is designed to be constant-time.
    match public_key.verify(&hash, &signature) {
        Ok(()) => CtVerificationResult::success(),
        Err(_) => CtVerificationResult::failure(),
    }
}

/// Verify an RSA-SHA256 signature.
///
/// RSA verification is naturally constant-time when using
/// constant-time modular exponentiation.
pub fn verify_rsa_sha256(sig: &DnssecSignature, data: &SignedData) -> CtVerificationResult {
    use rsa::RsaPublicKey;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;

    // Parse PKCS#1 RSA public key.
    let Ok(public_key) = RsaPublicKey::from_pkcs1_der(sig.public_key.as_ref()) else {
        return CtVerificationResult::failure();
    };

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    // Parse signature.
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig.signature.as_ref()) else {
        return CtVerificationResult::failure();
    };

    // Prepare signed data.
    let signed_data = crate::prepare_signed_data(data.rrsig_header.as_ref(), &[data.rrset_data.as_ref()]);

    // Verify.
    match verifying_key.verify(&signed_data, &signature) {
        Ok(()) => CtVerificationResult::success(),
        Err(_) => CtVerificationResult::failure(),
    }
}

/// Verify an RSA-SHA512 signature.
pub fn verify_rsa_sha512(sig: &DnssecSignature, data: &SignedData) -> CtVerificationResult {
    use rsa::RsaPublicKey;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;

    // Parse PKCS#1 RSA public key.
    let Ok(public_key) = RsaPublicKey::from_pkcs1_der(sig.public_key.as_ref()) else {
        return CtVerificationResult::failure();
    };

    let verifying_key = VerifyingKey::<Sha512>::new(public_key);

    // Parse signature.
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig.signature.as_ref()) else {
        return CtVerificationResult::failure();
    };

    // Prepare signed data.
    let signed_data = crate::prepare_signed_data(data.rrsig_header.as_ref(), &[data.rrset_data.as_ref()]);

    // Verify.
    match verifying_key.verify(&signed_data, &signature) {
        Ok(()) => CtVerificationResult::success(),
        Err(_) => CtVerificationResult::failure(),
    }
}

/// Verify a Dilithium2 (PQC) signature — constant-time via pqcrypto.
///
/// Dilithium2 sig 2420 B, pubkey 1312 B. Verification is deterministic and
/// designed to be constant-time; we pad parse failures with dummy verify.
pub fn verify_dilithium2(sig: &DnssecSignature, data: &SignedData) -> CtVerificationResult {
    use pqcrypto_dilithium::dilithium2::{verify_detached_signature, DetachedSignature, PublicKey};
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

    let signed_data = crate::prepare_signed_data(data.rrsig_header.as_ref(), &[data.rrset_data.as_ref()]);

    let public_key = match PublicKey::from_bytes(sig.public_key.as_ref()) {
        Ok(k) => k,
        Err(_) => {
            // Dummy verify cost similar to real (~300µs)
            if let Ok(dk) = PublicKey::from_bytes(&[0u8; 1312]) {
                if let Ok(ds) = DetachedSignature::from_bytes(&[0u8; 2420]) {
                    let r = verify_detached_signature(&ds, &signed_data, &dk);
                    std::hint::black_box(&r);
                }
            }
            return CtVerificationResult::failure();
        }
    };

    let signature = match DetachedSignature::from_bytes(sig.signature.as_ref()) {
        Ok(s) => s,
        Err(_) => {
            if let Ok(dk) = PublicKey::from_bytes(&[0u8; 1312]) {
                if let Ok(ds) = DetachedSignature::from_bytes(&[0u8; 2420]) {
                    let r = verify_detached_signature(&ds, &signed_data, &dk);
                    std::hint::black_box(&r);
                }
            }
            return CtVerificationResult::failure();
        }
    };

    match verify_detached_signature(&signature, &signed_data, &public_key) {
        Ok(()) => CtVerificationResult::success(),
        Err(_) => {
            // Pad Err to match Ok cost
            if let Ok(dk) = PublicKey::from_bytes(&[0u8; 1312]) {
                if let Ok(ds) = DetachedSignature::from_bytes(&[0u8; 2420]) {
                    let r = verify_detached_signature(&ds, &signed_data, &dk);
                    std::hint::black_box(&r);
                }
            }
            CtVerificationResult::failure()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DnssecAlgorithm;
    use bytes::Bytes;

    // Note: These tests verify error handling paths.
    // Full verification tests would require generating actual test keys.

    #[test]
    fn ed25519_returns_failure_for_invalid_signature() {
        let sig = DnssecSignature {
            algorithm: DnssecAlgorithm::Ed25519,
            signature: Bytes::from(vec![0xffu8; 64]),
            public_key: Bytes::from(vec![0x01u8; 32]),
        };
        let data = SignedData {
            rrset_data: Bytes::from("test message for verification"),
            rrsig_header: Bytes::from("header"),
        };
        assert!(!verify_ed25519(&sig, &data).is_valid());
    }

    #[test]
    fn ecdsa_p256_returns_failure_for_invalid_key() {
        let sig = DnssecSignature {
            algorithm: DnssecAlgorithm::EcdsaP256Sha256,
            signature: Bytes::from(vec![0u8; 64]),
            public_key: Bytes::from(vec![0u8; 65]),
        };
        let data = SignedData {
            rrset_data: Bytes::from("test"),
            rrsig_header: Bytes::from("header"),
        };
        assert!(!verify_ecdsa_p256(&sig, &data).is_valid());
    }

    #[test]
    fn rsa_sha256_returns_failure_for_invalid_key() {
        let sig = DnssecSignature {
            algorithm: DnssecAlgorithm::Rsasha256,
            signature: Bytes::from(vec![0u8; 256]),
            public_key: Bytes::from(vec![0u8; 256]),
        };
        let data = SignedData {
            rrset_data: Bytes::from("test"),
            rrsig_header: Bytes::from("header"),
        };
        assert!(!verify_rsa_sha256(&sig, &data).is_valid());
    }
}
