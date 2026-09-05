//! High-level DNSSEC verification interface.
//!
//! Provides a unified interface for verifying DNSSEC signatures
//! across all supported algorithms with constant-time guarantees.

use crate::algorithms;
use crate::{CtVerificationResult, DnssecSignature, SignedData};

/// Verification result that can be used in constant-time operations.
pub type VerificationResult = CtVerificationResult;

/// Verify a DNSSEC signature using the appropriate algorithm.
///
/// This function dispatches to the algorithm-specific verification
/// function. The dispatch itself is NOT constant-time (it branches
/// on the algorithm number), but this is acceptable because:
/// 1. The algorithm number is public information
/// 2. Each algorithm-specific verification IS constant-time
///
/// # Example
///
/// ```
/// use constant_time_dnssec::{verify_signature, DnssecSignature, SignedData, DnssecAlgorithm};
/// use bytes::Bytes;
///
/// let sig = DnssecSignature {
///     algorithm: DnssecAlgorithm::Ed25519,
///     signature: Bytes::from(vec![0xffu8; 64]),  // Invalid signature
///     public_key: Bytes::from(vec![0x01u8; 32]),
/// };
/// let data = SignedData {
///     rrset_data: Bytes::from("test data"),
///     rrsig_header: Bytes::from("header"),
/// };
///
/// let result = verify_signature(&sig, &data);
/// assert!(!result.is_valid());
/// ```
pub fn verify_signature(sig: &DnssecSignature, data: &SignedData) -> VerificationResult {
    match sig.algorithm {
        crate::DnssecAlgorithm::Ed25519 => algorithms::verify_ed25519(sig, data),
        crate::DnssecAlgorithm::EcdsaP256Sha256 => algorithms::verify_ecdsa_p256(sig, data),
        crate::DnssecAlgorithm::Rsasha256 => algorithms::verify_rsa_sha256(sig, data),
        crate::DnssecAlgorithm::Rsasha512 => algorithms::verify_rsa_sha512(sig, data),
        // Unsupported algorithms return failure.
        _ => CtVerificationResult::failure(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DnssecAlgorithm;
    use bytes::Bytes;

    fn make_test_sig(algorithm: DnssecAlgorithm) -> DnssecSignature {
        let (sig_len, key_len) = match algorithm {
            DnssecAlgorithm::Ed25519 => (64, 32),
            DnssecAlgorithm::EcdsaP256Sha256 => (64, 65),
            DnssecAlgorithm::Rsasha256 | DnssecAlgorithm::Rsasha512 => (256, 256),
            _ => (64, 64),
        };

        DnssecSignature {
            algorithm,
            signature: Bytes::from(vec![0u8; sig_len]),
            public_key: Bytes::from(vec![0u8; key_len]),
        }
    }

    fn make_test_data() -> SignedData {
        SignedData {
            rrset_data: Bytes::from("test rrset data"),
            rrsig_header: Bytes::from("test rrsig header"),
        }
    }

    #[test]
    fn verify_signature_returns_failure_for_unsupported_algorithm() {
        let sig = make_test_sig(DnssecAlgorithm::Rsasha1);
        let data = make_test_data();
        assert!(!verify_signature(&sig, &data).is_valid());
    }
}
