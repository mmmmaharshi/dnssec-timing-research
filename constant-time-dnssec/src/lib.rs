//! Constant-time DNSSEC signature verification primitives.
//!
//! This library provides constant-time verification of DNSSEC signatures
//! to prevent timing side-channels that could leak information about
//! signature validity.
//!
//! # Design Principles
//!
//! 1. No early returns based on signature validity
//! 2. Constant-time comparison for all signature checks
//! 3. Uniform execution path regardless of validation outcome
//! 4. No secret-dependent branches or memory accesses

#![warn(missing_docs)]

use bytes::Bytes;
use subtle::ConstantTimeEq;

pub mod algorithms;
pub mod verify;

pub use verify::{VerificationResult, verify_signature};

/// DNSSEC algorithm numbers as defined in RFC 4034.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnssecAlgorithm {
    /// RSA/SHA-1 (deprecated, included for completeness).
    Rsasha1 = 5,
    /// RSA/SHA-256.
    Rsasha256 = 8,
    /// RSA/SHA-512.
    Rsasha512 = 10,
    /// ECDSA Curve P-256 with SHA-256.
    EcdsaP256Sha256 = 13,
    /// ECDSA Curve P-384 with SHA-384.
    EcdsaP384Sha384 = 14,
    /// Ed25519.
    Ed25519 = 15,
    /// Ed448.
    Ed448 = 16,
    /// Dilithium2 (PQC, not IANA, for Q1 scale demo).
    Dilithium2 = 17,
}

impl DnssecAlgorithm {
    /// Convert from a DNSSEC algorithm number.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            5 => Some(Self::Rsasha1),
            8 => Some(Self::Rsasha256),
            10 => Some(Self::Rsasha512),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            17 => Some(Self::Dilithium2),
            _ => None,
        }
    }

    /// Returns `true` if this algorithm is supported for constant-time verification.
    #[must_use]
    pub fn is_ct_supported(self) -> bool {
        matches!(
            self,
            Self::Rsasha256
                | Self::Rsasha512
                | Self::EcdsaP256Sha256
                | Self::Ed25519
                | Self::Dilithium2
        )
    }
}

/// A DNSSEC signature with its associated algorithm and public key.
#[derive(Debug, Clone)]
pub struct DnssecSignature {
    /// Algorithm used for signing.
    pub algorithm: DnssecAlgorithm,
    /// The raw signature bytes.
    pub signature: Bytes,
    /// The signer's DNSKEY (public key portion).
    pub public_key: Bytes,
}

/// The data to be verified (`RRset` + RRSIG header).
#[derive(Debug, Clone)]
pub struct SignedData {
    /// The canonical form of the `RRset` being verified.
    pub rrset_data: Bytes,
    /// The RRSIG rdata (excluding the signature itself).
    pub rrsig_header: Bytes,
}

/// Result of a constant-time verification operation.
///
/// This type uses constant-time operations to prevent leaking
/// information about the verification result through timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtVerificationResult {
    /// 1 if verification succeeded, 0 if it failed.
    ///
    /// Stored as `u8` to enable constant-time operations.
    value: u8,
}

impl CtVerificationResult {
    /// Create a successful result.
    #[must_use]
    pub const fn success() -> Self {
        Self { value: 1 }
    }

    /// Create a failed result.
    #[must_use]
    pub const fn failure() -> Self {
        Self { value: 0 }
    }

    /// Returns `true` if verification succeeded.
    ///
    /// Note: This method itself is NOT constant-time by design,
    /// as it's meant to be called after all timing-sensitive
    /// operations are complete.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.value == 1
    }

    /// Constant-time OR: returns success if either `self` or `other` is success.
    #[must_use]
    pub fn ct_or(self, other: Self) -> Self {
        Self {
            value: self.value | other.value,
        }
    }

    /// Constant-time AND: returns success only if both `self` and `other` are success.
    #[must_use]
    pub fn ct_and(self, other: Self) -> Self {
        Self {
            value: self.value & other.value,
        }
    }
}

impl ConstantTimeEq for CtVerificationResult {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value)
    }
}

/// Constant-time comparison of two byte slices.
///
/// Returns [`CtVerificationResult::success()`] if equal, [`CtVerificationResult::failure()`] otherwise.
/// Execution time is independent of the content of the slices.
#[must_use]
pub fn ct_slice_compare(a: &[u8], b: &[u8]) -> CtVerificationResult {
    if a.len() != b.len() {
        // DNSSEC signatures have fixed lengths per algorithm,
        // so length mismatch always means failure.
        return CtVerificationResult::failure();
    }

    let result = a.ct_eq(b);
    CtVerificationResult {
        value: result.unwrap_u8(),
    }
}

/// Prepare the signed data for DNSSEC verification.
///
/// This follows RFC 4034 Section 5.3.2:
/// `signed_data = RRSIG_RDATA | RR(i) * (i=1..n)`
/// where `RRSIG_RDATA` excludes the signature field.
#[must_use]
pub fn prepare_signed_data(rrsig_header: &[u8], rrset: &[&[u8]]) -> Vec<u8> {
    let rrset_len: usize = rrset.iter().map(|r| r.len()).sum();
    let total_len: usize = rrsig_header.len() + rrset_len;
    let mut data = Vec::with_capacity(total_len);

    data.extend_from_slice(rrsig_header);
    for rr in rrset {
        data.extend_from_slice(rr);
    }

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_slice_compare_returns_success_when_slices_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(ct_slice_compare(&a, &b).is_valid());
    }

    #[test]
    fn ct_slice_compare_returns_failure_when_slices_differ() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!ct_slice_compare(&a, &b).is_valid());
    }

    #[test]
    fn ct_slice_compare_returns_failure_when_lengths_differ() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3];
        assert!(!ct_slice_compare(&a, &b).is_valid());
    }

    #[test]
    fn ct_or_returns_success_when_either_is_success() {
        let s = CtVerificationResult::success();
        let f = CtVerificationResult::failure();

        assert!(s.ct_or(s).is_valid());
        assert!(s.ct_or(f).is_valid());
        assert!(f.ct_or(s).is_valid());
        assert!(!f.ct_or(f).is_valid());
    }

    #[test]
    fn ct_and_returns_success_when_both_are_success() {
        let s = CtVerificationResult::success();
        let f = CtVerificationResult::failure();

        assert!(s.ct_and(s).is_valid());
        assert!(!s.ct_and(f).is_valid());
        assert!(!f.ct_and(s).is_valid());
        assert!(!f.ct_and(f).is_valid());
    }

    #[test]
    fn prepare_signed_data_concatenates_header_and_records() {
        let header = b"header";
        let rr1 = b"rr1";
        let rr2 = b"rr2";

        let result = prepare_signed_data(header, &[rr1, rr2]);
        assert_eq!(result, b"headerrr1rr2");
    }

    #[test]
    fn from_u8_returns_correct_algorithm() {
        assert_eq!(
            DnssecAlgorithm::from_u8(8),
            Some(DnssecAlgorithm::Rsasha256)
        );
        assert_eq!(
            DnssecAlgorithm::from_u8(13),
            Some(DnssecAlgorithm::EcdsaP256Sha256)
        );
        assert_eq!(DnssecAlgorithm::from_u8(15), Some(DnssecAlgorithm::Ed25519));
        assert_eq!(DnssecAlgorithm::from_u8(99), None);
    }
}
