//! BLS12-381 signature operations
//!
//! This module provides BLS signature verification and signing functionality
//! compatible with the RISNode gateway signing scheme.

use alloc::vec::Vec;
use alloy_primitives::B256;
use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;

use crate::error::BlsError;
use crate::BLS_DST;

/// BLS secret key wrapper
#[derive(Clone)]
pub struct BlsSecretKey(SecretKey);

impl core::fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlsSecretKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl BlsSecretKey {
    /// Create a secret key from 32 bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != 32 {
            return Err(BlsError::InvalidSecretKeyLength(bytes.len()));
        }

        let sk = SecretKey::from_bytes(bytes)
            .map_err(|_| BlsError::SecretKeyCreationFailed)?;

        Ok(Self(sk))
    }

    /// Get the public key for this secret key
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig = self.0.sign(message, BLS_DST, &[]);
        sig.compress().to_vec()
    }
}

/// BLS public key wrapper
#[derive(Clone)]
pub struct BlsPublicKey(PublicKey);

impl core::fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let bytes = self.0.compress();
        f.debug_struct("BlsPublicKey")
            .field("compressed_len", &bytes.len())
            .finish_non_exhaustive()
    }
}

impl BlsPublicKey {
    /// Create a public key from 48 bytes (compressed G1 point)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != 48 {
            return Err(BlsError::InvalidPubkeyLength(bytes.len()));
        }

        let pk = PublicKey::from_bytes(bytes)
            .map_err(|_| BlsError::PubkeyDecompressFailed)?;

        Ok(Self(pk))
    }

    /// Serialize the public key to 48 bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.compress().to_vec()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, BlsError> {
        if signature.len() != 96 {
            return Err(BlsError::InvalidSignatureLength(signature.len()));
        }

        let sig = Signature::from_bytes(signature)
            .map_err(|_| BlsError::SignatureDecompressFailed)?;

        let result = sig.verify(true, message, BLS_DST, &[], &self.0, true);

        Ok(result == BLST_ERROR::BLST_SUCCESS)
    }
}

/// Verify a BLS signature
///
/// # Arguments
/// * `message` - The 32-byte hash that was signed
/// * `signature_bytes` - The 96-byte compressed G2 signature
/// * `pubkey_bytes` - The 48-byte compressed G1 public key
///
/// # Returns
/// `Ok(true)` if verification succeeds, `Ok(false)` if signature is invalid,
/// `Err` if there's a format error
pub fn verify_bls_signature(
    message: &B256,
    signature_bytes: &[u8],
    pubkey_bytes: &[u8],
) -> Result<bool, BlsError> {
    let pubkey = BlsPublicKey::from_bytes(pubkey_bytes)?;
    pubkey.verify(message.as_slice(), signature_bytes)
}

/// Sign a message with a BLS secret key
///
/// # Arguments
/// * `message` - The message bytes to sign
/// * `secret_key_bytes` - The 32-byte secret key
///
/// # Returns
/// The 96-byte compressed G2 signature
pub fn sign_bls_message(
    message: &[u8],
    secret_key_bytes: &[u8],
) -> Result<Vec<u8>, BlsError> {
    let sk = BlsSecretKey::from_bytes(secret_key_bytes)?;
    Ok(sk.sign(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        // Create a test secret key
        let sk_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];

        let sk = BlsSecretKey::from_bytes(&sk_bytes).unwrap();
        let pk = sk.public_key();

        // Sign a message
        let message = B256::repeat_byte(0x42);
        let signature = sk.sign(message.as_slice());

        // Verify
        assert_eq!(signature.len(), 96);
        let is_valid = pk.verify(message.as_slice(), &signature).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let wrong_message = B256::repeat_byte(0x43);
        let is_valid = pk.verify(wrong_message.as_slice(), &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_invalid_lengths() {
        // Invalid secret key length
        let result = BlsSecretKey::from_bytes(&[0u8; 31]);
        assert!(matches!(result, Err(BlsError::InvalidSecretKeyLength(31))));

        // Invalid public key length
        let result = BlsPublicKey::from_bytes(&[0u8; 47]);
        assert!(matches!(result, Err(BlsError::InvalidPubkeyLength(47))));
    }
}
