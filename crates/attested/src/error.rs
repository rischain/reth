//! Error types for attested transactions

use alloc::string::String;
use thiserror::Error;

/// Errors related to attested transactions
#[derive(Debug, Error)]
pub enum AttestedError {
    /// Invalid transaction type
    #[error("Invalid transaction type: expected 0x64, got {0:#x}")]
    InvalidTxType(u8),

    /// RLP decoding error
    #[error("RLP decode error: {0}")]
    RlpDecode(String),

    /// Invalid original transaction type
    #[error("Invalid original transaction type: {0:#x}")]
    InvalidOriginalTxType(u8),

    /// Gateway verification error
    #[error("Gateway verification failed: {0}")]
    GatewayError(#[from] GatewayError),

    /// BLS error
    #[error("BLS error: {0}")]
    BlsError(#[from] BlsError),
}

/// BLS signature errors
#[derive(Debug, Error)]
pub enum BlsError {
    /// Invalid signature length
    #[error("Invalid BLS signature length: {0}, expected 96 bytes")]
    InvalidSignatureLength(usize),

    /// Invalid public key length
    #[error("Invalid BLS public key length: {0}, expected 48 bytes")]
    InvalidPubkeyLength(usize),

    /// Invalid secret key length
    #[error("Invalid BLS secret key length: {0}, expected 32 bytes")]
    InvalidSecretKeyLength(usize),

    /// Failed to decompress signature
    #[error("Failed to decompress BLS signature")]
    SignatureDecompressFailed,

    /// Failed to decompress public key
    #[error("Failed to decompress BLS public key")]
    PubkeyDecompressFailed,

    /// Failed to create secret key
    #[error("Failed to create BLS secret key")]
    SecretKeyCreationFailed,

    /// Signature verification failed
    #[error("BLS signature verification failed")]
    VerificationFailed,
}

/// Gateway verification errors
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Gateway signature is missing
    #[error("Gateway signature is missing")]
    MissingSignature,

    /// Invalid gateway signature length
    #[error("Invalid gateway signature length: {0}, expected 96 bytes")]
    InvalidSignatureLength(usize),

    /// Gateway signature has expired
    #[error("Gateway signature expired at block {expiry}, current block {current}")]
    SignatureExpired {
        /// Block number when the signature expires
        expiry: u64,
        /// Current block number
        current: u64,
    },

    /// Gateway public key not found
    #[error("Gateway public key not found for version {0}")]
    PubkeyNotFound(u64),

    /// Invalid gateway signature
    #[error("Invalid gateway signature")]
    InvalidSignature,

    /// BLS error
    #[error("BLS error: {0}")]
    BlsError(#[from] BlsError),
}
