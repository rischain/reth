//! Transaction pool integration for attested transactions
//!
//! This module provides a transaction validator wrapper that adds gateway signature
//! verification for Type 0x64 attested transactions.

use alloc::string::String;

use crate::error::GatewayError;
use crate::tx_attested::ATTESTED_TX_TYPE;
use crate::verifier::GatewayVerifier;

#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

/// Validation errors specific to attested transactions
#[derive(Debug, Clone)]
pub enum AttestedValidationError {
    /// Gateway signature verification failed
    GatewayVerificationFailed(String),
    /// Attested transaction required but not provided
    AttestedRequired,
    /// Gateway signature expired
    SignatureExpired {
        /// Block number when the signature expires
        expiry: u64,
        /// Current block number
        current: u64,
    },
    /// Missing gateway signature
    MissingSignature,
    /// Invalid signature length
    InvalidSignatureLength(usize),
    /// Public key not found for version
    PubkeyNotFound(u64),
}

impl core::fmt::Display for AttestedValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GatewayVerificationFailed(msg) => {
                write!(f, "Gateway verification failed: {}", msg)
            }
            Self::AttestedRequired => {
                write!(f, "Attested transaction (Type 0x64) is required")
            }
            Self::SignatureExpired { expiry, current } => {
                write!(
                    f,
                    "Gateway signature expired at block {}, current block {}",
                    expiry, current
                )
            }
            Self::MissingSignature => {
                write!(f, "Gateway signature is missing")
            }
            Self::InvalidSignatureLength(len) => {
                write!(
                    f,
                    "Invalid gateway signature length: {}, expected 96 bytes",
                    len
                )
            }
            Self::PubkeyNotFound(version) => {
                write!(f, "Gateway public key not found for version {}", version)
            }
        }
    }
}

impl core::error::Error for AttestedValidationError {}

impl From<GatewayError> for AttestedValidationError {
    fn from(err: GatewayError) -> Self {
        match err {
            GatewayError::MissingSignature => Self::MissingSignature,
            GatewayError::InvalidSignatureLength(len) => Self::InvalidSignatureLength(len),
            GatewayError::SignatureExpired { expiry, current } => {
                Self::SignatureExpired { expiry, current }
            }
            GatewayError::PubkeyNotFound(version) => Self::PubkeyNotFound(version),
            GatewayError::InvalidSignature => {
                Self::GatewayVerificationFailed("Invalid BLS signature".into())
            }
            GatewayError::BlsError(e) => {
                Self::GatewayVerificationFailed(alloc::format!("BLS error: {}", e))
            }
        }
    }
}

/// Context for attested transaction validation
///
/// This struct holds the verifier and provides validation methods that can be
/// called during transaction pool validation.
#[derive(Debug)]
pub struct AttestedValidationContext {
    /// Gateway signature verifier
    verifier: Arc<GatewayVerifier>,
    /// Current block number (for expiry checking)
    current_block: u64,
}

impl AttestedValidationContext {
    /// Create a new validation context
    pub fn new(verifier: Arc<GatewayVerifier>, current_block: u64) -> Self {
        Self {
            verifier,
            current_block,
        }
    }

    /// Update the current block number
    pub fn set_current_block(&mut self, block: u64) {
        self.current_block = block;
    }

    /// Get the current block number
    pub fn current_block(&self) -> u64 {
        self.current_block
    }

    /// Get the verifier
    pub fn verifier(&self) -> &GatewayVerifier {
        &self.verifier
    }

    /// Check if a transaction type is an attested transaction
    pub fn is_attested_tx_type(tx_type: u8) -> bool {
        tx_type == ATTESTED_TX_TYPE
    }

    /// Check if attested transactions are required at the current block
    pub fn is_attested_required(&self) -> bool {
        let config = self.verifier.config();
        config.require_attested && config.is_active(self.current_block)
    }

    /// Validate an attested transaction's gateway signature
    ///
    /// This should be called during transaction pool validation for Type 0x64 transactions.
    pub fn validate_attested_tx(
        &self,
        tx: &crate::tx_attested::TxAttested,
    ) -> Result<(), AttestedValidationError> {
        self.verifier
            .verify(tx, self.current_block)
            .map_err(AttestedValidationError::from)
    }

    /// Check if non-attested transaction should be rejected
    ///
    /// Returns an error if attested transactions are required but a non-attested
    /// transaction was received.
    pub fn check_non_attested_allowed(&self, tx_type: u8) -> Result<(), AttestedValidationError> {
        if self.is_attested_required() && tx_type != ATTESTED_TX_TYPE {
            return Err(AttestedValidationError::AttestedRequired);
        }
        Ok(())
    }
}

/// Builder for creating an attested transaction validation setup
#[derive(Debug, Default)]
pub struct AttestedValidationBuilder {
    verifier: Option<Arc<GatewayVerifier>>,
    current_block: u64,
}

impl AttestedValidationBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the gateway verifier
    pub fn with_verifier(mut self, verifier: Arc<GatewayVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Set the initial block number
    pub fn with_block(mut self, block: u64) -> Self {
        self.current_block = block;
        self
    }

    /// Build the validation context
    ///
    /// Returns None if no verifier was configured
    pub fn build(self) -> Option<AttestedValidationContext> {
        self.verifier.map(|v| AttestedValidationContext {
            verifier: v,
            current_block: self.current_block,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::BlsSecretKey;
    use crate::tx_attested::TxAttested;
    use crate::verifier::GatewayVerifierBuilder;
    use alloy_primitives::{Bytes, TxKind, U256};

    fn create_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let sk = BlsSecretKey::from_bytes(&secret_bytes).unwrap();
        let pk = sk.public_key();

        (secret_bytes.to_vec(), pk.to_bytes())
    }

    fn create_signed_tx(sk_bytes: &[u8]) -> TxAttested {
        let sk = BlsSecretKey::from_bytes(sk_bytes).unwrap();

        let mut tx = TxAttested {
            chain_id: 1337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1000000000,
            max_priority_fee_per_gas: 1000000000,
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
            gateway_version: 0,
            gateway_expiry: 0,
            gateway_signature: Bytes::new(),
            original_tx_type: Default::default(),
        };

        let hash = tx.attestation_hash();
        let signature = sk.sign(hash.as_slice());
        tx.gateway_signature = Bytes::from(signature);

        tx
    }

    #[test]
    fn test_validation_context_valid_tx() {
        let (sk_bytes, pk_bytes) = create_test_keypair();

        let verifier = Arc::new(
            GatewayVerifierBuilder::new()
                .with_static_pubkey(pk_bytes)
                .build(),
        );

        let ctx = AttestedValidationContext::new(verifier, 100);
        let tx = create_signed_tx(&sk_bytes);

        assert!(ctx.validate_attested_tx(&tx).is_ok());
    }

    #[test]
    fn test_validation_context_expired_tx() {
        let (sk_bytes, pk_bytes) = create_test_keypair();

        let verifier = Arc::new(
            GatewayVerifierBuilder::new()
                .with_static_pubkey(pk_bytes)
                .build(),
        );

        let ctx = AttestedValidationContext::new(verifier, 200);

        let sk = BlsSecretKey::from_bytes(&sk_bytes).unwrap();
        let mut tx = TxAttested {
            chain_id: 1337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1000000000,
            max_priority_fee_per_gas: 1000000000,
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::new(),
            access_list: Default::default(),
            gateway_version: 0,
            gateway_expiry: 100, // Expires at block 100
            gateway_signature: Bytes::new(),
            original_tx_type: Default::default(),
        };

        let hash = tx.attestation_hash();
        tx.gateway_signature = Bytes::from(sk.sign(hash.as_slice()));

        let result = ctx.validate_attested_tx(&tx);
        assert!(matches!(
            result,
            Err(AttestedValidationError::SignatureExpired { .. })
        ));
    }

    #[test]
    fn test_attested_required() {
        let (_, pk_bytes) = create_test_keypair();

        let verifier = Arc::new(
            GatewayVerifierBuilder::new()
                .with_static_pubkey(pk_bytes)
                .require_attested(true)
                .with_attested_block(50)
                .build(),
        );

        // Before activation block - non-attested allowed
        let ctx = AttestedValidationContext::new(Arc::clone(&verifier), 40);
        assert!(ctx.check_non_attested_allowed(0x02).is_ok());

        // After activation block - non-attested rejected
        let ctx = AttestedValidationContext::new(verifier, 100);
        assert!(matches!(
            ctx.check_non_attested_allowed(0x02),
            Err(AttestedValidationError::AttestedRequired)
        ));

        // Attested tx always allowed
        assert!(ctx.check_non_attested_allowed(ATTESTED_TX_TYPE).is_ok());
    }

    #[test]
    fn test_is_attested_tx_type() {
        assert!(AttestedValidationContext::is_attested_tx_type(ATTESTED_TX_TYPE));
        assert!(!AttestedValidationContext::is_attested_tx_type(0x00));
        assert!(!AttestedValidationContext::is_attested_tx_type(0x02));
    }

    #[test]
    fn test_builder() {
        let (_, pk_bytes) = create_test_keypair();

        let verifier = Arc::new(
            GatewayVerifierBuilder::new()
                .with_static_pubkey(pk_bytes)
                .build(),
        );

        let ctx = AttestedValidationBuilder::new()
            .with_verifier(verifier)
            .with_block(100)
            .build();

        assert!(ctx.is_some());
        let ctx = ctx.unwrap();
        assert_eq!(ctx.current_block(), 100);
    }

    #[test]
    fn test_builder_no_verifier() {
        let ctx = AttestedValidationBuilder::new().with_block(100).build();

        assert!(ctx.is_none());
    }
}
