//! Gateway signature verifier
//!
//! This module provides the gateway signature verification logic that should be
//! integrated into Reth's transaction pool and block processing.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

// For now, only support std as spin is optional
#[cfg(feature = "std")]
use std::sync::RwLock;
#[cfg(all(not(feature = "std"), feature = "spin"))]
use spin::RwLock;

use alloy_primitives::Address;

use crate::error::GatewayError;
use crate::signature::verify_bls_signature;
use crate::tx_attested::TxAttested;

/// Gateway configuration
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GatewayConfig {
    /// Static gateway public key (48 bytes, from genesis config)
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub static_pubkey: Option<Vec<u8>>,

    /// Gateway registry contract address (for dynamic key management)
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub registry_address: Option<Address>,

    /// Require all transactions to be attested (Type 0x64)
    #[cfg_attr(feature = "serde", serde(default))]
    pub require_attested: bool,

    /// Block number when attested transactions are activated
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub attested_block: Option<u64>,
}

impl GatewayConfig {
    /// Check if attested transactions are active at the given block
    pub fn is_active(&self, block_number: u64) -> bool {
        match self.attested_block {
            Some(activation_block) => block_number >= activation_block,
            None => true, // Always active if no activation block specified
        }
    }
}

/// Cached gateway key with validity window
#[derive(Debug, Clone)]
pub struct GatewayKey {
    /// The public key bytes (48 bytes)
    pub pubkey: Vec<u8>,
    /// Block number after which this key is valid
    pub valid_after: u64,
    /// Block number before which this key is valid (0 = no limit)
    pub valid_before: u64,
}

impl GatewayKey {
    /// Check if the key is valid at the given block
    pub fn is_valid_at(&self, block_number: u64) -> bool {
        block_number >= self.valid_after
            && (self.valid_before == 0 || block_number <= self.valid_before)
    }
}

/// Gateway signature verifier
///
/// Verifies BLS signatures on attested transactions. Supports:
/// - Static public key from genesis config
/// - Dynamic key rotation via contract registry
/// - Key caching for performance
pub struct GatewayVerifier {
    config: GatewayConfig,
    /// Cached public keys by version
    key_cache: RwLock<BTreeMap<u64, GatewayKey>>,
    /// Whether the verifier is initialized
    initialized: AtomicBool,
}

impl core::fmt::Debug for GatewayVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GatewayVerifier")
            .field("config", &self.config)
            .field("initialized", &self.initialized.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl GatewayVerifier {
    /// Create a new gateway verifier with the given configuration
    pub fn new(config: GatewayConfig) -> Self {
        let mut key_cache = BTreeMap::new();
        let has_static_pubkey = config.static_pubkey.is_some();

        // Pre-populate cache with static pubkey at version 0
        if let Some(ref pubkey) = config.static_pubkey {
            key_cache.insert(
                0,
                GatewayKey {
                    pubkey: pubkey.clone(),
                    valid_after: 0,
                    valid_before: 0, // No expiry
                },
            );
        }

        Self {
            config,
            key_cache: RwLock::new(key_cache),
            initialized: AtomicBool::new(has_static_pubkey),
        }
    }

    /// Check if the verifier is properly initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed)
    }

    /// Get the configuration
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Add a public key to the cache
    pub fn add_key(&self, version: u64, key: GatewayKey) {
        let mut cache = self.key_cache.write().unwrap();
        cache.insert(version, key);
        self.initialized.store(true, Ordering::Relaxed);
    }

    /// Get a public key from the cache
    pub fn get_key(&self, version: u64) -> Option<GatewayKey> {
        let cache = self.key_cache.read().unwrap();
        cache.get(&version).cloned()
    }

    /// Verify an attested transaction's gateway signature
    ///
    /// # Arguments
    /// * `tx` - The attested transaction to verify
    /// * `block_number` - The current block number (for expiry checking)
    ///
    /// # Returns
    /// * `Ok(())` if verification succeeds
    /// * `Err(GatewayError)` if verification fails
    pub fn verify(&self, tx: &TxAttested, block_number: u64) -> Result<(), GatewayError> {
        // 1. Check if attested transactions are active
        if !self.config.is_active(block_number) {
            // Not active yet, skip verification
            return Ok(());
        }

        // 2. Check signature length
        if tx.gateway_signature.is_empty() {
            return Err(GatewayError::MissingSignature);
        }
        if tx.gateway_signature.len() != 96 {
            return Err(GatewayError::InvalidSignatureLength(tx.gateway_signature.len()));
        }

        // 3. Check expiry
        if tx.is_expired(block_number) {
            return Err(GatewayError::SignatureExpired {
                expiry: tx.gateway_expiry,
                current: block_number,
            });
        }

        // 4. Get public key for the specified version
        let gateway_key = self.get_pubkey_for_version(tx.gateway_version, block_number)?;

        // 5. Calculate attestation hash
        let message = tx.attestation_hash();

        // 6. Verify BLS signature
        let is_valid = verify_bls_signature(&message, &tx.gateway_signature, &gateway_key)?;

        if !is_valid {
            return Err(GatewayError::InvalidSignature);
        }

        Ok(())
    }

    /// Get the public key for a specific version
    fn get_pubkey_for_version(
        &self,
        version: u64,
        block_number: u64,
    ) -> Result<Vec<u8>, GatewayError> {
        // 1. Try cache first
        if let Some(key) = self.get_key(version) {
            if key.is_valid_at(block_number) {
                return Ok(key.pubkey);
            }
        }

        // 2. TODO: Query contract registry if configured
        // if let Some(registry) = &self.config.registry_address {
        //     let key = self.query_registry(registry, version)?;
        //     self.add_key(version, key.clone());
        //     return Ok(key.pubkey);
        // }

        // 3. Fall back to static pubkey for version 0
        if version == 0 {
            if let Some(ref pubkey) = self.config.static_pubkey {
                return Ok(pubkey.clone());
            }
        }

        Err(GatewayError::PubkeyNotFound(version))
    }
}

/// Builder for GatewayVerifier
#[derive(Debug, Default)]
pub struct GatewayVerifierBuilder {
    config: GatewayConfig,
}

impl GatewayVerifierBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the static public key
    pub fn with_static_pubkey(mut self, pubkey: Vec<u8>) -> Self {
        self.config.static_pubkey = Some(pubkey);
        self
    }

    /// Set the registry contract address
    pub fn with_registry(mut self, address: Address) -> Self {
        self.config.registry_address = Some(address);
        self
    }

    /// Set whether attested transactions are required
    pub fn require_attested(mut self, require: bool) -> Self {
        self.config.require_attested = require;
        self
    }

    /// Set the activation block
    pub fn with_attested_block(mut self, block: u64) -> Self {
        self.config.attested_block = Some(block);
        self
    }

    /// Build the verifier
    pub fn build(self) -> GatewayVerifier {
        GatewayVerifier::new(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::BlsSecretKey;
    use alloy_primitives::{Bytes, TxKind, U256};

    fn create_test_keypair() -> (Vec<u8>, Vec<u8>) {
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
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

        // Sign the transaction
        let hash = tx.attestation_hash();
        let signature = sk.sign(hash.as_slice());
        tx.gateway_signature = Bytes::from(signature);

        tx
    }

    #[test]
    fn test_verify_valid_signature() {
        let (sk_bytes, pk_bytes) = create_test_keypair();

        let verifier = GatewayVerifierBuilder::new()
            .with_static_pubkey(pk_bytes)
            .build();

        let tx = create_signed_tx(&sk_bytes);

        // Should succeed
        let result = verifier.verify(&tx, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let (_, pk_bytes) = create_test_keypair();

        let verifier = GatewayVerifierBuilder::new()
            .with_static_pubkey(pk_bytes)
            .build();

        // Sign with wrong key
        let other_sk = BlsSecretKey::from_bytes(&[
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ]).unwrap();

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
        let signature = other_sk.sign(hash.as_slice());
        tx.gateway_signature = Bytes::from(signature);

        // Should fail
        let result = verifier.verify(&tx, 100);
        assert!(matches!(result, Err(GatewayError::InvalidSignature)));
    }

    #[test]
    fn test_verify_expired_signature() {
        let (sk_bytes, pk_bytes) = create_test_keypair();

        let verifier = GatewayVerifierBuilder::new()
            .with_static_pubkey(pk_bytes)
            .build();

        let mut tx = create_signed_tx(&sk_bytes);
        tx.gateway_expiry = 100; // Expires at block 100

        // Re-sign with new expiry
        let hash = tx.attestation_hash();
        let sk = BlsSecretKey::from_bytes(&sk_bytes).unwrap();
        tx.gateway_signature = Bytes::from(sk.sign(hash.as_slice()));

        // Should succeed at block 50
        assert!(verifier.verify(&tx, 50).is_ok());

        // Should succeed at block 100 (boundary)
        assert!(verifier.verify(&tx, 100).is_ok());

        // Should fail at block 101
        let result = verifier.verify(&tx, 101);
        assert!(matches!(result, Err(GatewayError::SignatureExpired { .. })));
    }

    #[test]
    fn test_missing_pubkey() {
        let verifier = GatewayVerifierBuilder::new().build();

        let tx = TxAttested {
            gateway_signature: Bytes::from(vec![0u8; 96]),
            gateway_version: 999, // Non-existent version
            ..Default::default()
        };

        let result = verifier.verify(&tx, 100);
        assert!(matches!(result, Err(GatewayError::PubkeyNotFound(999))));
    }

    #[test]
    fn test_require_attested_config() {
        let config = GatewayConfig {
            require_attested: true,
            attested_block: Some(1000),
            ..Default::default()
        };

        // Not active before block 1000
        assert!(!config.is_active(999));

        // Active at and after block 1000
        assert!(config.is_active(1000));
        assert!(config.is_active(1001));
    }
}
