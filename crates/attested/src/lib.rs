//! Attested Transaction Types and Primitives for Reth
//!
//! This crate provides support for Attested Transaction (Type 0x64)
//! which wraps standard Ethereum transactions with a BLS12-381 gateway signature.
//!
//! # Overview
//!
//! The gateway signing mechanism requires transactions to be attested by a
//! trusted gateway before being accepted into the network. This provides an
//! additional layer of transaction validation beyond standard Ethereum consensus.
//!
//! # Transaction Type
//!
//! The Attested Transaction uses type ID `0x64` (100) to avoid conflicts with
//! existing Ethereum EIPs:
//! - `0x00` - Legacy transaction
//! - `0x01` - EIP-2930 (access list)
//! - `0x02` - EIP-1559 (dynamic fee)
//! - `0x03` - EIP-4844 (blob)
//! - `0x04` - EIP-7702 (account abstraction)
//! - `0x64` - Attested transaction (this crate)
//!
//! # Transaction Structure
//!
//! An attested transaction contains:
//! - All standard EIP-1559 fields (chain_id, nonce, gas, fees, to, value, data, access_list)
//! - `gateway_version` - Version of the gateway public key used
//! - `gateway_expiry` - Block number when the attestation expires (0 = no expiry)
//! - `gateway_signature` - 96-byte BLS12-381 signature over the transaction
//! - `original_tx_type` - The original transaction type that was wrapped
//!
//! # Example - Verifying a Transaction
//!
//! ```ignore
//! use reth_attested::{TxAttested, GatewayVerifier, GatewayConfig};
//!
//! // Create a gateway verifier with a static public key
//! let config = GatewayConfig {
//!     static_pubkey: Some(gateway_pubkey),
//!     ..Default::default()
//! };
//! let verifier = GatewayVerifier::new(config);
//!
//! // Verify an attested transaction
//! verifier.verify(&attested_tx, current_block_number)?;
//! ```
//!
//! # Example - Transaction Pool Integration
//!
//! To integrate attested transaction validation into a Reth transaction pool,
//! use the `AttestedValidationContext`:
//!
//! ```ignore
//! use std::sync::Arc;
//! use reth_attested::{
//!     AttestedValidationContext, GatewayVerifier, GatewayVerifierBuilder,
//!     ATTESTED_TX_TYPE,
//! };
//!
//! // 1. Create the gateway verifier with your configuration
//! let verifier = Arc::new(
//!     GatewayVerifierBuilder::new()
//!         .with_static_pubkey(gateway_pubkey_bytes)
//!         .require_attested(true)  // Require all txs to be attested
//!         .with_attested_block(1000)  // Active from block 1000
//!         .build()
//! );
//!
//! // 2. Create validation context for current block
//! let ctx = AttestedValidationContext::new(verifier, current_block);
//!
//! // 3. During transaction validation, check transaction type
//! let tx_type = transaction.ty();
//!
//! if tx_type == ATTESTED_TX_TYPE {
//!     // Validate gateway signature for attested transactions
//!     if let Some(attested_tx) = extract_attested_tx(&transaction) {
//!         ctx.validate_attested_tx(&attested_tx)?;
//!     }
//! } else {
//!     // Check if non-attested transactions are allowed
//!     ctx.check_non_attested_allowed(tx_type)?;
//! }
//! ```
//!
//! # Example - Using EthTransactionValidatorBuilder
//!
//! To enable Type 0x64 in the standard Reth transaction validator:
//!
//! ```ignore
//! use reth_transaction_pool::EthTransactionValidatorBuilder;
//! use reth_attested::ATTESTED_TX_TYPE;
//!
//! let validator = EthTransactionValidatorBuilder::new(client)
//!     .with_custom_tx_type(ATTESTED_TX_TYPE)  // Enable Type 0x64
//!     .build(blob_store);
//! ```
//!
//! # Configuration
//!
//! Gateway configuration can be specified via `GatewayConfig`:
//!
//! - `static_pubkey` - 48-byte compressed BLS public key from genesis
//! - `registry_address` - Contract address for dynamic key rotation (future)
//! - `require_attested` - Whether to reject non-attested transactions
//! - `attested_block` - Block number when attested mode activates

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod tx_attested;
mod signature;
mod verifier;
mod error;
mod transaction;
mod pool;
pub mod genesis;

pub use tx_attested::{TxAttested, ATTESTED_TX_TYPE, OriginalTxType};
pub use signature::{verify_bls_signature, sign_bls_message, BlsSecretKey, BlsPublicKey};
pub use verifier::{GatewayVerifier, GatewayConfig, GatewayKey, GatewayVerifierBuilder};
pub use error::{AttestedError, BlsError, GatewayError};
pub use transaction::{AttestedTransaction, AttestedTransactionSigned};
pub use pool::{
    AttestedValidationContext, AttestedValidationBuilder, AttestedValidationError,
};
pub use genesis::{GenesisGatewayConfig, GenesisConfigError};
#[cfg(feature = "serde")]
pub use genesis::gateway_config_from_extra_fields;

/// Domain separation tag for gateway attestation
pub const DOMAIN_TAG: &[u8] = b"RISNode Gateway Attestation v1";

/// BLS DST (Domain Separation Tag) for signing
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
