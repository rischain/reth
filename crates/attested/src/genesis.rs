//! Genesis configuration support for attested transactions
//!
//! This module provides helpers to extract gateway configuration from genesis files.
//! Gateway public keys and other attestation settings are stored in the genesis
//! `config.extra_fields` section.
//!
//! # Genesis JSON Format
//!
//! Add the following to your genesis.json config section:
//!
//! ```json
//! {
//!   "config": {
//!     "chainId": 1337,
//!     "gateway": {
//!       "publicKey": "0x...",
//!       "requireAttested": true,
//!       "attestedBlock": 0,
//!       "registryAddress": "0x..."
//!     }
//!   }
//! }
//! ```

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloy_primitives::Address;

use crate::verifier::GatewayConfig;

/// Gateway configuration as stored in genesis JSON
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GenesisGatewayConfig {
    /// Hex-encoded BLS public key (48 bytes, 96 hex chars)
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub public_key: Option<String>,

    /// Registry contract address for dynamic key management
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub registry_address: Option<Address>,

    /// Whether attested transactions are required
    #[cfg_attr(feature = "serde", serde(default))]
    pub require_attested: bool,

    /// Block number when attested transactions activate
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub attested_block: Option<u64>,
}

impl GenesisGatewayConfig {
    /// Extract gateway config from genesis extra_fields
    ///
    /// This looks for a "gateway" key in the extra_fields map and parses it
    /// as a `GenesisGatewayConfig`.
    #[cfg(feature = "serde")]
    pub fn extract_from(
        extra_fields: &alloc::collections::BTreeMap<String, serde_json::Value>,
    ) -> Option<Self> {
        let gateway_value = extra_fields.get("gateway")?;
        serde_json::from_value(gateway_value.clone()).ok()
    }

    /// Convert to runtime GatewayConfig
    pub fn into_gateway_config(self) -> Result<GatewayConfig, GenesisConfigError> {
        let static_pubkey = if let Some(ref hex_str) = self.public_key {
            Some(parse_hex_pubkey(hex_str)?)
        } else {
            None
        };

        Ok(GatewayConfig {
            static_pubkey,
            registry_address: self.registry_address,
            require_attested: self.require_attested,
            attested_block: self.attested_block,
        })
    }
}

/// Errors when parsing gateway genesis configuration
#[derive(Debug, Clone)]
pub enum GenesisConfigError {
    /// Invalid hex string for public key
    InvalidHexPubkey(String),
    /// Public key has wrong length
    InvalidPubkeyLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length in bytes
        got: usize,
    },
}

impl core::fmt::Display for GenesisConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidHexPubkey(msg) => write!(f, "Invalid hex public key: {}", msg),
            Self::InvalidPubkeyLength { expected, got } => {
                write!(f, "Invalid public key length: expected {} bytes, got {}", expected, got)
            }
        }
    }
}

impl core::error::Error for GenesisConfigError {}

/// Parse a hex-encoded public key string
///
/// Accepts:
/// - "0x" prefixed hex strings
/// - Bare hex strings
///
/// The resulting bytes must be exactly 48 bytes (BLS compressed G1 point).
fn parse_hex_pubkey(hex_str: &str) -> Result<Vec<u8>, GenesisConfigError> {
    let hex_str = hex_str.trim();
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    let bytes = hex::decode(hex_str)
        .map_err(|e| GenesisConfigError::InvalidHexPubkey(e.to_string()))?;

    if bytes.len() != 48 {
        return Err(GenesisConfigError::InvalidPubkeyLength {
            expected: 48,
            got: bytes.len(),
        });
    }

    Ok(bytes)
}

/// Helper to create GatewayConfig directly from genesis extra_fields
///
/// # Example
///
/// ```ignore
/// use reth_attested::genesis::gateway_config_from_extra_fields;
///
/// let genesis: Genesis = load_genesis();
/// let gateway_config = gateway_config_from_extra_fields(&genesis.config.extra_fields)?;
/// ```
#[cfg(feature = "serde")]
pub fn gateway_config_from_extra_fields(
    extra_fields: &alloc::collections::BTreeMap<String, serde_json::Value>,
) -> Result<Option<GatewayConfig>, GenesisConfigError> {
    match GenesisGatewayConfig::extract_from(extra_fields) {
        Some(genesis_config) => Ok(Some(genesis_config.into_gateway_config()?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_pubkey() {
        // Valid 48-byte key with 0x prefix
        let hex = "0x".to_string() + &"ab".repeat(48);
        let result = parse_hex_pubkey(&hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 48);

        // Valid 48-byte key without prefix
        let hex = "cd".repeat(48);
        let result = parse_hex_pubkey(&hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 48);

        // Wrong length
        let hex = "ab".repeat(32);
        let result = parse_hex_pubkey(&hex);
        assert!(matches!(result, Err(GenesisConfigError::InvalidPubkeyLength { .. })));

        // Invalid hex
        let hex = "not_hex";
        let result = parse_hex_pubkey(hex);
        assert!(matches!(result, Err(GenesisConfigError::InvalidHexPubkey(_))));
    }

    #[test]
    fn test_genesis_config_conversion() {
        let genesis_config = GenesisGatewayConfig {
            public_key: Some("0x".to_string() + &"ab".repeat(48)),
            registry_address: None,
            require_attested: true,
            attested_block: Some(1000),
        };

        let gateway_config = genesis_config.into_gateway_config().unwrap();
        assert!(gateway_config.static_pubkey.is_some());
        assert_eq!(gateway_config.static_pubkey.unwrap().len(), 48);
        assert!(gateway_config.require_attested);
        assert_eq!(gateway_config.attested_block, Some(1000));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_extract_from_extra_fields() {
        use alloc::collections::BTreeMap;

        let mut extra_fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();

        let gateway_json = serde_json::json!({
            "publicKey": format!("0x{}", "ab".repeat(48)),
            "requireAttested": true,
            "attestedBlock": 500
        });

        extra_fields.insert("gateway".to_string(), gateway_json);

        let genesis_config = GenesisGatewayConfig::extract_from(&extra_fields);
        assert!(genesis_config.is_some());

        let config = genesis_config.unwrap();
        assert!(config.public_key.is_some());
        assert!(config.require_attested);
        assert_eq!(config.attested_block, Some(500));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_extract_missing_gateway() {
        use alloc::collections::BTreeMap;

        let extra_fields: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let genesis_config = GenesisGatewayConfig::extract_from(&extra_fields);
        assert!(genesis_config.is_none());
    }
}
