//! Attested Transaction (Type 0x64)
//!
//! An attested transaction wraps a standard Ethereum transaction and adds
//! a BLS12-381 gateway signature that proves the transaction has been
//! verified by a trusted gateway.

use alloc::vec::Vec;
use alloy_eips::eip2930::AccessList;
use alloy_consensus::Typed2718;
use alloy_primitives::{keccak256, Bytes, ChainId, Signature, TxKind, B256, U256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use bytes::BufMut;

use crate::DOMAIN_TAG;

/// Attested Transaction Type ID (0x64 = 100)
/// Using 0x64 to avoid conflicts with existing EIPs (0x00-0x04)
pub const ATTESTED_TX_TYPE: u8 = 0x64;

/// Original transaction types that can be wrapped
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum OriginalTxType {
    /// Legacy transaction (type 0x00)
    #[default]
    Legacy = 0x00,
    /// EIP-2930 transaction (type 0x01)
    Eip2930 = 0x01,
    /// EIP-1559 transaction (type 0x02)
    Eip1559 = 0x02,
}

impl TryFrom<u8> for OriginalTxType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Legacy),
            0x01 => Ok(Self::Eip2930),
            0x02 => Ok(Self::Eip1559),
            _ => Err(value),
        }
    }
}

impl From<OriginalTxType> for u8 {
    fn from(value: OriginalTxType) -> Self {
        value as u8
    }
}

/// Attested Transaction (Type 0x64)
///
/// This transaction type wraps a standard EIP-1559 style transaction and adds
/// gateway attestation metadata including a BLS12-381 signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TxAttested {
    // === Base EIP-1559 fields ===
    /// Chain ID
    pub chain_id: ChainId,
    /// Nonce
    pub nonce: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Max fee per gas (EIP-1559)
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas (EIP-1559)
    pub max_priority_fee_per_gas: u128,
    /// Recipient address (None for contract creation)
    pub to: TxKind,
    /// Value to transfer
    pub value: U256,
    /// Input data
    pub input: Bytes,
    /// Access list (EIP-2930)
    pub access_list: AccessList,

    // === Gateway attestation metadata ===
    /// Gateway public key version (for key rotation)
    pub gateway_version: u64,
    /// Signature expiry block number (0 = no expiry)
    pub gateway_expiry: u64,
    /// BLS12-381 signature (96 bytes, compressed G2 point)
    pub gateway_signature: Bytes,

    // === Original transaction info ===
    /// Original transaction type (0x00/0x01/0x02)
    pub original_tx_type: OriginalTxType,
}

impl TxAttested {
    /// Returns the transaction type (always 0x64 for attested transactions)
    pub const fn tx_type(&self) -> u8 {
        ATTESTED_TX_TYPE
    }

    /// Calculate the attestation hash for gateway signing
    ///
    /// The hash is computed as:
    /// `keccak256(0x64 || keccak256(RLP([chain_id, nonce, max_priority_fee, max_fee, gas, to, value, data, access_list, gateway_version, gateway_expiry, domain_tag])))`
    pub fn attestation_hash(&self) -> B256 {
        // Encode payload for hashing
        let payload = AttestationPayload {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            input: self.input.clone(),
            access_list: self.access_list.clone(),
            gateway_version: self.gateway_version,
            gateway_expiry: self.gateway_expiry,
            domain_tag: Bytes::from_static(DOMAIN_TAG),
        };

        let mut rlp_buf = Vec::new();
        payload.encode(&mut rlp_buf);
        let rlp_hash = keccak256(&rlp_buf);

        // Prefix with transaction type
        let mut prefixed = Vec::with_capacity(33);
        prefixed.push(ATTESTED_TX_TYPE);
        prefixed.extend_from_slice(rlp_hash.as_slice());

        keccak256(&prefixed)
    }

    /// Calculate the signature hash for ECDSA signing (user signature)
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        buf.push(ATTESTED_TX_TYPE);

        #[derive(RlpEncodable)]
        struct SigningPayload<'a> {
            chain_id: ChainId,
            nonce: u64,
            max_priority_fee_per_gas: u128,
            max_fee_per_gas: u128,
            gas_limit: u64,
            to: TxKind,
            value: U256,
            input: &'a Bytes,
            access_list: &'a AccessList,
            gateway_version: u64,
            gateway_expiry: u64,
            gateway_signature: &'a Bytes,
            original_tx_type: u8,
        }

        let payload = SigningPayload {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            input: &self.input,
            access_list: &self.access_list,
            gateway_version: self.gateway_version,
            gateway_expiry: self.gateway_expiry,
            gateway_signature: &self.gateway_signature,
            original_tx_type: self.original_tx_type.into(),
        };

        payload.encode(&mut buf);
        keccak256(&buf)
    }

    /// Check if the gateway signature has expired
    pub fn is_expired(&self, current_block: u64) -> bool {
        self.gateway_expiry != 0 && current_block > self.gateway_expiry
    }

    /// Get the effective gas price given a base fee
    pub fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        match base_fee {
            Some(base_fee) => {
                let tip = self.max_fee_per_gas.saturating_sub(base_fee as u128);
                let tip = tip.min(self.max_priority_fee_per_gas);
                (base_fee as u128).saturating_add(tip)
            }
            None => self.max_fee_per_gas,
        }
    }

    /// Decode from RLP with signature
    pub fn rlp_decode_with_signature(buf: &mut &[u8]) -> alloy_rlp::Result<(Self, Signature)> {
        #[derive(RlpDecodable)]
        struct TxAttestedWithSig {
            chain_id: ChainId,
            nonce: u64,
            max_priority_fee_per_gas: u128,
            max_fee_per_gas: u128,
            gas_limit: u64,
            to: TxKind,
            value: U256,
            input: Bytes,
            access_list: AccessList,
            gateway_version: u64,
            gateway_expiry: u64,
            gateway_signature: Bytes,
            original_tx_type: u8,
            // ECDSA signature fields
            v: u8,
            r: U256,
            s: U256,
        }

        let rlp = TxAttestedWithSig::decode(buf)?;

        let original_tx_type = OriginalTxType::try_from(rlp.original_tx_type)
            .map_err(|_| alloy_rlp::Error::Custom("invalid original tx type"))?;

        let tx = Self {
            chain_id: rlp.chain_id,
            nonce: rlp.nonce,
            max_priority_fee_per_gas: rlp.max_priority_fee_per_gas,
            max_fee_per_gas: rlp.max_fee_per_gas,
            gas_limit: rlp.gas_limit,
            to: rlp.to,
            value: rlp.value,
            input: rlp.input,
            access_list: rlp.access_list,
            gateway_version: rlp.gateway_version,
            gateway_expiry: rlp.gateway_expiry,
            gateway_signature: rlp.gateway_signature,
            original_tx_type,
        };

        // Reconstruct signature from v, r, s (v == 1 means odd parity)
        let signature = Signature::new(rlp.r, rlp.s, rlp.v != 0);

        Ok((tx, signature))
    }

    /// Encode to RLP with signature
    pub fn rlp_encode_with_signature(&self, signature: &Signature, out: &mut dyn BufMut) {
        #[derive(RlpEncodable)]
        struct TxAttestedWithSig<'a> {
            chain_id: ChainId,
            nonce: u64,
            max_priority_fee_per_gas: u128,
            max_fee_per_gas: u128,
            gas_limit: u64,
            to: TxKind,
            value: U256,
            input: &'a Bytes,
            access_list: &'a AccessList,
            gateway_version: u64,
            gateway_expiry: u64,
            gateway_signature: &'a Bytes,
            original_tx_type: u8,
            v: u8,
            r: U256,
            s: U256,
        }

        let v = signature.v() as u8;
        let rlp = TxAttestedWithSig {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            input: &self.input,
            access_list: &self.access_list,
            gateway_version: self.gateway_version,
            gateway_expiry: self.gateway_expiry,
            gateway_signature: &self.gateway_signature,
            original_tx_type: self.original_tx_type.into(),
            v,
            r: signature.r(),
            s: signature.s(),
        };

        rlp.encode(out);
    }

    /// Get the encoded length with signature
    pub fn rlp_encoded_length_with_signature(&self, signature: &Signature) -> usize {
        let v = signature.v() as u8;
        let list_len = self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.input.length()
            + self.access_list.length()
            + self.gateway_version.length()
            + self.gateway_expiry.length()
            + self.gateway_signature.length()
            + 1u8.length() // original_tx_type
            + v.length()
            + signature.r().length()
            + signature.s().length();

        alloy_rlp::length_of_length(list_len) + list_len
    }
}

/// Payload structure for attestation hash calculation
#[derive(RlpEncodable)]
struct AttestationPayload {
    chain_id: ChainId,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
    to: TxKind,
    value: U256,
    input: Bytes,
    access_list: AccessList,
    gateway_version: u64,
    gateway_expiry: u64,
    domain_tag: Bytes,
}

/// RLP encoding for TxAttested (without signature)
impl Encodable for TxAttested {
    fn encode(&self, out: &mut dyn BufMut) {
        #[derive(RlpEncodable)]
        struct TxAttestedRlp<'a> {
            chain_id: ChainId,
            nonce: u64,
            max_priority_fee_per_gas: u128,
            max_fee_per_gas: u128,
            gas_limit: u64,
            to: TxKind,
            value: U256,
            input: &'a Bytes,
            access_list: &'a AccessList,
            gateway_version: u64,
            gateway_expiry: u64,
            gateway_signature: &'a Bytes,
            original_tx_type: u8,
        }

        let rlp = TxAttestedRlp {
            chain_id: self.chain_id,
            nonce: self.nonce,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            gas_limit: self.gas_limit,
            to: self.to,
            value: self.value,
            input: &self.input,
            access_list: &self.access_list,
            gateway_version: self.gateway_version,
            gateway_expiry: self.gateway_expiry,
            gateway_signature: &self.gateway_signature,
            original_tx_type: self.original_tx_type.into(),
        };

        rlp.encode(out);
    }

    fn length(&self) -> usize {
        let list_len = self.chain_id.length()
            + self.nonce.length()
            + self.max_priority_fee_per_gas.length()
            + self.max_fee_per_gas.length()
            + self.gas_limit.length()
            + self.to.length()
            + self.value.length()
            + self.input.length()
            + self.access_list.length()
            + self.gateway_version.length()
            + self.gateway_expiry.length()
            + self.gateway_signature.length()
            + 1u8.length(); // original_tx_type

        alloy_rlp::length_of_length(list_len) + list_len
    }
}

/// RLP decoding for TxAttested (without signature)
impl Decodable for TxAttested {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        #[derive(RlpDecodable)]
        struct TxAttestedRlp {
            chain_id: ChainId,
            nonce: u64,
            max_priority_fee_per_gas: u128,
            max_fee_per_gas: u128,
            gas_limit: u64,
            to: TxKind,
            value: U256,
            input: Bytes,
            access_list: AccessList,
            gateway_version: u64,
            gateway_expiry: u64,
            gateway_signature: Bytes,
            original_tx_type: u8,
        }

        let rlp = TxAttestedRlp::decode(buf)?;

        let original_tx_type = OriginalTxType::try_from(rlp.original_tx_type)
            .map_err(|_| alloy_rlp::Error::Custom("invalid original tx type"))?;

        Ok(Self {
            chain_id: rlp.chain_id,
            nonce: rlp.nonce,
            max_priority_fee_per_gas: rlp.max_priority_fee_per_gas,
            max_fee_per_gas: rlp.max_fee_per_gas,
            gas_limit: rlp.gas_limit,
            to: rlp.to,
            value: rlp.value,
            input: rlp.input,
            access_list: rlp.access_list,
            gateway_version: rlp.gateway_version,
            gateway_expiry: rlp.gateway_expiry,
            gateway_signature: rlp.gateway_signature,
            original_tx_type,
        })
    }
}

/// Implement Typed2718 trait (required for Transaction trait)
impl Typed2718 for TxAttested {
    fn ty(&self) -> u8 {
        ATTESTED_TX_TYPE
    }
}

/// Implement alloy Transaction trait
impl alloy_consensus::Transaction for TxAttested {
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    fn gas_price(&self) -> Option<u128> {
        None // EIP-1559 style, no legacy gas price
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None // No blob support in attested tx
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        true
    }

    fn kind(&self) -> TxKind {
        self.to
    }

    fn is_create(&self) -> bool {
        self.to.is_create()
    }

    fn value(&self) -> U256 {
        self.value
    }

    fn input(&self) -> &Bytes {
        &self.input
    }

    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.access_list)
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        None
    }
}

impl reth_primitives_traits::InMemorySize for TxAttested {
    fn size(&self) -> usize {
        // Calculate size: base struct + dynamic fields
        core::mem::size_of::<Self>() +
            self.input.len() +
            // AccessList: count entries and storage keys
            self.access_list.iter().map(|item| {
                core::mem::size_of::<alloy_primitives::Address>() +
                    item.storage_keys.len() * core::mem::size_of::<alloy_primitives::B256>()
            }).sum::<usize>() +
            self.gateway_signature.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_attestation_hash() {
        let tx = TxAttested {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1000000000,
            max_priority_fee_per_gas: 1000000000,
            to: TxKind::Call(address!("0000000000000000000000000000000000000001")),
            value: U256::from(1000000000000000000u64), // 1 ETH
            input: Bytes::new(),
            access_list: AccessList::default(),
            gateway_version: 0,
            gateway_expiry: 0,
            gateway_signature: Bytes::new(),
            original_tx_type: OriginalTxType::Eip1559,
        };

        let hash = tx.attestation_hash();
        assert_ne!(hash, B256::ZERO);
    }

    #[test]
    fn test_rlp_roundtrip() {
        let tx = TxAttested {
            chain_id: 1337,
            nonce: 42,
            gas_limit: 100000,
            max_fee_per_gas: 2000000000,
            max_priority_fee_per_gas: 1000000000,
            to: TxKind::Call(address!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")),
            value: U256::from(123456789u64),
            input: Bytes::from(vec![0x01, 0x02, 0x03]),
            access_list: AccessList::default(),
            gateway_version: 1,
            gateway_expiry: 1000000,
            gateway_signature: Bytes::from(vec![0u8; 96]),
            original_tx_type: OriginalTxType::Eip1559,
        };

        // Encode
        let mut encoded = Vec::new();
        tx.encode(&mut encoded);

        // Decode
        let decoded = TxAttested::decode(&mut encoded.as_slice()).unwrap();

        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_is_expired() {
        let mut tx = TxAttested::default();

        // No expiry
        tx.gateway_expiry = 0;
        assert!(!tx.is_expired(1000000));

        // Not expired
        tx.gateway_expiry = 1000;
        assert!(!tx.is_expired(500));
        assert!(!tx.is_expired(1000));

        // Expired
        assert!(tx.is_expired(1001));
    }

    #[test]
    fn test_tx_type() {
        let tx = TxAttested::default();
        assert_eq!(tx.tx_type(), 0x64);
        assert_eq!(tx.ty(), 0x64);
    }
}
