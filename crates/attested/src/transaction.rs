//! RISNode Transaction Types
//!
//! This module defines the transaction envelope that includes support for
//! attested transactions (Type 0x64) alongside standard Ethereum transactions.

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

use alloy_consensus::{
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx, SignerRecoverable, TxHashRef},
    SignableTransaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702,
    TxLegacy, TxType, Typed2718,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718, IsTyped2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{
    bytes::BufMut, keccak256, Address, Bytes, ChainId, Signature, TxHash, TxKind, B256, U256,
};
use alloy_rlp::{Decodable, Encodable};
use reth_primitives_traits::{
    crypto::secp256k1::{recover_signer, recover_signer_unchecked},
    sync::OnceLock,
    transaction::signed::RecoveryError,
    InMemorySize, SignedTransaction,
};

use crate::tx_attested::{TxAttested, ATTESTED_TX_TYPE};

macro_rules! delegate {
    ($self:expr => $tx:ident.$method:ident($($arg:expr),*)) => {
        match $self {
            AttestedTransaction::Legacy($tx) => $tx.$method($($arg),*),
            AttestedTransaction::Eip2930($tx) => $tx.$method($($arg),*),
            AttestedTransaction::Eip1559($tx) => $tx.$method($($arg),*),
            AttestedTransaction::Eip4844($tx) => $tx.$method($($arg),*),
            AttestedTransaction::Eip7702($tx) => $tx.$method($($arg),*),
            AttestedTransaction::Attested($tx) => $tx.$method($($arg),*),
        }
    };
}

/// Transaction Types with Attested Transaction Support
///
/// Includes all standard Ethereum transaction types plus the Attested Transaction (0x64).
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::From)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttestedTransaction {
    /// Legacy transaction (type `0x0`).
    Legacy(TxLegacy),
    /// Transaction with an [`AccessList`] ([EIP-2930]), type `0x1`.
    Eip2930(TxEip2930),
    /// A transaction with a priority fee ([EIP-1559]), type `0x2`.
    Eip1559(TxEip1559),
    /// Shard Blob Transactions ([EIP-4844]), type `0x3`.
    Eip4844(TxEip4844),
    /// EOA Set Code Transactions ([EIP-7702]), type `0x4`.
    Eip7702(TxEip7702),
    /// Attested Transaction, type `0x64`.
    Attested(TxAttested),
}

impl AttestedTransaction {
    /// Returns true if this is a legacy transaction
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy(_))
    }

    /// Returns true if this is an attested transaction
    pub const fn is_attested(&self) -> bool {
        matches!(self, Self::Attested(_))
    }

    /// Returns the transaction type as u8
    pub const fn tx_type_byte(&self) -> u8 {
        match self {
            Self::Legacy(_) => 0x00,
            Self::Eip2930(_) => 0x01,
            Self::Eip1559(_) => 0x02,
            Self::Eip4844(_) => 0x03,
            Self::Eip7702(_) => 0x04,
            Self::Attested(_) => ATTESTED_TX_TYPE,
        }
    }
}

impl Default for AttestedTransaction {
    fn default() -> Self {
        Self::Legacy(TxLegacy::default())
    }
}

impl Typed2718 for AttestedTransaction {
    fn ty(&self) -> u8 {
        self.tx_type_byte()
    }
}

impl alloy_consensus::Transaction for AttestedTransaction {
    fn chain_id(&self) -> Option<ChainId> {
        delegate!(self => tx.chain_id())
    }

    fn nonce(&self) -> u64 {
        delegate!(self => tx.nonce())
    }

    fn gas_limit(&self) -> u64 {
        delegate!(self => tx.gas_limit())
    }

    fn gas_price(&self) -> Option<u128> {
        delegate!(self => tx.gas_price())
    }

    fn max_fee_per_gas(&self) -> u128 {
        delegate!(self => tx.max_fee_per_gas())
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        delegate!(self => tx.max_priority_fee_per_gas())
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        delegate!(self => tx.max_fee_per_blob_gas())
    }

    fn priority_fee_or_price(&self) -> u128 {
        delegate!(self => tx.priority_fee_or_price())
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        delegate!(self => tx.effective_gas_price(base_fee))
    }

    fn is_dynamic_fee(&self) -> bool {
        delegate!(self => tx.is_dynamic_fee())
    }

    fn kind(&self) -> TxKind {
        delegate!(self => tx.kind())
    }

    fn is_create(&self) -> bool {
        delegate!(self => tx.is_create())
    }

    fn value(&self) -> U256 {
        delegate!(self => tx.value())
    }

    fn input(&self) -> &Bytes {
        delegate!(self => tx.input())
    }

    fn access_list(&self) -> Option<&AccessList> {
        delegate!(self => tx.access_list())
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        delegate!(self => tx.blob_versioned_hashes())
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        delegate!(self => tx.authorization_list())
    }
}

impl InMemorySize for AttestedTransaction {
    fn size(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.size(),
            Self::Eip2930(tx) => tx.size(),
            Self::Eip1559(tx) => tx.size(),
            Self::Eip4844(tx) => tx.size(),
            Self::Eip7702(tx) => tx.size(),
            Self::Attested(tx) => core::mem::size_of_val(tx),
        }
    }
}

/// Signed RISNode Transaction
///
/// A transaction with its ECDSA signature and cached hash.
#[derive(Debug, Clone, Eq, derive_more::AsRef, derive_more::Deref)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AttestedTransactionSigned {
    /// Transaction hash
    #[cfg_attr(feature = "serde", serde(skip))]
    hash: OnceLock<TxHash>,
    /// The transaction signature values
    signature: Signature,
    /// Raw transaction info
    #[deref]
    #[as_ref]
    transaction: AttestedTransaction,
}

impl AttestedTransactionSigned {
    /// Creates a new signed transaction from the given transaction, signature and hash.
    pub fn new(transaction: AttestedTransaction, signature: Signature, hash: B256) -> Self {
        Self { hash: hash.into(), signature, transaction }
    }

    /// Creates a new signed transaction from the given transaction and signature.
    pub fn new_unhashed(transaction: AttestedTransaction, signature: Signature) -> Self {
        Self { hash: OnceLock::new(), signature, transaction }
    }

    /// Returns the transaction hash.
    #[inline]
    pub fn hash(&self) -> &B256 {
        self.hash.get_or_init(|| self.recalculate_hash())
    }

    /// Returns the signature
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the inner transaction
    pub fn transaction(&self) -> &AttestedTransaction {
        &self.transaction
    }

    /// Splits the transaction into parts.
    pub fn into_parts(self) -> (AttestedTransaction, Signature, B256) {
        let hash = *self.hash.get_or_init(|| self.recalculate_hash());
        (self.transaction, self.signature, hash)
    }

    fn recalculate_hash(&self) -> B256 {
        keccak256(self.encoded_2718())
    }

    /// Calculate the signature hash
    pub fn signature_hash(&self) -> B256 {
        match &self.transaction {
            AttestedTransaction::Legacy(tx) => tx.signature_hash(),
            AttestedTransaction::Eip2930(tx) => tx.signature_hash(),
            AttestedTransaction::Eip1559(tx) => tx.signature_hash(),
            AttestedTransaction::Eip4844(tx) => tx.signature_hash(),
            AttestedTransaction::Eip7702(tx) => tx.signature_hash(),
            AttestedTransaction::Attested(tx) => tx.signature_hash(),
        }
    }
}

impl Hash for AttestedTransactionSigned {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signature.hash(state);
        self.transaction.hash(state);
    }
}

impl PartialEq for AttestedTransactionSigned {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature &&
            self.transaction == other.transaction &&
            self.hash() == other.hash()
    }
}

impl Typed2718 for AttestedTransactionSigned {
    fn ty(&self) -> u8 {
        self.transaction.ty()
    }
}

impl alloy_consensus::Transaction for AttestedTransactionSigned {
    fn chain_id(&self) -> Option<ChainId> {
        self.transaction.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.transaction.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.transaction.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.transaction.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.transaction.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.transaction.is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.transaction.kind()
    }

    fn is_create(&self) -> bool {
        self.transaction.is_create()
    }

    fn value(&self) -> U256 {
        self.transaction.value()
    }

    fn input(&self) -> &Bytes {
        self.transaction.input()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.transaction.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.transaction.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.transaction.authorization_list()
    }
}

impl InMemorySize for AttestedTransactionSigned {
    fn size(&self) -> usize {
        let Self { hash: _, signature, transaction } = self;
        core::mem::size_of::<B256>() + signature.size() + transaction.size()
    }
}

impl Encodable2718 for AttestedTransactionSigned {
    fn type_flag(&self) -> Option<u8> {
        (!self.transaction.is_legacy()).then(|| self.ty())
    }

    fn encode_2718_len(&self) -> usize {
        match &self.transaction {
            AttestedTransaction::Legacy(tx) => tx.eip2718_encoded_length(&self.signature),
            AttestedTransaction::Eip2930(tx) => tx.eip2718_encoded_length(&self.signature),
            AttestedTransaction::Eip1559(tx) => tx.eip2718_encoded_length(&self.signature),
            AttestedTransaction::Eip4844(tx) => tx.eip2718_encoded_length(&self.signature),
            AttestedTransaction::Eip7702(tx) => tx.eip2718_encoded_length(&self.signature),
            AttestedTransaction::Attested(tx) => 1 + tx.rlp_encoded_length_with_signature(&self.signature),
        }
    }

    fn encode_2718(&self, out: &mut dyn BufMut) {
        match &self.transaction {
            AttestedTransaction::Legacy(tx) => tx.eip2718_encode(&self.signature, out),
            AttestedTransaction::Eip2930(tx) => tx.eip2718_encode(&self.signature, out),
            AttestedTransaction::Eip1559(tx) => tx.eip2718_encode(&self.signature, out),
            AttestedTransaction::Eip4844(tx) => tx.eip2718_encode(&self.signature, out),
            AttestedTransaction::Eip7702(tx) => tx.eip2718_encode(&self.signature, out),
            AttestedTransaction::Attested(tx) => {
                out.put_u8(ATTESTED_TX_TYPE);
                tx.rlp_encode_with_signature(&self.signature, out);
            }
        }
    }

    fn trie_hash(&self) -> B256 {
        *self.hash()
    }
}

impl Decodable2718 for AttestedTransactionSigned {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        // Check for attested transaction type first
        if ty == ATTESTED_TX_TYPE {
            let (tx, signature) = TxAttested::rlp_decode_with_signature(buf)
                .map_err(Eip2718Error::RlpError)?;
            return Ok(Self {
                transaction: AttestedTransaction::Attested(tx),
                signature,
                hash: OnceLock::new(),
            });
        }

        // Handle standard Ethereum types
        match ty.try_into().map_err(|_| Eip2718Error::UnexpectedType(ty))? {
            TxType::Legacy => Err(Eip2718Error::UnexpectedType(0)),
            TxType::Eip2930 => {
                let (tx, signature) = TxEip2930::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: AttestedTransaction::Eip2930(tx),
                    signature,
                    hash: OnceLock::new(),
                })
            }
            TxType::Eip1559 => {
                let (tx, signature) = TxEip1559::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: AttestedTransaction::Eip1559(tx),
                    signature,
                    hash: OnceLock::new(),
                })
            }
            TxType::Eip4844 => {
                let (tx, signature) = TxEip4844::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: AttestedTransaction::Eip4844(tx),
                    signature,
                    hash: OnceLock::new(),
                })
            }
            TxType::Eip7702 => {
                let (tx, signature) = TxEip7702::rlp_decode_with_signature(buf)?;
                Ok(Self {
                    transaction: AttestedTransaction::Eip7702(tx),
                    signature,
                    hash: OnceLock::new(),
                })
            }
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        let (tx, signature) = TxLegacy::rlp_decode_with_signature(buf)?;
        Ok(Self {
            transaction: AttestedTransaction::Legacy(tx),
            signature,
            hash: OnceLock::new(),
        })
    }
}

impl Encodable for AttestedTransactionSigned {
    fn encode(&self, out: &mut dyn BufMut) {
        self.network_encode(out);
    }

    fn length(&self) -> usize {
        self.network_len()
    }
}

impl Decodable for AttestedTransactionSigned {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::network_decode(buf).map_err(Into::into)
    }
}

impl SignerRecoverable for AttestedTransactionSigned {
    fn recover_signer(&self) -> Result<Address, RecoveryError> {
        let signature_hash = self.signature_hash();
        recover_signer(&self.signature, signature_hash)
    }

    fn recover_signer_unchecked(&self) -> Result<Address, RecoveryError> {
        let signature_hash = self.signature_hash();
        recover_signer_unchecked(&self.signature, signature_hash)
    }

    fn recover_unchecked_with_buf(&self, buf: &mut Vec<u8>) -> Result<Address, RecoveryError> {
        buf.clear();
        match &self.transaction {
            AttestedTransaction::Legacy(tx) => tx.encode_for_signing(buf),
            AttestedTransaction::Eip2930(tx) => tx.encode_for_signing(buf),
            AttestedTransaction::Eip1559(tx) => tx.encode_for_signing(buf),
            AttestedTransaction::Eip4844(tx) => tx.encode_for_signing(buf),
            AttestedTransaction::Eip7702(tx) => tx.encode_for_signing(buf),
            AttestedTransaction::Attested(tx) => {
                // For attested transactions, use the signature hash directly
                let hash = tx.signature_hash();
                return recover_signer_unchecked(&self.signature, hash);
            }
        }
        let signature_hash = keccak256(buf);
        recover_signer_unchecked(&self.signature, signature_hash)
    }
}

impl TxHashRef for AttestedTransactionSigned {
    fn tx_hash(&self) -> &TxHash {
        self.hash.get_or_init(|| self.recalculate_hash())
    }
}

impl IsTyped2718 for AttestedTransactionSigned {
    fn is_type(type_id: u8) -> bool {
        // Standard Ethereum types + attested type
        matches!(type_id, 0x00 | 0x01 | 0x02 | 0x03 | 0x04 | ATTESTED_TX_TYPE)
    }
}

impl SignedTransaction for AttestedTransactionSigned {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn test_transaction_type() {
        let legacy = AttestedTransaction::Legacy(TxLegacy::default());
        assert_eq!(legacy.tx_type_byte(), 0x00);
        assert!(legacy.is_legacy());
        assert!(!legacy.is_attested());

        let attested = AttestedTransaction::Attested(TxAttested::default());
        assert_eq!(attested.tx_type_byte(), 0x64);
        assert!(!attested.is_legacy());
        assert!(attested.is_attested());
    }

    #[test]
    fn test_signed_transaction_hash() {
        let tx = AttestedTransaction::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 1000000000,
            max_priority_fee_per_gas: 1000000000,
            to: TxKind::Call(address!("0000000000000000000000000000000000000001")),
            value: U256::from(1000000000000000000u64),
            input: Bytes::new(),
            access_list: AccessList::default(),
        });

        let signature = Signature::test_signature();
        let signed = AttestedTransactionSigned::new_unhashed(tx, signature);

        // Hash should be computed on first access
        let hash1 = *signed.hash();
        let hash2 = *signed.hash();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, B256::ZERO);
    }
}
