use candid::Nat;
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};

use crate::eth_types::Address;
use crate::numeric::{BlockNumber, LogIndex, Wei};

pub type Quantity = ethnum::u256;

pub fn into_nat(quantity: Quantity) -> candid::Nat {
    use num_bigint::BigUint;
    candid::Nat::from(BigUint::from_bytes_be(&quantity.to_be_bytes()))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Data(pub Vec<u8>);

impl std::str::FromStr for Data {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.to_string()))
            .map_err(|e| format!("failed to parse data from string: {}", e))
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct FixedSizeData(pub [u8; 32]);

impl AsRef<[u8]> for FixedSizeData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::str::FromStr for FixedSizeData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("Ethereum hex string doesn't start with 0x".to_string());
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("failed to decode hash from hex: {}", e))?;
        Ok(Self(bytes))
    }
}

impl Debug for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl Display for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl LowerHex for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl UpperHex for FixedSizeData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode_upper(self.0))
    }
}

#[derive(
    Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, Ord, PartialOrd, Encode, Decode,
)]
#[serde(transparent)]
#[cbor(transparent)]
pub struct Hash(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl LowerHex for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl UpperHex for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode_upper(self.0))
    }
}

impl std::str::FromStr for Hash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err("Ethereum hash doesn't start with 0x".to_string());
        }
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(&s[2..], &mut bytes)
            .map_err(|e| format!("failed to decode hash from hex: {}", e))?;
        Ok(Self(bytes))
    }
}

/// Block tags.
/// See <https://ethereum.org/en/developers/docs/apis/json-rpc/#default-block>
#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlockTag {
    /// The latest mined block.
    #[default]
    Latest,
    /// The latest safe head block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    Safe,
    /// The latest finalized block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    Finalized,
}

// impl From<CandidBlockTag> for BlockTag {
//     fn from(block_tag: CandidBlockTag) -> BlockTag {
//         match block_tag {
//             CandidBlockTag::Latest => BlockTag::Latest,
//             CandidBlockTag::Safe => BlockTag::Safe,
//             CandidBlockTag::Finalized => BlockTag::Finalized,
//         }
//     }
// }

// impl From<BlockTag> for CandidBlockTag {
//     fn from(value: BlockTag) -> Self {
//         match value {
//             BlockTag::Latest => CandidBlockTag::Latest,
//             BlockTag::Safe => CandidBlockTag::Safe,
//             BlockTag::Finalized => CandidBlockTag::Finalized,
//         }
//     }
// }

impl Display for BlockTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Latest => write!(f, "latest"),
            Self::Safe => write!(f, "safe"),
            Self::Finalized => write!(f, "finalized"),
        }
    }
}

/// The block specification indicating which block to query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BlockSpec {
    /// Query the block with the specified index.
    Number(BlockNumber),
    /// Query the block with the specified tag.
    Tag(BlockTag),
}

impl Default for BlockSpec {
    fn default() -> Self {
        Self::Tag(BlockTag::default())
    }
}

impl std::str::FromStr for BlockSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("0x") {
            let block_number = BlockNumber::from_str_hex(s)
                .map_err(|e| format!("failed to parse block number '{s}': {e}"))?;
            return Ok(BlockSpec::Number(block_number));
        }
        Ok(BlockSpec::Tag(match s {
            "latest" => BlockTag::Latest,
            "safe" => BlockTag::Safe,
            "finalized" => BlockTag::Finalized,
            _ => return Err(format!("unknown block tag '{s}'")),
        }))
    }
}

/// A topic is either a 32 Bytes DATA, or an array of 32 Bytes DATA with "or" options.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Topic {
    Single(FixedSizeData),
    Multiple(Vec<FixedSizeData>),
}

impl From<FixedSizeData> for Topic {
    fn from(data: FixedSizeData) -> Self {
        Topic::Single(data)
    }
}

impl From<Vec<FixedSizeData>> for Topic {
    fn from(data: Vec<FixedSizeData>) -> Self {
        Topic::Multiple(data)
    }
}

/// Parameters of the [`eth_getLogs`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs) call.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLogsParam {
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub from_block: BlockSpec,
    /// Integer block number, or "latest" for the last mined block or "pending", "earliest" for not yet mined transactions.
    pub to_block: BlockSpec,
    /// Contract address or a list of addresses from which logs should originate.
    pub address: Vec<Address>,
    /// Array of 32 Bytes DATA topics.
    /// Topics are order-dependent.
    /// Each topic can also be an array of DATA with "or" options.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<Topic>,
}

/// An entry of the [`eth_getLogs`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs) call reply.
// Example:
// ```json
// {
//    "address": "0x7e41257f7b5c3dd3313ef02b1f4c864fe95bec2b",
//    "topics": [
//      "0x2a2607d40f4a6feb97c36e0efd57e0aa3e42e0332af4fceb78f21b7dffcbd657"
//    ],
//    "data": "0x00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764000000000000000000000000000000000000000000000000002386f26fc100000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003f62327071372d71677a7a692d74623564622d72357363692d637736736c2d6e646f756c2d666f7435742d347a7732702d657a6677692d74616a32792d76716500",
//    "blockNumber": "0x3aa4f4",
//    "transactionHash": "0x5618f72c485bd98a3df58d900eabe9e24bfaa972a6fe5227e02233fad2db1154",
//    "transactionIndex": "0x6",
//    "blockHash": "0x908e6b84d26d71421bfaa08e7966e0afcef3883a28a53a0a7a31104caf1e94c2",
//    "logIndex": "0x8",
//    "removed": false
//  }
// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// The address from which this log originated.
    pub address: Address,
    /// Array of 0 to 4 32 Bytes DATA of indexed log arguments.
    /// In solidity: The first topic is the event signature hash (e.g. Deposit(address,bytes32,uint256)),
    /// unless you declared the event with the anonymous specifier.
    pub topics: Vec<FixedSizeData>,
    /// Contains one or more 32-byte non-indexed log arguments.
    pub data: Data,
    /// The block number in which this log appeared.
    /// None if the block is pending.
    pub block_number: Option<BlockNumber>,
    // 32 Bytes - hash of the transactions from which this log was created.
    // None when its pending log.
    pub transaction_hash: Option<Hash>,
    // Integer of the transactions position within the block the log was created from.
    // None if the log is pending.
    pub transaction_index: Option<Quantity>,
    /// 32 Bytes - hash of the block in which this log appeared.
    /// None if the block is pending.
    pub block_hash: Option<Hash>,
    /// Integer of the log index position in the block.
    /// None if the log is pending.
    pub log_index: Option<LogIndex>,
    /// "true" when the log was removed due to a chain reorganization.
    /// "false" if it's a valid log.
    #[serde(default)]
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    ///The block number. `None` when its pending block.
    pub number: BlockNumber,
    /// Base fee value of this block
    pub base_fee_per_gas: Wei,
}
