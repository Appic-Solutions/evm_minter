use std::fmt;

use crate::eth_types::Address;
use crate::numeric::{BlockNumber, Erc20Value, LogIndex, Wei};
use crate::rpc_client::{MultiCallError, RpcClient};
use crate::rpc_declrations::{FixedSizeData, Hash, LogEntry};
use candid::Principal;
use minicbor::{Decode, Encode};
use thiserror::Error;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct ReceivedNativeEvent {
    #[n(0)]
    pub transaction_hash: Hash,
    #[n(1)]
    pub block_number: BlockNumber,
    #[cbor(n(2))]
    pub log_index: LogIndex,
    #[n(3)]
    pub from_address: Address,
    #[n(4)]
    pub value: Wei,
    #[cbor(n(5), with = "crate::cbor::principal")]
    pub principal: Principal,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct ReceivedErc20Event {
    #[n(0)]
    pub transaction_hash: Hash,
    #[n(1)]
    pub block_number: BlockNumber,
    #[cbor(n(2))]
    pub log_index: LogIndex,
    #[n(3)]
    pub from_address: Address,
    #[n(4)]
    pub value: Erc20Value,
    #[cbor(n(5), with = "crate::cbor::principal")]
    pub principal: Principal,
    #[n(6)]
    pub erc20_contract_address: Address,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceivedDepositEvent {
    Native(ReceivedNativeEvent),
    Erc20(ReceivedErc20Event),
}

impl fmt::Debug for ReceivedNativeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedNativeEvent")
            .field("transaction_hash", &self.transaction_hash)
            .field("block_number", &self.block_number)
            .field("log_index", &self.log_index)
            .field("from_address", &self.from_address)
            .field("value", &self.value)
            .field("principal", &format_args!("{}", self.principal))
            .finish()
    }
}

impl fmt::Debug for ReceivedErc20Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedErc20Event")
            .field("transaction_hash", &self.transaction_hash)
            .field("block_number", &self.block_number)
            .field("log_index", &self.log_index)
            .field("from_address", &self.from_address)
            .field("value", &self.value)
            .field("principal", &format_args!("{}", self.principal))
            .field("contract_address", &self.erc20_contract_address)
            .finish()
    }
}

/// A unique identifier of the event source: the source transaction hash and the log
/// entry index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct EventSource {
    #[n(0)]
    pub transaction_hash: Hash,
    #[n(1)]
    pub log_index: LogIndex,
}

impl fmt::Display for EventSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}:{}", self.transaction_hash, self.log_index)
    }
}

impl ReceivedNativeEvent {
    pub fn source(&self) -> EventSource {
        EventSource {
            transaction_hash: self.transaction_hash,
            log_index: self.log_index,
        }
    }
}

impl ReceivedErc20Event {
    pub fn source(&self) -> EventSource {
        EventSource {
            transaction_hash: self.transaction_hash,
            log_index: self.log_index,
        }
    }
}

impl ReceivedDepositEvent {
    /// Return event source, which is globally unique regardless of whether
    /// it is for ETH or ERC-20. This is because the `transaction_hash` already
    /// unique determines the transaction, and `log_index` would match the place
    /// in which event appears for this transaction.
    pub fn source(&self) -> EventSource {
        match self {
            ReceivedDepositEvent::Native(evt) => evt.source(),
            ReceivedDepositEvent::Erc20(evt) => evt.source(),
        }
    }
    pub fn from_address(&self) -> Address {
        match self {
            ReceivedDepositEvent::Native(evt) => evt.from_address,
            ReceivedDepositEvent::Erc20(evt) => evt.from_address,
        }
    }
    pub fn principal(&self) -> Principal {
        match self {
            ReceivedDepositEvent::Native(evt) => evt.principal,
            ReceivedDepositEvent::Erc20(evt) => evt.principal,
        }
    }
    pub fn block_number(&self) -> BlockNumber {
        match self {
            ReceivedDepositEvent::Native(evt) => evt.block_number,
            ReceivedDepositEvent::Erc20(evt) => evt.block_number,
        }
    }
    pub fn log_index(&self) -> LogIndex {
        match self {
            ReceivedDepositEvent::Native(evt) => evt.log_index,
            ReceivedDepositEvent::Erc20(evt) => evt.log_index,
        }
    }
    pub fn transaction_hash(&self) -> Hash {
        match self {
            ReceivedDepositEvent::Native(evt) => evt.transaction_hash,
            ReceivedDepositEvent::Erc20(evt) => evt.transaction_hash,
        }
    }
    pub fn value(&self) -> candid::Nat {
        match self {
            ReceivedDepositEvent::Native(evt) => evt.value.into(),
            ReceivedDepositEvent::Erc20(evt) => evt.value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedEventError {
    PendingLogEntry,
    InvalidEventSource {
        source: EventSource,
        error: EventSourceError,
    },
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EventSourceError {
    #[error("failed to decode principal from bytes {invalid_principal}")]
    InvalidPrincipal { invalid_principal: FixedSizeData },
    #[error("invalid ReceivedDepositEvent: {0}")]
    InvalidEvent(String),
}

impl TryFrom<LogEntry> for ReceivedDepositEvent {
    type Error = ReceivedEventError;

    fn try_from(entry: LogEntry) -> Result<Self, Self::Error> {
        let _block_hash = entry
            .block_hash
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let block_number = entry
            .block_number
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let transaction_hash = entry
            .transaction_hash
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let _transaction_index = entry
            .transaction_index
            .ok_or(ReceivedEventError::PendingLogEntry)?;
        let log_index = entry.log_index.ok_or(ReceivedEventError::PendingLogEntry)?;
        let event_source = EventSource {
            transaction_hash,
            log_index,
        };

        if entry.removed {
            return Err(ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(
                    "this event has been removed from the chain".to_string(),
                ),
            });
        }

        let parse_address = |address: &[u8; 32]| -> Result<Address, ReceivedEventError> {
            Address::try_from(address).map_err(|err| ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Invalid address in log entry: {}",
                    err
                )),
            })
        };

        let parse_principal = |principal: &FixedSizeData| -> Result<Principal, ReceivedEventError> {
            parse_principal_from_slice(&principal.0).map_err(|_err| {
                ReceivedEventError::InvalidEventSource {
                    source: event_source,
                    error: EventSourceError::InvalidPrincipal {
                        invalid_principal: principal.clone(),
                    },
                }
            })
        };

        // We have only one non-indexed data field.
        let user_address: [u8; 32] = entry.data.0.clone().try_into().map_err(|data| {
            ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Invalid data length; expected 32-byte value, got {}",
                    hex::encode(data)
                )),
            }
        })?;

        let from_address = parse_address(&user_address)?;

        // We have 4 indexed topics for all deposit events:
        // (hash, contract_address of the token(in case of native token its 0x000000000000000000000000000), amount of token(value), principalId)
        match entry.topics[0] {
            FixedSizeData(crate::state::RECEIVED_DEPOSITED_TOKEN_EVENT_TOPIC) => {
                if entry.topics.len() != 4 {
                    return Err(ReceivedEventError::InvalidEventSource {
                        source: event_source,
                        error: EventSourceError::InvalidEvent(format!(
                            "Expected 4 topics for ReceivedDepositEvnet event, got {}",
                            entry.topics.len()
                        )),
                    });
                };
                let token_contract_address = parse_address(&entry.topics[1].0)?;
                let principal = parse_principal(&entry.topics[3])?;
                let value = &entry.topics[2];
                match token_contract_address.is_native_token() {
                    true => Ok(ReceivedDepositEvent::Native(ReceivedNativeEvent {
                        transaction_hash,
                        block_number,
                        log_index,
                        from_address,
                        value: Wei::from_be_bytes(value.0),
                        principal,
                    })),
                    false => Ok(ReceivedDepositEvent::Erc20(ReceivedErc20Event {
                        transaction_hash,
                        block_number,
                        log_index,
                        from_address,
                        value: Erc20Value::from_be_bytes(value.0),
                        principal,
                        erc20_contract_address: token_contract_address,
                    })),
                }
            }
            _ => Err(ReceivedEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Expected either ReceivedEth or ReceivedERC20 topics, got {}",
                    entry.topics[0]
                )),
            }),
        }
    }
}

/// Decode a candid::Principal from a slice of at most 32 bytes
/// encoded as follows
/// - the first byte is the number of bytes in the principal
/// - the next N bytes are the principal
/// - the remaining bytes are zero
///
/// Any other encoding will return an error.
/// Some specific valid [`Principal`]s are also not allowed
/// since the decoded principal will be used to receive ckETH:
/// * the management canister principal
/// * the anonymous principal
///
/// This method MUST never panic (decode bytes from untrusted sources).
fn parse_principal_from_slice(slice: &[u8]) -> Result<Principal, String> {
    const ANONYMOUS_PRINCIPAL_BYTES: [u8; 1] = [4];

    if slice.is_empty() {
        return Err("slice too short".to_string());
    }
    if slice.len() > 32 {
        return Err(format!("Expected at most 32 bytes, got {}", slice.len()));
    }
    let num_bytes = slice[0] as usize;
    if num_bytes == 0 {
        return Err("management canister principal is not allowed".to_string());
    }
    if num_bytes > 29 {
        return Err(format!(
            "invalid number of bytes: expected a number in the range [1,29], got {num_bytes}",
        ));
    }
    if slice.len() < 1 + num_bytes {
        return Err("slice too short".to_string());
    }
    let (principal_bytes, trailing_zeroes) = slice[1..].split_at(num_bytes);
    if !trailing_zeroes
        .iter()
        .all(|trailing_zero| *trailing_zero == 0)
    {
        return Err("trailing non-zero bytes".to_string());
    }
    if principal_bytes == ANONYMOUS_PRINCIPAL_BYTES {
        return Err("anonymous principal is not allowed".to_string());
    }
    Principal::try_from_slice(principal_bytes).map_err(|err| err.to_string())
}
