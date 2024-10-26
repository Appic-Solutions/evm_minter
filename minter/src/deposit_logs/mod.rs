#[cfg(test)]
mod test;

use std::fmt;

use crate::checked_amount::CheckedAmountOf;
use crate::eth_types::Address;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, Erc20Value, LogIndex, Wei};
use crate::rpc_client::{MultiCallError, RpcClient};
use crate::rpc_declrations::{Data, FixedSizeData, Hash, LogEntry};
use crate::state::read_state;
use candid::Principal;
use ic_canister_log::log;
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
    #[n(6)]
    pub subaccount: Option<LedgerSubaccount>,
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
    #[n(7)]
    pub subaccount: Option<LedgerSubaccount>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceivedDepositEvent {
    Native(ReceivedNativeEvent),
    Erc20(ReceivedErc20Event),
}

impl From<ReceivedNativeEvent> for ReceivedDepositEvent {
    fn from(event: ReceivedNativeEvent) -> Self {
        ReceivedDepositEvent::Native(event)
    }
}

impl From<ReceivedErc20Event> for ReceivedDepositEvent {
    fn from(event: ReceivedErc20Event) -> Self {
        ReceivedDepositEvent::Erc20(event)
    }
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
            .field("subaccount", &self.subaccount)
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
            .field("subaccount", &self.subaccount)
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

    pub fn subaccount(&self) -> Option<[u8; 32]> {
        match self {
            ReceivedDepositEvent::Native(evt) => match &evt.subaccount {
                Some(sub) => Some(sub.clone().to_bytes()),
                None => None,
            },
            ReceivedDepositEvent::Erc20(evt) => match &evt.subaccount {
                Some(sub) => Some(sub.clone().to_bytes()),
                None => None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedDepsitEventError {
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

pub fn report_transaction_error(error: ReceivedDepsitEventError) {
    match error {
        ReceivedDepsitEventError::PendingLogEntry => {
            log!(
                DEBUG,
                "[report_transaction_error]: ignoring pending log entry",
            );
        }
        ReceivedDepsitEventError::InvalidEventSource { source, error } => {
            log!(
                INFO,
                "[report_transaction_error]: cannot process {source} due to {error}",
            );
        }
    }
}

// Fetches deposit logs by creating an instance of RPClient from state
// and calling the get_logs function
pub async fn last_received_deposit_events(
    topic: &[u8; 32],
    contract_address: Address,
    token_contract_addresses: &[Address],
    from: BlockNumber,
    to: BlockNumber,
) -> Result<(Vec<ReceivedDepositEvent>, Vec<ReceivedDepsitEventError>), MultiCallError<Vec<LogEntry>>>
{
    use crate::rpc_declrations::GetLogsParam;

    if from > to {
        ic_cdk::trap(&format!(
            "BUG: invalid block range. {:?} should not be greater than {:?}",
            from, to
        ));
    }
    let mut topics: Vec<_> = vec![FixedSizeData(*topic).into()];
    // We add token contract addresses as additional topics to match.
    // It has a disjunction semantics, so it will match if event matches any one of these addresses.
    if !token_contract_addresses.is_empty() {
        topics.push(
            token_contract_addresses
                .iter()
                .map(|address| FixedSizeData(address.into()))
                .collect::<Vec<_>>()
                .into(),
        )
    }

    let result = read_state(RpcClient::from_state_all_providers)
        .get_logs(GetLogsParam {
            from_block: from.into(),
            to_block: to.into(),
            address: vec![contract_address],
            topics,
        })
        .await?;

    let (ok, not_ok): (Vec<_>, Vec<_>) = result
        .into_iter()
        .map(ReceivedDepositEvent::try_from)
        .partition(Result::is_ok);
    let valid_transactions: Vec<ReceivedDepositEvent> =
        ok.into_iter().map(Result::unwrap).collect();
    let errors: Vec<ReceivedDepsitEventError> =
        not_ok.into_iter().map(Result::unwrap_err).collect();
    Ok((valid_transactions, errors))
}

// Converts LogEntry to ReceivedDepsitEvent
impl TryFrom<LogEntry> for ReceivedDepositEvent {
    type Error = ReceivedDepsitEventError;

    fn try_from(entry: LogEntry) -> Result<Self, Self::Error> {
        let _block_hash = entry
            .block_hash
            .ok_or(ReceivedDepsitEventError::PendingLogEntry)?;
        let block_number = entry
            .block_number
            .ok_or(ReceivedDepsitEventError::PendingLogEntry)?;
        let transaction_hash = entry
            .transaction_hash
            .ok_or(ReceivedDepsitEventError::PendingLogEntry)?;
        let _transaction_index = entry
            .transaction_index
            .ok_or(ReceivedDepsitEventError::PendingLogEntry)?;
        let log_index = entry
            .log_index
            .ok_or(ReceivedDepsitEventError::PendingLogEntry)?;
        let event_source = EventSource {
            transaction_hash,
            log_index,
        };

        if entry.removed {
            return Err(ReceivedDepsitEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(
                    "this event has been removed from the chain".to_string(),
                ),
            });
        }

        let parse_address = |address: &[u8; 32]| -> Result<Address, ReceivedDepsitEventError> {
            Address::try_from(address).map_err(|err| ReceivedDepsitEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Invalid address in log entry: {}",
                    err
                )),
            })
        };

        let parse_principal =
            |principal: &FixedSizeData| -> Result<Principal, ReceivedDepsitEventError> {
                parse_principal_from_slice(&principal.0).map_err(|_err| {
                    ReceivedDepsitEventError::InvalidEventSource {
                        source: event_source,
                        error: EventSourceError::InvalidPrincipal {
                            invalid_principal: principal.clone(),
                        },
                    }
                })
            };

        if entry.topics.is_empty() {
            return Err(ReceivedDepsitEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent("Expected at least one topic".to_string()),
            });
        }

        // We have 4 indexed topics for all deposit events:
        // The overal event is as follow :
        // DepositLog(
        //     address from_address,
        //     address indexed token,
        //     uint256 indexed amount,
        //     bytes32 indexed principal,
        //     bytes32 subaccount
        // );
        // Indexed topics are as follow
        // (
        //     Event Topic,
        //     Indexed contract_address of the token(in case of native token its 0x000000000000000000000000000),
        //     Indexed amount of token(value),
        //     Indexed principalId
        // );
        match entry.topics[0] {
            FixedSizeData(crate::state::RECEIVED_DEPOSITED_TOKEN_EVENT_TOPIC) => {
                if entry.topics.len() != 4 {
                    return Err(ReceivedDepsitEventError::InvalidEventSource {
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

                // Non indexed data
                // We have two non-indexed data field (from_address, subaccount).

                let [from_address_bytes, subaccount_bytes] =
                    parse_data_into_32_byte_words(entry.data, event_source)?;

                let from_address = parse_address(&from_address_bytes)?;
                let subaccount = LedgerSubaccount::from_bytes(subaccount_bytes);

                match token_contract_address.is_native_token() {
                    true => Ok(ReceivedDepositEvent::Native(ReceivedNativeEvent {
                        transaction_hash,
                        block_number,
                        log_index,
                        from_address,
                        value: Wei::from_be_bytes(value.0),
                        principal,
                        subaccount,
                    })),
                    false => Ok(ReceivedDepositEvent::Erc20(ReceivedErc20Event {
                        transaction_hash,
                        block_number,
                        log_index,
                        from_address,
                        value: Erc20Value::from_be_bytes(value.0),
                        principal,
                        erc20_contract_address: token_contract_address,
                        subaccount,
                    })),
                }
            }
            _ => Err(ReceivedDepsitEventError::InvalidEventSource {
                source: event_source,
                error: EventSourceError::InvalidEvent(format!(
                    "Expected either ReceivedEth or ReceivedERC20 topics, got {}",
                    entry.topics[0]
                )),
            }),
        }
    }
}

fn parse_data_into_32_byte_words<const N: usize>(
    data: Data,
    event_source: EventSource,
) -> Result<[[u8; 32]; N], ReceivedDepsitEventError> {
    let data = data.0;
    if data.len() != 32 * N {
        return Err(ReceivedDepsitEventError::InvalidEventSource {
            source: event_source,
            error: EventSourceError::InvalidEvent(format!(
                "Expected {} bytes, got {}",
                32 * N,
                data.len()
            )),
        });
    }
    let mut result = Vec::with_capacity(N);
    for chunk in data.chunks_exact(32) {
        let mut word = [0; 32];
        word.copy_from_slice(chunk);
        result.push(word);
    }
    Ok(result.try_into().unwrap())
}

enum InternalLedgerSubaccountTag {}
type InternalLedgerSubaccount = CheckedAmountOf<InternalLedgerSubaccountTag>;

/// Ledger subaccount.
///
/// Internally represented as a u256 to optimize cbor encoding for low values,
/// which can be represented as a u32 or a u64.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Decode, Encode)]
pub struct LedgerSubaccount(#[n(0)] InternalLedgerSubaccount);

impl LedgerSubaccount {
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        const DEFAULT_SUBACCOUNT: [u8; 32] = [0; 32];
        if bytes == DEFAULT_SUBACCOUNT {
            return None;
        }
        Some(Self(InternalLedgerSubaccount::from_be_bytes(bytes)))
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes()
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
