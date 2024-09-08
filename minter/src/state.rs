pub mod audit;
pub mod event;
pub mod transactions;
use std::{
    cell::RefCell,
    collections::{btree_map, BTreeMap, BTreeSet, HashSet},
    fmt::{Display, Formatter},
    str::FromStr,
};

use candid::Principal;
use hex_literal::hex;
use ic_canister_log::log;
use ic_crypto_secp256k1::PublicKey;
use serde_bytes::ByteBuf;
use transactions::WithdrawalTransactions;

use crate::{
    address::ecdsa_public_key_to_address,
    deposit_logs::{EventSource, ReceivedDepositEvent},
    erc20::ERC20TokenSymbol,
    eth_types::Address,
    lifecycles::EvmNetwork,
    logs::DEBUG,
    map::DedupMultiKeyMap,
    numeric::{BlockNumber, Erc20Value, LedgerMintIndex, Wei, WeiPerGas},
    rpc_declrations::{BlockTag, FixedSizeData},
    tx::GasFeeEstimate,
};
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;

thread_local! {
    pub static STATE:RefCell<Option<State>>=RefCell::default();
}

pub(crate) const RECEIVED_DEPOSITED_TOKEN_EVENT_TOPIC: [u8; 32] =
    hex!("d04bc46dc93f065e7320e2cdc9c8ea8e1acaf085995e9f777cf770a2ee71e655");

pub const MAIN_DERIVATION_PATH: Vec<ByteBuf> = vec![];

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum InvalidEventReason {
    /// Deposit is invalid and was never minted.
    /// This is most likely due to a user error (e.g., user's IC principal cannot be decoded)
    /// or there is a critical issue in the logs returned from the JSON-RPC providers.
    InvalidDeposit(String),

    /// Deposit is valid but it's unknown whether it was minted or not,
    /// most likely because there was an unexpected panic in the callback.
    /// The deposit is quarantined to avoid any double minting and
    /// will not be further processed without manual intervention.
    QuarantinedDeposit,
}

impl Display for InvalidEventReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidEventReason::InvalidDeposit(reason) => {
                write!(f, "Invalid deposit: {}", reason)
            }
            InvalidEventReason::QuarantinedDeposit => {
                write!(f, "Quarantined deposit")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintedEvent {
    pub deposit_event: ReceivedDepositEvent,
    pub mint_block_index: LedgerMintIndex,
    pub token_symbol: String,
    pub erc20_contract_address: Option<Address>,
}

impl MintedEvent {
    pub fn source(&self) -> EventSource {
        self.deposit_event.source()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct State {
    pub evm_network: EvmNetwork,
    pub ecdsa_key_name: String,
    pub native_ledger_id: Principal,
    pub native_symbol: ERC20TokenSymbol,
    pub helper_contract_address: Option<Address>,

    // Principal id of EVM_RPC_CANISTER
    pub evm_canister_id: Principal,
    pub ecdsa_public_key: Option<EcdsaPublicKeyResponse>,
    // pub cketh_minimum_withdrawal_amount: Wei,
    pub block_height: BlockTag,
    pub first_scraped_block_number: BlockNumber,
    pub last_scraped_block_number: BlockNumber,
    pub last_observed_block_number: Option<BlockNumber>,
    pub events_to_mint: BTreeMap<EventSource, ReceivedDepositEvent>,
    pub minted_events: BTreeMap<EventSource, MintedEvent>,
    pub invalid_events: BTreeMap<EventSource, InvalidEventReason>,

    pub withdrawal_transactions: WithdrawalTransactions,
    pub skipped_blocks: BTreeSet<BlockNumber>,

    // Current balance of Native held by the minter.
    // Computed based on audit events.
    pub native_balance: NativeBalance,

    // Current balance of ERC-20 tokens held by the minter.
    // Computed based on audit events.
    pub erc20_balances: Erc20Balances,

    // /// Per-principal lock for pending withdrawals
    pub pending_withdrawal_principals: BTreeSet<Principal>,

    /// Locks preventing concurrent execution timer tasks
    pub active_tasks: HashSet<TaskType>,
    /// Number of HTTP outcalls since the last upgrade.
    /// Used to correlate request and response in logs.
    // pub http_request_counter: u64,
    pub last_transaction_price_estimate: Option<(u64, GasFeeEstimate)>,

    // /// Canister ID of the ledger suite orchestrator that
    // /// can add new ERC-20 token to the minter
    // pub ledger_suite_orchestrator_id: Option<Principal>,

    // /// Canister ID of the EVM RPC canister that
    // /// handles communication with Ethereum
    // pub evm_rpc_id: Option<Principal>,
    /// ERC-20 tokens that the minter can mint:
    /// - primary key: ledger ID for the ERC20 token
    /// - secondary key: ERC-20 contract address on Ethereum
    /// - value: ERC20 token symbol
    pub erc20_tokens: DedupMultiKeyMap<Principal, Address, ERC20TokenSymbol>,

    pub min_max_priority_fee_per_gas: WeiPerGas,
}

impl State {
    // Returns the blockcheight
    pub const fn block_height(&self) -> BlockTag {
        self.block_height
    }

    pub const fn evm_network(&self) -> EvmNetwork {
        self.evm_network
    }

    pub fn max_block_spread_for_logs_scraping(&self) -> u16 {
        // Limit set by the EVM-RPC canister itself, see
        // https://github.com/internet-computer-protocol/evm-rpc-canister/blob/3cce151d4c1338d83e6741afa354ccf11dff41e8/src/candid_rpc.rs#L192
        500_u16
    }

    fn record_event_to_mint(&mut self, event: &ReceivedDepositEvent) {
        let event_source = event.source();
        assert!(
            !self.events_to_mint.contains_key(&event_source),
            "there must be no two different events with the same source"
        );
        assert!(!self.minted_events.contains_key(&event_source));
        assert!(!self.invalid_events.contains_key(&event_source));
        if let ReceivedDepositEvent::Erc20(event) = event {
            assert!(
                self.erc20_tokens
                    .contains_alt(&event.erc20_contract_address),
                "BUG: unsupported ERC-20 contract address in event {event:?}"
            )
        }

        self.events_to_mint.insert(event_source, event.clone());

        self.update_balance_upon_deposit(event)
    }

    pub fn has_events_to_mint(&self) -> bool {
        !self.events_to_mint.is_empty()
    }

    fn record_invalid_deposit(&mut self, source: EventSource, error: String) -> bool {
        assert!(
            !self.events_to_mint.contains_key(&source),
            "attempted to mark an accepted event as invalid"
        );
        assert!(
            !self.minted_events.contains_key(&source),
            "attempted to mark a minted event {source:?} as invalid"
        );

        match self.invalid_events.entry(source) {
            btree_map::Entry::Occupied(_) => false,
            btree_map::Entry::Vacant(entry) => {
                entry.insert(InvalidEventReason::InvalidDeposit(error));
                true
            }
        }
    }

    pub fn record_skipped_block(&mut self, block_number: BlockNumber) {
        assert!(
            self.skipped_blocks.insert(block_number),
            "BUG: block {} was already skipped ",
            block_number,
        );
    }

    fn update_balance_upon_deposit(&mut self, event: &ReceivedDepositEvent) {
        match event {
            ReceivedDepositEvent::Native(event) => self.native_balance.eth_balance_add(event.value),
            ReceivedDepositEvent::Erc20(event) => self
                .erc20_balances
                .erc20_add(event.erc20_contract_address, event.value),
        };
    }
}
pub fn read_state<R>(f: impl FnOnce(&State) -> R) -> R {
    STATE.with(|s| f(s.borrow().as_ref().expect("BUG: state is not initialized")))
}

/// Mutates (part of) the current state using `f`.
///
/// Panics if there is no state.
pub fn mutate_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut State) -> R,
{
    STATE.with(|s| {
        f(s.borrow_mut()
            .as_mut()
            .expect("BUG: state is not initialized"))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBalance {
    /// Amount of ETH controlled by the minter's address via tECDSA.
    /// Note that invalid deposits are not accounted for and so this value
    /// might be less than what is displayed by Etherscan
    /// or retrieved by the JSON-RPC call `eth_getBalance`.
    /// Also, some transactions may have gone directly to the minter's address
    /// without going via the helper smart contract.
    native_balance: Wei,
    /// Total amount of fees across all finalized transactions icNative -> Native. cconversion of twin native token to token on the home chain.
    total_effective_tx_fees: Wei,
    /// Total amount of fees that were charged to the user during the withdrawal
    /// but not consumed by the finalized transaction icNative -> Native. cconversion of twin native token to token on the home chain.
    total_unspent_tx_fees: Wei,
}

impl Default for NativeBalance {
    fn default() -> Self {
        Self {
            native_balance: Wei::ZERO,
            total_effective_tx_fees: Wei::ZERO,
            total_unspent_tx_fees: Wei::ZERO,
        }
    }
}

impl NativeBalance {
    fn eth_balance_add(&mut self, value: Wei) {
        self.native_balance = self.native_balance.checked_add(value).unwrap_or_else(|| {
            panic!(
                "BUG: overflow when adding {} to {}",
                value, self.native_balance
            )
        })
    }

    fn eth_balance_sub(&mut self, value: Wei) {
        self.native_balance = self.native_balance.checked_sub(value).unwrap_or_else(|| {
            panic!(
                "BUG: underflow when subtracting {} from {}",
                value, self.native_balance
            )
        })
    }

    fn total_effective_tx_fees_add(&mut self, value: Wei) {
        self.total_effective_tx_fees = self
            .total_effective_tx_fees
            .checked_add(value)
            .unwrap_or_else(|| {
                panic!(
                    "BUG: overflow when adding {} to {}",
                    value, self.total_effective_tx_fees
                )
            })
    }

    fn total_unspent_tx_fees_add(&mut self, value: Wei) {
        self.total_unspent_tx_fees = self
            .total_unspent_tx_fees
            .checked_add(value)
            .unwrap_or_else(|| {
                panic!(
                    "BUG: overflow when adding {} to {}",
                    value, self.total_unspent_tx_fees
                )
            })
    }

    pub fn native_balance(&self) -> Wei {
        self.native_balance
    }

    pub fn total_effective_tx_fees(&self) -> Wei {
        self.total_effective_tx_fees
    }

    pub fn total_unspent_tx_fees(&self) -> Wei {
        self.total_unspent_tx_fees
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Erc20Balances {
    balance_by_erc20_contract: BTreeMap<Address, Erc20Value>,
}

impl Erc20Balances {
    pub fn balance_of(&self, erc20_contract: &Address) -> Erc20Value {
        *self
            .balance_by_erc20_contract
            .get(erc20_contract)
            .unwrap_or(&Erc20Value::ZERO)
    }

    pub fn erc20_add(&mut self, erc20_contract: Address, deposit: Erc20Value) {
        match self.balance_by_erc20_contract.get(&erc20_contract) {
            Some(previous_value) => {
                let new_value = previous_value.checked_add(deposit).unwrap_or_else(|| {
                    panic!(
                        "BUG: overflow when adding {} to {}",
                        deposit, previous_value
                    )
                });
                self.balance_by_erc20_contract
                    .insert(erc20_contract, new_value);
            }
            None => {
                self.balance_by_erc20_contract
                    .insert(erc20_contract, deposit);
            }
        }
    }

    pub fn erc20_sub(&mut self, erc20_contract: Address, withdrawal_amount: Erc20Value) {
        let previous_value = self
            .balance_by_erc20_contract
            .get(&erc20_contract)
            .expect("BUG: Cannot subtract from a missing ERC-20 balance");
        let new_value = previous_value
            .checked_sub(withdrawal_amount)
            .unwrap_or_else(|| {
                panic!(
                    "BUG: underflow when subtracting {} from {}",
                    withdrawal_amount, previous_value
                )
            });
        self.balance_by_erc20_contract
            .insert(erc20_contract, new_value);
    }
}

#[derive(Debug, Hash, Copy, Clone, PartialEq, Eq)]
pub enum TaskType {
    Mint,
    RetrieveEth,
    ScrapLogs,
    RefreshGasFeeEstimate,
    Reimbursement,
    // MintCkErc20,
}

pub async fn lazy_call_ecdsa_public_key() -> PublicKey {
    use ic_cdk::api::management_canister::ecdsa::{
        ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    };

    fn to_public_key(response: &EcdsaPublicKeyResponse) -> PublicKey {
        PublicKey::deserialize_sec1(&response.public_key).unwrap_or_else(|e| {
            ic_cdk::trap(&format!("failed to decode minter's public key: {:?}", e))
        })
    }

    if let Some(ecdsa_pk_response) = read_state(|s| s.ecdsa_public_key.clone()) {
        return to_public_key(&ecdsa_pk_response);
    }
    let key_name = read_state(|s| s.ecdsa_key_name.clone());
    log!(DEBUG, "Fetching the ECDSA public key {key_name}");
    let (response,) = ecdsa_public_key(EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: MAIN_DERIVATION_PATH
            .into_iter()
            .map(|x| x.to_vec())
            .collect(),
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name,
        },
    })
    .await
    .unwrap_or_else(|(error_code, message)| {
        ic_cdk::trap(&format!(
            "failed to get minter's public key: {} (error code = {:?})",
            message, error_code,
        ))
    });
    mutate_state(|s| s.ecdsa_public_key = Some(response.clone()));
    to_public_key(&response)
}

pub async fn minter_address() -> Address {
    ecdsa_public_key_to_address(&lazy_call_ecdsa_public_key().await)
}
