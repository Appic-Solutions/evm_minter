use crate::endpoints::CandidBlockTag;
use crate::erc20::ERC20TokenSymbol;
use crate::eth_types::Address;
use crate::evm_config::EvmNetwork;
use crate::numeric::{BlockNumber, TransactionNonce, Wei, WeiPerGas, WeiPerGasUnit};
use crate::rpc_declrations::BlockTag;
use crate::state::transactions::WithdrawalTransactions;
use crate::state::{InvalidStateError, State};
use candid::types::number::Nat;
use candid::types::principal::Principal;
use candid::{CandidType, Deserialize};
use minicbor::{Decode, Encode};

#[derive(CandidType, Deserialize, Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct InitArg {
    #[n(0)]
    pub evm_network: EvmNetwork,
    #[n(1)]
    pub ecdsa_key_name: String,
    #[n(2)]
    pub helper_contract_address: Option<String>,
    #[cbor(n(3), with = "crate::cbor::principal")]
    pub native_ledger_id: Principal,
    #[n(4)]
    pub native_symbol: String,
    #[n(5)]
    pub block_height: CandidBlockTag,
    #[cbor(n(6), with = "crate::cbor::nat")]
    pub native_minimum_withdrawal_amount: Nat,
    #[cbor(n(7), with = "crate::cbor::nat")]
    pub native_ledger_transfer_fee: Nat,
    #[cbor(n(8), with = "crate::cbor::nat")]
    pub next_transaction_nonce: Nat,
    #[cbor(n(9), with = "crate::cbor::nat")]
    pub last_scraped_block_number: Nat,
    #[cbor(n(10), with = "crate::cbor::nat")]
    pub min_max_priority_fee_per_gas: Nat,
}

impl TryFrom<InitArg> for State {
    type Error = InvalidStateError;
    fn try_from(
        InitArg {
            evm_network,
            ecdsa_key_name,
            helper_contract_address,
            native_ledger_id,
            native_symbol,
            block_height,
            native_minimum_withdrawal_amount,
            native_ledger_transfer_fee,
            next_transaction_nonce,
            last_scraped_block_number,
            min_max_priority_fee_per_gas,
        }: InitArg,
    ) -> Result<Self, Self::Error> {
        use std::str::FromStr;

        let initial_nonce = TransactionNonce::try_from(next_transaction_nonce)
            .map_err(|e| InvalidStateError::InvalidTransactionNonce(format!("ERROR: {}", e)))?;
        let native_minimum_withdrawal_amount = Wei::try_from(native_minimum_withdrawal_amount)
            .map_err(|e| {
                InvalidStateError::InvalidMinimumWithdrawalAmount(format!("ERROR: {}", e))
            })?;
        let native_ledger_transfer_fee =
            Wei::try_from(native_ledger_transfer_fee).map_err(|e| {
                InvalidStateError::InvalidMinimumLedgerTransferFee(format!("ERROR: {}", e))
            })?;
        let native_symbol = ERC20TokenSymbol::new(native_symbol);
        let helper_contract_address = helper_contract_address
            .map(|a| Address::from_str(&a))
            .transpose()
            .map_err(|e| {
                InvalidStateError::InvalidHelperContractAddress(format!("ERROR: {}", e))
            })?;
        let last_scraped_block_number =
            BlockNumber::try_from(last_scraped_block_number).map_err(|e| {
                InvalidStateError::InvalidLastScrapedBlockNumber(format!("ERROR: {}", e))
            })?;
        let min_max_priority_fee_per_gas: WeiPerGas =
            WeiPerGas::try_from(min_max_priority_fee_per_gas).map_err(|e| {
                InvalidStateError::InvalidMinimumMaximumPriorityFeePerGas(format!("ERROR: {}", e))
            })?;
        let first_scraped_block_number =
            last_scraped_block_number
                .checked_increment()
                .ok_or_else(|| {
                    InvalidStateError::InvalidLastScrapedBlockNumber(
                        "ERROR: last_scraped_block_number is at maximum value".to_string(),
                    )
                })?;
        let state = Self {
            evm_network,
            ecdsa_key_name,
            helper_contract_address,
            pending_withdrawal_principals: Default::default(),
            native_symbol,
            withdrawal_transactions: WithdrawalTransactions::new(initial_nonce),
            native_ledger_id,
            native_ledger_transfer_fee,
            native_minimum_withdrawal_amount,
            block_height: BlockTag::from(block_height),
            first_scraped_block_number,
            last_scraped_block_number,
            last_observed_block_number: None,
            events_to_mint: Default::default(),
            minted_events: Default::default(),
            ecdsa_public_key: None,
            invalid_events: Default::default(),
            native_balance: Default::default(),
            skipped_blocks: Default::default(),
            active_tasks: Default::default(),
            last_transaction_price_estimate: None,
            erc20_tokens: Default::default(),
            erc20_balances: Default::default(),
            evm_canister_id: Principal::from_slice(&[0_u8, 0, 0, 0, 2, 48, 0, 204, 1, 1]),
            min_max_priority_fee_per_gas,
        };
        state.validate_config()?;
        Ok(state)
    }
}
