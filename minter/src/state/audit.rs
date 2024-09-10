// #[cfg(test)]
// mod tests;

pub use super::event::{Event, EventType};
use super::{
    transactions::{Reimbursed, ReimbursementIndex},
    State,
};
// use crate::erc20::CkTokenSymbol;
// use crate::state::transactions::{Reimbursed, ReimbursementIndex};
use crate::{
    erc20::ERC20TokenSymbol,
    storage::{record_event, with_event_iter},
};

/// Updates the state to reflect the given state transition.
// public because it's used in tests since process_event
// requires canister infrastructure to retrieve time
pub fn apply_state_transition(state: &mut State, payload: &EventType) {
    match payload {
        EventType::Init(init_arg) => {
            panic!("state re-initialization is not allowed: {init_arg:?}");
        }
        EventType::Upgrade(upgrade_arg) => {
            state
                .upgrade(upgrade_arg.clone())
                .expect("applying upgrade event should succeed");
        }
        EventType::AcceptedDeposit(native_event) => {
            state.record_event_to_mint(&native_event.clone().into());
        }
        EventType::AcceptedErc20Deposit(erc20_event) => {
            state.record_event_to_mint(&erc20_event.clone().into());
        }
        EventType::InvalidDeposit {
            event_source,
            reason,
        } => {
            let _ = state.record_invalid_deposit(*event_source, reason.clone());
        }
        EventType::MintedNative {
            event_source,
            mint_block_index,
        } => {
            state.record_successful_mint(
                *event_source,
                &state.native_symbol.to_string(),
                *mint_block_index,
                None,
            );
        }
        EventType::MintedErc20 {
            event_source,
            mint_block_index,
            erc20_token_symbol,
            erc20_contract_address,
        } => {
            state.record_successful_mint(
                *event_source,
                erc20_token_symbol,
                *mint_block_index,
                Some(*erc20_contract_address),
            );
        }
        EventType::SyncedToBlock { block_number } => {
            state.last_scraped_block_number = *block_number;
        }
        EventType::AcceptedNativeWithdrawalRequest(request) => {
            state
                .withdrawal_transactions
                .record_withdrawal_request(request.clone());
        }
        EventType::CreatedTransaction {
            withdrawal_id,
            transaction,
        } => {
            state
                .withdrawal_transactions
                .record_created_transaction(*withdrawal_id, transaction.clone());
        }
        EventType::SignedTransaction {
            withdrawal_id: _,
            transaction,
        } => {
            state
                .withdrawal_transactions
                .record_signed_transaction(transaction.clone());
        }
        EventType::ReplacedTransaction {
            withdrawal_id: _,
            transaction,
        } => {
            state
                .withdrawal_transactions
                .record_resubmit_transaction(transaction.clone());
        }
        EventType::FinalizedTransaction {
            withdrawal_id,
            transaction_receipt,
        } => {
            state.record_finalized_transaction(withdrawal_id, transaction_receipt);
        }
        EventType::ReimbursedNativeWithdrawal(Reimbursed {
            burn_in_block: withdrawal_id,
            reimbursed_in_block,
            reimbursed_amount: _,
            transaction_hash: _,
        }) => {
            state
                .withdrawal_transactions
                .record_finalized_reimbursement(
                    ReimbursementIndex::Native {
                        ledger_burn_index: *withdrawal_id,
                    },
                    *reimbursed_in_block,
                );
        }
        EventType::SkippedBlock { block_number } => {
            state.record_skipped_block(*block_number);
        } // EventType::AddedCkErc20Token(ckerc20_token) => {
        //     state.record_add_ckerc20_token(ckerc20_token.clone());
        // }
        EventType::AcceptedErc20WithdrawalRequest(request) => {
            state.record_erc20_withdrawal_request(request.clone())
        }
        EventType::ReimbursedErc20Withdrawal {
            native_ledger_burn_index,
            erc20_ledger_id,
            reimbursed,
        } => {
            state
                .withdrawal_transactions
                .record_finalized_reimbursement(
                    ReimbursementIndex::Erc20 {
                        native_ledger_burn_index: *native_ledger_burn_index,
                        ledger_id: *erc20_ledger_id,
                        erc20_ledger_burn_index: reimbursed.burn_in_block,
                    },
                    reimbursed.reimbursed_in_block,
                );
        }
        EventType::FailedErc20WithdrawalRequest(native_reimbursement_request) => {
            state.withdrawal_transactions.record_reimbursement_request(
                ReimbursementIndex::Native {
                    ledger_burn_index: native_reimbursement_request.ledger_burn_index,
                },
                native_reimbursement_request.clone(),
            )
        }
        EventType::QuarantinedDeposit { event_source } => {
            state.record_quarantined_deposit(*event_source);
        }
        EventType::QuarantinedReimbursement { index } => {
            state
                .withdrawal_transactions
                .record_quarantined_reimbursement(index.clone());
        }
    }
}

/// Records the given event payload in the event log and updates the state to reflect the change.
pub fn process_event(state: &mut State, payload: EventType) {
    apply_state_transition(state, &payload);
    record_event(payload);
}

/// Recomputes the minter state from the event log.
///
/// # Panics
///
/// This function panics if:
///   * The event log is empty.
///   * The first event in the log is not an Init event.
///   * One of the events in the log invalidates the minter's state invariants.
pub fn replay_events() -> State {
    with_event_iter(|iter| replay_events_internal(iter))
}

fn replay_events_internal<T: IntoIterator<Item = Event>>(events: T) -> State {
    let mut events_iter = events.into_iter();
    let mut state = match events_iter
        .next()
        .expect("the event log should not be empty")
    {
        Event {
            payload: EventType::Init(init_arg),
            ..
        } => State::try_from(init_arg).expect("state initialization should succeed"),
        other => panic!("the first event must be an Init event, got: {other:?}"),
    };
    for event in events_iter {
        apply_state_transition(&mut state, &event.payload);
    }
    state
}
