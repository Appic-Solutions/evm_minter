use std::cmp::{min, Ordering};
use std::time::Duration;

use ic_canister_log::log;
use icrc_ledger_types::icrc1::account::Account;
use scopeguard::ScopeGuard;

use crate::checked_amount::CheckedAmountOf;
use crate::deposit_logs::{
    report_transaction_error, ReceivedDepositEvent, ReceivedDepsitEventError,
};
use crate::eth_types::Address;
use crate::evm_config::EvmNetwork;
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::{BlockNumber, BlockNumberTag, LedgerMintIndex};
use crate::rpc_client::{is_response_too_large, RpcClient};
use crate::rpc_declrations::BlockSpec;
use crate::state::audit::{process_event, EventType};
use crate::state::{
    mutate_state, read_state, State, TaskType, RECEIVED_DEPOSITED_TOKEN_EVENT_TOPIC,
};
use num_traits::ToPrimitive;
async fn mint() {
    use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
    use icrc_ledger_types::icrc1::transfer::TransferArg;

    let _guard = match TimerGuard::new(TaskType::Mint) {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let (eth_ledger_canister_id, events) = read_state(|s| (s.native_ledger_id, s.events_to_mint()));
    let mut error_count = 0;

    for event in events {
        // Ensure that even if we were to panic in the callback, after having contacted the ledger to mint the tokens,
        // this event will not be processed again.
        let prevent_double_minting_guard = scopeguard::guard(event.clone(), |event| {
            mutate_state(|s| {
                process_event(
                    s,
                    EventType::QuarantinedDeposit {
                        event_source: event.source(),
                    },
                )
            });
        });
        let (token_symbol, ledger_canister_id) = match &event {
            ReceivedDepositEvent::Native(_) => ("Native".to_string(), eth_ledger_canister_id),
            ReceivedDepositEvent::Erc20(event) => {
                if let Some(result) = read_state(|s| {
                    s.erc20_tokens
                        .get_entry_alt(&event.erc20_contract_address)
                        .map(|(principal, symbol)| (symbol.to_string(), *principal))
                }) {
                    result
                } else {
                    panic!(
                        "Failed to mint ERC20: {event:?} Unsupported ERC20 contract address. (This should have already been filtered out by process_event)"
                    )
                }
            }
        };
        let client = ICRC1Client {
            runtime: CdkRuntime,
            ledger_canister_id,
        };
        let block_index = match client
            .transfer(TransferArg {
                from_subaccount: None,
                to: Account {
                    owner: event.principal(),
                    subaccount: event.subaccount(),
                },
                fee: None,
                created_at_time: None,
                memo: Some((&event).into()),
                amount: event.value(),
            })
            .await
        {
            Ok(Ok(block_index)) => block_index.0.to_u64().expect("nat does not fit into u64"),
            Ok(Err(err)) => {
                log!(INFO, "Failed to mint {token_symbol}: {event:?} {err}");
                error_count += 1;
                // minting failed, defuse guard
                ScopeGuard::into_inner(prevent_double_minting_guard);
                continue;
            }
            Err(err) => {
                log!(
                    INFO,
                    "Failed to send a message to the ledger ({ledger_canister_id}): {err:?}"
                );
                error_count += 1;
                // minting failed, defuse guard
                ScopeGuard::into_inner(prevent_double_minting_guard);
                continue;
            }
        };
        mutate_state(|s| {
            process_event(
                s,
                match &event {
                    ReceivedDepositEvent::Native(event) => EventType::MintedNative {
                        event_source: event.source(),
                        mint_block_index: LedgerMintIndex::new(block_index),
                    },

                    ReceivedDepositEvent::Erc20(event) => EventType::MintedErc20 {
                        event_source: event.source(),
                        mint_block_index: LedgerMintIndex::new(block_index),
                        erc20_contract_address: event.erc20_contract_address,
                        erc20_token_symbol: token_symbol.clone(),
                    },
                },
            )
        });
        log!(
            INFO,
            "Minted {} {token_symbol} to {} in block {block_index}",
            event.value(),
            event.principal()
        );
        // minting succeeded, defuse guard
        ScopeGuard::into_inner(prevent_double_minting_guard);
    }

    if error_count > 0 {
        log!(
            INFO,
            "Failed to mint {error_count} events, rescheduling the minting"
        );
        ic_cdk_timers::set_timer(crate::MINT_RETRY_DELAY, || ic_cdk::spawn(mint()));
    }
}

/// Scraps Deposit logs between `from` and `min(from + MAX_BLOCK_SPREAD, to)` since certain RPC providers
/// require that the number of blocks queried is no greater than MAX_BLOCK_SPREAD.
/// Returns the last block number that was scraped (which is `min(from + MAX_BLOCK_SPREAD, to)`) if there
/// was no error when querying the providers, otherwise returns `None`.
async fn scrape_logs_range_inclusive<F>(
    topic: &[u8; 32],
    helper_contract_address: Address,
    token_contract_addresses: &[Address],
    from: BlockNumber,
    to: BlockNumber,
    max_block_spread: u16,
    update_last_scraped_block_number: &F,
) -> Option<BlockNumber>
where
    F: Fn(BlockNumber),
{
    match from.cmp(&to) {
        Ordering::Less | Ordering::Equal => {
            let max_to = from
                .checked_add(BlockNumber::from(max_block_spread))
                .unwrap_or(BlockNumber::MAX);
            let mut last_block_number = min(max_to, to);
            log!(
                DEBUG,
                "Scrapping logs from block {:?} to block {:?}...",
                from,
                last_block_number
            );

            let (transaction_events, errors) = loop {
                match crate::deposit_logs::last_received_deposit_events(
                    topic,
                    helper_contract_address,
                    token_contract_addresses,
                    from,
                    last_block_number,
                )
                .await
                {
                    Ok((events, errors)) => break (events, errors),
                    Err(e) => {
                        log!(
                        INFO,
                        "Failed to get logs from block {from} to block {last_block_number}: {e:?}",
                    );
                        if e.has_http_outcall_error_matching(is_response_too_large) {
                            if from == last_block_number {
                                mutate_state(|s| {
                                    process_event(
                                        s,
                                        EventType::SkippedBlock {
                                            block_number: last_block_number,
                                        },
                                    );
                                });
                                update_last_scraped_block_number(last_block_number);
                                return Some(last_block_number);
                            } else {
                                let new_last_block_number = from
                                    .checked_add(last_block_number
                                            .checked_sub(from)
                                            .expect("last_scraped_block_number is greater or equal than from")
                                            .div_by_two())
                                    .expect("must be less than last_scraped_block_number");
                                log!(INFO, "Too many logs received in range [{from}, {last_block_number}]. Will retry with range [{from}, {new_last_block_number}]");
                                last_block_number = new_last_block_number;
                                continue;
                            }
                        }
                        return None;
                    }
                };
            };

            for event in transaction_events {
                log!(
                    INFO,
                    "Received event {event:?}; will mint {} to {}",
                    event.value(),
                    event.principal()
                );

                mutate_state(|s| process_event(s, event.into_deposit()));
            }
            if read_state(State::has_events_to_mint) {
                ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(mint()));
            }
            for error in errors {
                if let ReceivedDepsitEventError::InvalidEventSource { source, error } = &error {
                    mutate_state(|s| {
                        process_event(
                            s,
                            EventType::InvalidDeposit {
                                event_source: *source,
                                reason: error.to_string(),
                            },
                        )
                    });
                }
                report_transaction_error(error);
            }
            update_last_scraped_block_number(last_block_number);
            Some(last_block_number)
        }
        Ordering::Greater => {
            ic_cdk::trap(&format!(
                "BUG: last scraped block number ({:?}) is greater than the last queried block number ({:?})",
                from, to
            ));
        }
    }
}

async fn scrape_contract_logs<F>(
    topic: &[u8; 32],
    helper_contract_address: Option<Address>,
    token_contract_addresses: &[Address],
    last_block_number: BlockNumber,
    mut last_scraped_block_number: BlockNumber,
    max_block_spread: u16,
    update_last_scraped_block_number: F,
) where
    F: Fn(BlockNumber),
{
    let helper_contract_address = match helper_contract_address {
        Some(address) => address,
        None => {
            log!(
                DEBUG,
                "[scrape_contract_logs]: skipping scrapping logs: no contract address"
            );
            return;
        }
    };

    while last_scraped_block_number < last_block_number {
        let next_block_to_query = last_scraped_block_number
            .checked_increment()
            .unwrap_or(BlockNumber::MAX);
        last_scraped_block_number = match scrape_logs_range_inclusive(
            topic,
            helper_contract_address,
            token_contract_addresses,
            next_block_to_query,
            last_block_number,
            max_block_spread,
            &update_last_scraped_block_number,
        )
        .await
        {
            Some(last_scraped_block_number) => last_scraped_block_number,
            None => {
                return;
            }
        };
    }
}

pub async fn scrape_logs() {
    let _guard = match TimerGuard::new(TaskType::ScrapLogs) {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let last_block_number = match update_last_observed_block_number().await {
        Some(block_number) => block_number,
        None => {
            log!(
                DEBUG,
                "[scrape_logs]: skipping scrapping logs: no last observed block number"
            );
            return;
        }
    };
    let max_block_spread = read_state(|s| s.max_block_spread_for_logs_scraping());

    let token_contract_addresses =
        read_state(|s| s.erc20_tokens.alt_keys().cloned().collect::<Vec<_>>());
    if token_contract_addresses.is_empty() {
        log!(
            DEBUG,
            "[scrape_contract_logs]: skipping scrapping ERC-20 logs: no token contract address"
        );
        return;
    }
    scrape_contract_logs(
        &RECEIVED_DEPOSITED_TOKEN_EVENT_TOPIC,
        read_state(|s| s.helper_contract_address),
        &token_contract_addresses,
        last_block_number,
        read_state(|s| s.last_scraped_block_number),
        max_block_spread,
        &|last_block_number| mutate_state(|s| s.last_scraped_block_number = last_block_number),
    )
    .await
}

// Updates last_observed_block_number in the state.
pub async fn update_last_observed_block_number() -> Option<BlockNumber> {
    let block_height = read_state(State::block_height);
    let network = read_state(|state| state.evm_network);
    match read_state(RpcClient::from_state_one_provider)
        .get_block_by_number(BlockSpec::Tag(block_height))
        .await
    {
        Ok(latest_block) => {
            let mut block_number = Some(latest_block.number);
            match network {
                EvmNetwork::BSC => {
                    // Waiting for 20 blocks means the transaction is practically safe on BSC
                    // So we go 15 blocks before the latest block
                    block_number = latest_block.number.checked_sub(
                        BlockNumber::try_from(20_u32)
                            .expect("Removing 15 blocks from latest block shouldnever fails"),
                    )
                }
                EvmNetwork::ArbitrumOne => {
                    // it's generally recommended to wait for at least 6-12 blocks after a block is initially produced before
                    // considering it to be finalized and safe from reorgs. This waiting period provides a buffer to account for potential fork scenarios
                    //  or other unexpected events.
                    block_number = latest_block.number.checked_sub(
                        BlockNumber::try_from(12_u32)
                            .expect("Removing 15 blocks from latest block shouldnever fails"),
                    )
                }
                EvmNetwork::Base => {
                    // like Arbitrum, it's recommended to wait for a few blocks after a transaction is included in a block
                    // to ensure finality and minimize the risk of reorgs. A waiting period of 6-12 blocks is
                    // typically considered sufficient for most applications.

                    block_number = latest_block.number.checked_sub(
                        BlockNumber::try_from(12_u32)
                            .expect("Removing 15 blocks from latest block shouldnever fails"),
                    )
                }
                EvmNetwork::Optimism => {
                    // Similar to the other layer-2 networks, it's recommended to wait for a few blocks after a transaction is included in a block to
                    // ensure finality and minimize the risk of reorgs. A waiting period of 6-12 blocks is typically considered sufficient.

                    block_number = latest_block.number.checked_sub(
                        BlockNumber::try_from(12_u32)
                            .expect("Removing 15 blocks from latest block shouldnever fails"),
                    )
                }
                EvmNetwork::Avalanche => {
                    // If your application deals with extremely high-value transactions or sensitive data,
                    // you might want to consider waiting for a slightly longer period, such as 12 blocks.
                    // This can provide an additional layer of security, especially if you're dealing with particularly critical transactions.

                    block_number = latest_block.number.checked_sub(
                        BlockNumber::try_from(12_u32)
                            .expect("Removing 15 blocks from latest block shouldnever fails"),
                    )
                }

                EvmNetwork::Fantom => {
                    // If your application deals with extremely high-value transactions or sensitive data,
                    // you might want to consider waiting for a slightly longer period, such as 12 blocks.
                    // This can provide an additional layer of security, especially if you're dealing with particularly critical transactions.

                    block_number = latest_block.number.checked_sub(
                        BlockNumber::try_from(12_u32)
                            .expect("Removing 15 blocks from latest block shouldnever fails"),
                    )
                }

                // For the rest of the networks we rely on BlockTag::Finalized, So we can make sure that there wont be any reorgs
                _ => {}
            }
            mutate_state(|s| s.last_observed_block_number = block_number);
            block_number
        }
        Err(e) => {
            log!(
                INFO,
                "Failed to get the latest {block_height} block number: {e:?}"
            );
            read_state(|s| s.last_observed_block_number)
        }
    }
}
