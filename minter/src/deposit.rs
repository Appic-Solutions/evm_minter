use std::cmp::{min, Ordering};

use ic_canister_log::log;

use crate::eth_types::Address;
use crate::guard::TimerGuard;
use crate::logs::{DEBUG, INFO};
use crate::numeric::BlockNumber;
use crate::rpc_client::RpcClient;
use crate::rpc_declrations::BlockSpec;
use crate::state::{mutate_state, read_state, State, TaskType};

/// Scraps Ethereum logs between `from` and `min(from + MAX_BLOCK_SPREAD, to)` since certain RPC providers
/// require that the number of blocks queried is no greater than MAX_BLOCK_SPREAD.
/// Returns the last block number that was scraped (which is `min(from + MAX_BLOCK_SPREAD, to)`) if there
/// was no error when querying the providers, otherwise returns `None`.
// async fn scrape_logs_range_inclusive<F>(
//     topic: &[u8; 32],
//     topic_name: &str,
//     helper_contract_address: Address,
//     token_contract_addresses: &[Address],
//     from: BlockNumber,
//     to: BlockNumber,
//     max_block_spread: u16,
//     update_last_scraped_block_number: &F,
// ) -> Option<BlockNumber>
// where
//     F: Fn(BlockNumber),
// {
//     match from.cmp(&to) {
//         Ordering::Less | Ordering::Equal => {
//             let max_to = from
//                 .checked_add(BlockNumber::from(max_block_spread))
//                 .unwrap_or(BlockNumber::MAX);
//             let mut last_block_number = min(max_to, to);
//             log!(
//                 DEBUG,
//                 "Scrapping {topic_name} logs from block {:?} to block {:?}...",
//                 from,
//                 last_block_number
//             );

//             let (transaction_events, errors) = loop {
//                 match crate::eth_logs::last_received_events(
//                     topic,
//                     helper_contract_address,
//                     token_contract_addresses,
//                     from,
//                     last_block_number,
//                 )
//                 .await
//                 {
//                     Ok((events, errors)) => break (events, errors),
//                     Err(e) => {
//                         log!(
//                         INFO,
//                         "Failed to get {topic_name} logs from block {from} to block {last_block_number}: {e:?}",
//                     );
//                         if e.has_http_outcall_error_matching(
//                             HttpOutcallError::is_response_too_large,
//                         ) {
//                             if from == last_block_number {
//                                 mutate_state(|s| {
//                                     process_event(
//                                         s,
//                                         EventType::SkippedBlockForContract {
//                                             contract_address: helper_contract_address,
//                                             block_number: last_block_number,
//                                         },
//                                     );
//                                 });
//                                 update_last_scraped_block_number(last_block_number);
//                                 return Some(last_block_number);
//                             } else {
//                                 let new_last_block_number = from
//                                     .checked_add(last_block_number
//                                             .checked_sub(from)
//                                             .expect("last_scraped_block_number is greater or equal than from")
//                                             .div_by_two())
//                                     .expect("must be less than last_scraped_block_number");
//                                 log!(INFO, "Too many logs received in range [{from}, {last_block_number}]. Will retry with range [{from}, {new_last_block_number}]");
//                                 last_block_number = new_last_block_number;
//                                 continue;
//                             }
//                         }
//                         return None;
//                     }
//                 };
//             };

//             for event in transaction_events {
//                 log!(
//                     INFO,
//                     "Received event {event:?}; will mint {} {topic_name} to {}",
//                     event.value(),
//                     event.principal()
//                 );
//                 if crate::blocklist::is_blocked(&event.from_address()) {
//                     log!(
//                         INFO,
//                         "Received event from a blocked address: {} for {} {topic_name}",
//                         event.from_address(),
//                         event.value(),
//                     );
//                     mutate_state(|s| {
//                         process_event(
//                             s,
//                             EventType::InvalidDeposit {
//                                 event_source: event.source(),
//                                 reason: format!("blocked address {}", event.from_address()),
//                             },
//                         )
//                     });
//                 } else {
//                     mutate_state(|s| process_event(s, event.into_deposit()));
//                 }
//             }
//             if read_state(State::has_events_to_mint) {
//                 ic_cdk_timers::set_timer(Duration::from_secs(0), || ic_cdk::spawn(mint()));
//             }
//             for error in errors {
//                 if let ReceivedEventError::InvalidEventSource { source, error } = &error {
//                     mutate_state(|s| {
//                         process_event(
//                             s,
//                             EventType::InvalidDeposit {
//                                 event_source: *source,
//                                 reason: error.to_string(),
//                             },
//                         )
//                     });
//                 }
//                 report_transaction_error(error);
//             }
//             update_last_scraped_block_number(last_block_number);
//             Some(last_block_number)
//         }
//         Ordering::Greater => {
//             ic_cdk::trap(&format!(
//                 "BUG: last scraped block number ({:?}) is greater than the last queried block number ({:?})",
//                 from, to
//             ));
//         }
//     }
// }

// async fn scrape_contract_logs<F>(
//     topic: &[u8; 32],
//     topic_name: &str,
//     helper_contract_address: Option<Address>,
//     token_contract_addresses: &[Address],
//     last_block_number: BlockNumber,
//     mut last_scraped_block_number: BlockNumber,
//     max_block_spread: u16,
//     update_last_scraped_block_number: F,
// ) where
//     F: Fn(BlockNumber),
// {
//     let helper_contract_address = match helper_contract_address {
//         Some(address) => address,
//         None => {
//             log!(
//                 DEBUG,
//                 "[scrape_contract_logs]: skipping scrapping logs: no contract address"
//             );
//             return;
//         }
//     };

//     while last_scraped_block_number < last_block_number {
//         let next_block_to_query = last_scraped_block_number
//             .checked_increment()
//             .unwrap_or(BlockNumber::MAX);
//         last_scraped_block_number = match scrape_logs_range_inclusive(
//             topic,
//             topic_name,
//             helper_contract_address,
//             token_contract_addresses,
//             next_block_to_query,
//             last_block_number,
//             max_block_spread,
//             &update_last_scraped_block_number,
//         )
//         .await
//         {
//             Some(last_scraped_block_number) => last_scraped_block_number,
//             None => {
//                 return;
//             }
//         };
//     }
// }

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
}

// Updates last_observed_block_number in the state.
pub async fn update_last_observed_block_number() -> Option<BlockNumber> {
    let block_height = read_state(State::block_height);
    match read_state(RpcClient::from_state)
        .get_block_by_number(BlockSpec::Tag(block_height))
        .await
    {
        Ok(latest_block) => {
            let block_number = Some(latest_block.number);
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
