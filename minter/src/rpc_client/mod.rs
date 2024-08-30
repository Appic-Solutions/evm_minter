#[cfg(test)]
mod tests;

use std::{clone, collections::BTreeMap, fmt::Display, str::FromStr};

use crate::{
    checked_amount::CheckedAmountOf,
    eth_types::Address,
    lifecycles::EvmNetwork,
    logs::{PrintProxySink, DEBUG, INFO, TRACE_HTTP},
    numeric::{BlockNumber, GasAmount, LogIndex, Wei, WeiPerGas},
    rpc_declrations::{
        Block, BlockSpec, BlockTag, Data, FixedSizeData, GetLogsParam, Hash, LogEntry, Topic,
        TransactionReceipt, TransactionStatus,
    },
    state::State,
};
use ic_canister_log::log;

use evm_rpc_client::{
    types::candid::{
        Block as EvmBlock, BlockTag as EvmBlockTag, EthSepoliaService, FeeHistory as EvmFeeHistory,
        FeeHistoryArgs as EvmFeeHistoryArgs, GetLogsArgs as EvmGetLogsArgs, HttpOutcallError,
        LogEntry as EvmLogEntry, MultiRpcResult as EvmMultiRpcResult, RpcConfig as EvmRpcConfig,
        RpcError as EvmRpcError, RpcResult as EvmRpcResult, RpcService as EvmRpcService,
        RpcServices as EvmRpcServices, TransactionReceipt as EvmTransactionReceipt,
    },
    CallerService, EvmRpcClient, OverrideRpcConfig,
};
use num_traits::ToPrimitive;

use ic_cdk::api::call::RejectionCode;
use serde_json::error;
// We expect most of the calls to contain zero events.
const ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE: u64 = 100;

// This constant is our approximation of the expected header size.
// The HTTP standard doesn't define any limit, and many implementations limit
// the headers size to 8 KiB. We chose a lower limit because headers observed on most providers
// fit in the constant defined below, and if there is spike, then the payload size adjustment
// should take care of that.
pub const HEADER_SIZE_LIMIT: u64 = 2 * 1024;

#[derive(Debug)]
pub struct RpcClient {
    evm_rpc_client: Option<EvmRpcClient<PrintProxySink>>,
    chain: EvmNetwork,
}
impl RpcClient {
    pub fn from_state(state: &State) -> Self {
        let mut client = Self {
            evm_rpc_client: None,
            chain: state.evm_network_id,
        };
        const MIN_ATTACHED_CYCLES: u128 = 300_000_000_000;

        // TODO: Add a function to chose custom providers based on the chainid
        let providers = EvmRpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy]));

        client.evm_rpc_client = Some(
            EvmRpcClient::builder(CallerService {}, TRACE_HTTP)
                .with_providers(providers)
                .with_evm_canister_id(state.evm_canister_id)
                .with_min_attached_cycles(MIN_ATTACHED_CYCLES)
                .with_override_rpc_config(OverrideRpcConfig {
                    eth_get_logs: Some(EvmRpcConfig {
                        response_size_estimate: Some(
                            ETH_GET_LOGS_INITIAL_RESPONSE_SIZE_ESTIMATE + HEADER_SIZE_LIMIT,
                        ),
                    }),
                    ..Default::default()
                })
                .build(),
        );

        client
    }

    pub async fn get_logs(
        &self,
        params: GetLogsParam,
    ) -> Result<Vec<LogEntry>, MultiCallError<Vec<LogEntry>>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            let result = evm_rpc_client
                .eth_get_logs(EvmGetLogsArgs {
                    from_block: Some(into_evm_block_tag(params.from_block)),
                    to_block: Some(into_evm_block_tag(params.to_block)),
                    addresses: params.address.into_iter().map(|a| a.to_string()).collect(),
                    topics: Some(into_evm_topic(params.topics)),
                })
                .await
                .reduce();
            return result.result;
        } else {
            Err(MultiCallError::ConsistentEvmRpcCanisterError(String::from(
                "EVM RPC canister can not be None",
            )))
        }
    }

    pub async fn get_block_by_number(
        &self,
        block: BlockSpec,
    ) -> Result<Block, MultiCallError<Block>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            let result = evm_rpc_client
                .eth_get_block_by_number(into_evm_block_tag(block))
                .await
                .reduce();
            return result.result;
        } else {
            Err(MultiCallError::ConsistentEvmRpcCanisterError(String::from(
                "EVM RPC canister can not be None",
            )))
        }
    }

    pub async fn eth_get_transaction_receipt(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<TransactionReceipt>, MultiCallError<Option<TransactionReceipt>>> {
        if let Some(evm_rpc_client) = &self.evm_rpc_client {
            return evm_rpc_client
                .eth_get_transaction_receipt(tx_hash.to_string())
                .await
                .reduce()
                .into();
        } else {
            Err(MultiCallError::ConsistentEvmRpcCanisterError(String::from(
                "EVM RPC canister can not be None",
            )))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Ord, PartialOrd)]
pub enum SingleCallError {
    HttpOutcallError(HttpOutcallError),
    JsonRpcError { code: i64, message: String },
    EvmRpcError(String),
}

impl From<EvmRpcError> for SingleCallError {
    fn from(value: EvmRpcError) -> Self {
        match value {
            EvmRpcError::ProviderError(e) => SingleCallError::EvmRpcError(e.to_string()),
            EvmRpcError::HttpOutcallError(e) => SingleCallError::HttpOutcallError(e.into()),
            EvmRpcError::JsonRpcError(e) => SingleCallError::JsonRpcError {
                code: e.code,
                message: e.message,
            },
            EvmRpcError::ValidationError(e) => SingleCallError::EvmRpcError(e.to_string()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MultiCallError<T> {
    ConsistentHttpOutcallError(HttpOutcallError),
    ConsistentJsonRpcError { code: i64, message: String },
    ConsistentEvmRpcCanisterError(String),
    InconsistentResults(Vec<(EvmRpcService, Result<T, SingleCallError>)>),
}

impl<T> MultiCallError<T> {
    pub fn has_http_outcall_error_matching<P: Fn(&HttpOutcallError) -> bool>(
        &self,
        predicate: P,
    ) -> bool {
        match self {
            MultiCallError::ConsistentHttpOutcallError(error) => predicate(error),
            MultiCallError::ConsistentJsonRpcError { .. } => false,
            MultiCallError::InconsistentResults(results) => {
                results
                    .into_iter()
                    .any(|(rpcservice, rpc_result)| match rpc_result {
                        Ok(_) => false,
                        Err(rpc_error) => match rpc_error {
                            SingleCallError::HttpOutcallError(error) => predicate(error),
                            SingleCallError::JsonRpcError { .. }
                            | SingleCallError::EvmRpcError(_) => false,
                        },
                    })
            }
            MultiCallError::ConsistentEvmRpcCanisterError(_) => false,
        }
    }

    // If at there are at least two ok responses
    /// Expects at least 2 ok results to be ok or return the following error:
    /// * MultiCallError::ConsistentJsonRpcError: all errors are the same JSON-RPC error.
    /// * MultiCallError::ConsistentHttpOutcallError: all errors are the same HTTP outcall error.
    /// * MultiCallError::InconsistentResults if there are different errors or an ok result with some errors.
    pub fn at_least_two_ok(self) -> Result<Vec<(EvmRpcService, T)>, MultiCallError<T>> {
        match self {
            MultiCallError::InconsistentResults(inconsistent_result) => {
                let inconsistent_ok_results: Vec<(EvmRpcService, Result<T, SingleCallError>)> =
                    inconsistent_result
                        .into_iter()
                        .filter(|(rpc_service, result)| result.is_ok())
                        .collect();

                match inconsistent_ok_results.len() {
                    0 => Err(MultiCallError::InconsistentResults(inconsistent_ok_results)),
                    1 => Err(MultiCallError::InconsistentResults(inconsistent_ok_results)),
                    _ => {
                        let mapped: Vec<(EvmRpcService, T)> = inconsistent_ok_results
                            .into_iter()
                            .filter_map(|(rpc_service, result)| {
                                result.ok().map(|value| (rpc_service, value))
                            })
                            .collect();
                        Ok(mapped)
                    }
                }
            }
            _ => Err(self),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReducedResult<T> {
    result: Result<T, MultiCallError<T>>,
}

impl<T> From<Result<T, MultiCallError<T>>> for ReducedResult<T> {
    fn from(result: Result<T, MultiCallError<T>>) -> Self {
        Self { result }
    }
}

impl<T> From<ReducedResult<T>> for Result<T, MultiCallError<T>> {
    fn from(value: ReducedResult<T>) -> Self {
        value.result
    }
}

impl<T: std::fmt::Debug> ReducedResult<T> {
    /// Transform a `ReducedResult<T>` into a `ReducedResult<U>` by applying a mapping function `F`.
    /// The mapping function is also applied to the elements contained in the error `MultiCallError::InconsistentResults`.

    pub fn map_reduce<U, E: Display, F: Fn(T) -> Result<U, E>>(
        self,
        fallible_op: &F,
        // reduction: R,
    ) -> ReducedResult<U> {
        let result = match self.result {
            Ok(t) => fallible_op(t)
                .map_err(|e| MultiCallError::<U>::ConsistentEvmRpcCanisterError(e.to_string())),
            Err(MultiCallError::ConsistentHttpOutcallError(e)) => {
                Err(MultiCallError::<U>::ConsistentHttpOutcallError(e))
            }
            Err(MultiCallError::ConsistentJsonRpcError { code, message }) => {
                Err(MultiCallError::<U>::ConsistentJsonRpcError { code, message })
            }
            Err(MultiCallError::ConsistentEvmRpcCanisterError(e)) => {
                Err(MultiCallError::<U>::ConsistentEvmRpcCanisterError(e))
            }

            Err(MultiCallError::InconsistentResults(results)) => {
                let mapped_inconsistent_results = results
                    .into_iter()
                    .map(|(rpc_service, response)| {
                        let mapped_response = match response {
                            Ok(inconsistent_response) => fallible_op(inconsistent_response)
                                .map_err(|e| SingleCallError::EvmRpcError(e.to_string())),
                            Err(error) => Err(error),
                        };
                        return (rpc_service, mapped_response);
                    })
                    .collect();
                Err(MultiCallError::<U>::InconsistentResults(
                    mapped_inconsistent_results,
                ))
            }
        };
        ReducedResult { result }
    }

    pub fn from_multi_result(value: EvmMultiRpcResult<T>) -> Self {
        let result = match value {
            EvmMultiRpcResult::Consistent(result) => match result {
                Ok(t) => Ok(t),
                Err(e) => match e {
                    EvmRpcError::ProviderError(e) => {
                        Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
                    }
                    EvmRpcError::HttpOutcallError(e) => {
                        Err(MultiCallError::ConsistentHttpOutcallError(e.into()))
                    }
                    EvmRpcError::JsonRpcError(e) => Err(MultiCallError::ConsistentJsonRpcError {
                        code: e.code,
                        message: e.message,
                    }),
                    EvmRpcError::ValidationError(e) => {
                        Err(MultiCallError::ConsistentEvmRpcCanisterError(e.to_string()))
                    }
                },
            },
            EvmMultiRpcResult::Inconsistent(result) => {
                let converted_to_single_call_erro = result
                    .into_iter()
                    .map(|(rpc_provider, rpc_result)| {
                        let mapped_rpc_result = match rpc_result {
                            Ok(ok_response) => Ok(ok_response),
                            Err(rpc_error) => Err(SingleCallError::from(rpc_error)),
                        };
                        (rpc_provider, mapped_rpc_result)
                    })
                    .collect();

                Err(MultiCallError::InconsistentResults(
                    converted_to_single_call_erro,
                ))
                // Err(MultiCallError::InconsistentResults(result))
            }
        };
        Self { result }
    }

    // Reduce the inconsistent result with the starategy that if there is even ingle inconsistent resposne,
    // the new reduced result will be an inconsistent multierror call type.
    pub fn reduce_with_equality(self) -> Self {
        match self.result {
            Ok(_) => (),
            Err(ref multi_error) => match multi_error {
                MultiCallError::InconsistentResults(inconsistent_result) => {
                    log!(
                        INFO,
                        "[reduce_with_equality]: inconsistent results {inconsistent_result:?}"
                    );
                    ()
                }
                _ => (),
            },
        };
        self
    }

    // If Inconsistent, Aggregates results from multiple RPC node providers into a single result based on a strict majority rule.
    // The aggregation is performed by grouping results with the same key extracted using the provided extractor function.
    // If a strict majority (more than half) of results share the same value for a key, that value is returned.
    // If no strict majority exists, an error is returned with the inconsistent results.
    // pub fn reduce_with_strict_majority_by_key<F: Fn(&T) -> K, K: Ord>(self, extractor: F) -> Self {
    //     match self.result {
    //         Ok(_) => self,
    //         Err(multi_error) => match multi_error.at_least_two_ok() {
    //             Ok(inconsistent_ok_results) => {
    //                 let mut votes_by_key: BTreeMap<K, BTreeMap<EvmRpcService, T>> = BTreeMap::new();

    //                 self
    //             }
    //             Err(error) => ReducedResult { result: Err(error) },
    //         },
    //     };
    //     for (provider, result) in self.at_least_two_ok()?.into_iter() {
    //         let key = extractor(&result);
    //         match votes_by_key.remove(&key) {
    //             Some(mut votes_for_same_key) => {
    //                 let (_other_provider, other_result) = votes_for_same_key
    //                     .last_key_value()
    //                     .expect("BUG: results_with_same_key is non-empty");
    //                 if &result != other_result {
    //                     let error = MultiCallError::InconsistentResults(
    //                         MultiCallResults::from_non_empty_iter(
    //                             votes_for_same_key
    //                                 .into_iter()
    //                                 .chain(std::iter::once((provider, result)))
    //                                 .map(|(provider, result)| (provider, Ok(result))),
    //                         ),
    //                     );
    //                     log!(
    //                         INFO,
    //                         "[reduce_with_strict_majority_by_key]: inconsistent results {error:?}"
    //                     );
    //                     return Err(error);
    //                 }
    //                 votes_for_same_key.insert(provider, result);
    //                 votes_by_key.insert(key, votes_for_same_key);
    //             }
    //             None => {
    //                 let _ = votes_by_key.insert(key, BTreeMap::from([(provider, result)]));
    //             }
    //         }
    //     }

    //     let mut tally: Vec<(K, BTreeMap<RpcNodeProvider, T>)> = Vec::from_iter(votes_by_key);
    //     tally.sort_unstable_by(|(_left_key, left_ballot), (_right_key, right_ballot)| {
    //         left_ballot.len().cmp(&right_ballot.len())
    //     });
    //     match tally.len() {
    //         0 => panic!("BUG: tally should be non-empty"),
    //         1 => Ok(tally
    //             .pop()
    //             .and_then(|(_key, mut ballot)| ballot.pop_last())
    //             .expect("BUG: tally is non-empty")
    //             .1),
    //         _ => {
    //             let mut first = tally.pop().expect("BUG: tally has at least 2 elements");
    //             let second = tally.pop().expect("BUG: tally has at least 2 elements");
    //             if first.1.len() > second.1.len() {
    //                 Ok(first
    //                     .1
    //                     .pop_last()
    //                     .expect("BUG: tally should be non-empty")
    //                     .1)
    //             } else {
    //                 let error =
    //                     MultiCallError::InconsistentResults(MultiCallResults::from_non_empty_iter(
    //                         first
    //                             .1
    //                             .into_iter()
    //                             .chain(second.1)
    //                             .map(|(provider, result)| (provider, Ok(result))),
    //                     ));
    //                 log!(
    //                     INFO,
    //                     "[reduce_with_strict_majority_by_key]: no strict majority {error:?}"
    //                 );
    //                 Err(error)
    //             }
    //         }
    //     }
    // }
}

// Reduce trait implimentation for converting EVM_RPC_CANISTER response into desiered type.
// Convert inconsistent response into consistent if necessary with different strategies
trait Reduce {
    type Item;
    fn reduce(self) -> ReducedResult<Self::Item>;
}

impl Reduce for EvmMultiRpcResult<EvmBlock> {
    type Item = Block;

    fn reduce(self) -> ReducedResult<Self::Item> {
        ReducedResult::from_multi_result(self)
            .reduce_with_equality()
            .map_reduce(&|block: EvmBlock| {
                Ok::<Block, String>(Block {
                    number: BlockNumber::try_from(block.number)?,
                    base_fee_per_gas: Wei::try_from(block.base_fee_per_gas)?,
                })
            })
    }
}

impl Reduce for EvmMultiRpcResult<Vec<EvmLogEntry>> {
    type Item = Vec<LogEntry>;

    fn reduce(self) -> ReducedResult<Self::Item> {
        fn map_logs(logs: Vec<EvmLogEntry>) -> Result<Vec<LogEntry>, String> {
            logs.into_iter().map(map_single_log).collect()
        }

        fn map_single_log(log: EvmLogEntry) -> Result<LogEntry, String> {
            Ok(LogEntry {
                address: Address::from_str(&log.address)?,
                topics: log
                    .topics
                    .into_iter()
                    .map(|t| FixedSizeData::from_str(&t))
                    .collect::<Result<_, _>>()?,
                data: Data::from_str(&log.data)?,
                block_number: log.block_number.map(BlockNumber::try_from).transpose()?,
                transaction_hash: log
                    .transaction_hash
                    .as_deref()
                    .map(Hash::from_str)
                    .transpose()?,
                transaction_index: log
                    .transaction_index
                    .map(|i| CheckedAmountOf::<()>::try_from(i).map(|c| c.into_inner()))
                    .transpose()?,
                block_hash: log.block_hash.as_deref().map(Hash::from_str).transpose()?,
                log_index: log.log_index.map(LogIndex::try_from).transpose()?,
                removed: log.removed,
            })
        }
        let mapped_logs = ReducedResult::from_multi_result(self)
            .reduce_with_equality()
            .map_reduce(&map_logs);
        mapped_logs
    }
}

impl Reduce for EvmMultiRpcResult<Option<EvmTransactionReceipt>> {
    type Item = Option<TransactionReceipt>;

    fn reduce(self) -> ReducedResult<Self::Item> {
        fn map_transaction_receipt(
            receipt: Option<EvmTransactionReceipt>,
        ) -> Result<Option<TransactionReceipt>, String> {
            receipt
                .map(|evm_receipt| {
                    Ok(TransactionReceipt {
                        block_hash: Hash::from_str(&evm_receipt.block_hash)?,
                        block_number: BlockNumber::try_from(evm_receipt.block_number)?,
                        effective_gas_price: WeiPerGas::try_from(evm_receipt.effective_gas_price)?,
                        gas_used: GasAmount::try_from(evm_receipt.gas_used)?,
                        status: TransactionStatus::try_from(
                            evm_receipt
                                .status
                                .0
                                .to_u8()
                                .ok_or("invalid transaction status")?,
                        )?,
                        transaction_hash: Hash::from_str(&evm_receipt.transaction_hash)?,
                    })
                })
                .transpose()
        }

        let mapped_transaction_receipt = ReducedResult::from_multi_result(self)
            .reduce_with_equality()
            .map_reduce(&map_transaction_receipt);
        mapped_transaction_receipt
    }
}

fn into_evm_block_tag(block: BlockSpec) -> EvmBlockTag {
    match block {
        BlockSpec::Number(n) => EvmBlockTag::Number(n.into()),
        BlockSpec::Tag(BlockTag::Latest) => EvmBlockTag::Latest,
        BlockSpec::Tag(BlockTag::Safe) => EvmBlockTag::Safe,
        BlockSpec::Tag(BlockTag::Finalized) => EvmBlockTag::Finalized,
    }
}

fn into_evm_topic(topics: Vec<Topic>) -> Vec<Vec<String>> {
    let mut result = Vec::with_capacity(topics.len());
    for topic in topics {
        result.push(match topic {
            Topic::Single(single_topic) => vec![single_topic.to_string()],
            Topic::Multiple(multiple_topic) => {
                multiple_topic.into_iter().map(|t| t.to_string()).collect()
            }
        });
    }
    result
}

pub fn is_response_too_large(error: &HttpOutcallError) -> bool {
    match error {
        HttpOutcallError::IcError { code, message } => {
            code == &RejectionCode::SysFatal && message.contains("size limit")
        }
        _ => false,
    }
}
