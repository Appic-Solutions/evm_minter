use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use crate::{
    checked_amount::CheckedAmountOf,
    eth_types::Address,
    lifecycles::EvmNetwork,
    logs::{PrintProxySink, DEBUG, INFO, TRACE_HTTP},
    numeric::{BlockNumber, LogIndex},
    rpc_declrations::{Data, FixedSizeData, GetLogsParam, Hash, LogEntry},
    state::State,
};
use ic_canister_log::log;

use evm_rpc_client::{
    types::candid::{
        EthSepoliaService, HttpOutcallError, LogEntry as EvmLogEntry,
        MultiRpcResult as EvmMultiRpcResult, RpcConfig as EvmRpcConfig, RpcError as EvmRpcError,
        RpcResult as EvmRpcResult, RpcService as EvmRpcService, RpcServices as EvmRpcServices,
    },
    CallerService, EvmRpcClient, OverrideRpcConfig,
};
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

        // TODO: Add afunction to chose custom providers based on the chainid
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

    // pub fn get_logs(
    //     &self,
    //     params: GetLogsParam,
    // ) -> Result<Vec<LogEntry>, MultiCallError<Vec<LogEntry>>> {
    // }
}

/// Aggregates responses of different providers to the same query.
/// Guaranteed to be non-empty.
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct MultiCallResults<T> {
//     ok_results: BTreeMap<RpcNodeProvider, T>,
//     errors: BTreeMap<RpcNodeProvider, SingleCallError>,
// }

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

#[derive(Debug, PartialEq, Eq)]
pub struct ReducedResult<T> {
    result: Result<T, MultiCallError<T>>,
}

impl<T: std::fmt::Debug> ReducedResult<T> {
    /// Transform a `ReducedResult<T>` into a `ReducedResult<U>` by applying a mapping function `F`.
    /// The mapping function is also applied to the elements contained in the error `MultiCallError::InconsistentResults`,
    /// which depending on the mapping function could lead to the mapped results no longer being inconsistent.
    /// The final result in that case is given by applying the reduction function `R` to the mapped results.
    pub fn map_reduce<
        U,
        E: Display,
        F: Fn(T) -> Result<U, E>,
        // R: FnOnce(Vec<(EvmRpcService, EvmRpcResult<T>)>) -> Result<U, MultiCallError<U>>,
    >(
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
}

trait Reduce {
    type Item;
    fn reduce(self) -> ReducedResult<Self::Item>;
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
