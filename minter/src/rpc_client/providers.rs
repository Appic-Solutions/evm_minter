use crate::evm_config::EvmNetwork;

use evm_rpc_client::types::candid::{RpcApi, RpcService, RpcServices};
use ic_cdk::api::management_canister::http_request::HttpHeader;

fn get_providers(network: EvmNetwork) -> RpcService {
    let providers: RpcService = match network {
        EvmNetwork::Ethereum => {
            return RpcService::Custom(RpcApi {
                url: "https://zksync-mainnet.g.alchemy.com/v2/iH8aiaL9zywc-pYE1GxTiHNejUF08FZB"
                    .to_string(),
                headers: None,
            })
        }
        EvmNetwork::Sepolia => todo!(),
        EvmNetwork::ArbitrumOne => todo!(),
        EvmNetwork::BSC => todo!(),
        EvmNetwork::Polygon => todo!(),
        EvmNetwork::Optimism => todo!(),
        EvmNetwork::Base => todo!(),
    };
}
