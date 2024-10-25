use std::fmt::format;

use crate::evm_config::EvmNetwork;
use crate::storage::get_rpc_api_key;
use evm_rpc_types::{RpcApi, RpcServices};
use minicbor::{Decode, Encode};

#[derive(Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Provider {
    #[n(0)]
    Ankr,
    #[n(1)]
    LlamaNodes,
    #[n(2)]
    PublicNode,
}
impl Provider {
    pub fn get_url_with_api_key(self, url: &str) -> String {
        match get_rpc_api_key(self) {
            Some(api_key) => format(format_args!("{}/{}", url, api_key)),
            None => format(format_args!("{}", url)),
        }
    }
}

pub fn get_one_provider(network: EvmNetwork) -> RpcServices {
    let chain_id = network.chain_id();
    match network {
        EvmNetwork::Ethereum => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode
                    .get_url_with_api_key("https://ethereum-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::Sepolia => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode
                    .get_url_with_api_key("https://ethereum-sepolia-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::ArbitrumOne => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode
                    .get_url_with_api_key("https://arbitrum-one-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::BSC => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode.get_url_with_api_key("https://bsc-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::Polygon => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode
                    .get_url_with_api_key("https://polygon-bor-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::Optimism => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode
                    .get_url_with_api_key("https://optimism-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::Base => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode.get_url_with_api_key("https://base-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::Avalanche => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode
                    .get_url_with_api_key("https://avalanche-c-chain-rpc.publicnode.com"),
                headers: None,
            }],
        },
        EvmNetwork::Fantom => RpcServices::Custom {
            chain_id,
            services: vec![RpcApi {
                url: Provider::PublicNode.get_url_with_api_key("https://fantom-rpc.publicnode.com"),
                headers: None,
            }],
        },
    }
}

pub fn get_providers(network: EvmNetwork) -> RpcServices {
    let chain_id = network.chain_id();
    match network {
        EvmNetwork::Ethereum => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::LlamaNodes.get_url_with_api_key("https://eth.llamarpc.com"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/eth"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://ethereum-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::Sepolia => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/eth_sepolia"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://ethereum-sepolia-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::ArbitrumOne => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::LlamaNodes.get_url_with_api_key("https://arbitrum.llamarpc.com"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/arbitrum"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://arbitrum-one-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::BSC => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::LlamaNodes.get_url_with_api_key("https://binance.llamarpc.com"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/bsc"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://bsc-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::Polygon => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::LlamaNodes.get_url_with_api_key("https://polygon.llamarpc.com"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/polygon"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://polygon-bor-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::Optimism => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::LlamaNodes.get_url_with_api_key("https://optimism.llamarpc.com"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/optimism"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://optimism-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::Base => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::LlamaNodes.get_url_with_api_key("https://base.llamarpc.com"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/base"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://base-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::Avalanche => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/avalanche"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://avalanche-c-chain-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
        EvmNetwork::Fantom => RpcServices::Custom {
            chain_id,
            services: vec![
                RpcApi {
                    url: Provider::Ankr.get_url_with_api_key("https://rpc.ankr.com/fantom"),
                    headers: None,
                },
                RpcApi {
                    url: Provider::PublicNode
                        .get_url_with_api_key("https://fantom-rpc.publicnode.com"),
                    headers: None,
                },
            ],
        },
    }
}
