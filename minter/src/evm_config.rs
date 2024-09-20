// use crate::lifecycle::init::InitArg;
// use crate::lifecycle::upgrade::UpgradeArg;
use candid::{CandidType, Deserialize};
use minicbor::{Decode, Encode};
use std::{
    default,
    fmt::{Display, Formatter},
};

#[derive(
    CandidType, Clone, Copy, Deserialize, Default, Debug, Eq, PartialEq, Hash, Encode, Decode,
)]
#[cbor(index_only)]
pub enum EvmNetwork {
    #[n(1)]
    Ethereum,
    #[n(11155111)]
    #[default]
    Sepolia,
    #[n(42161)]
    ArbitrumOne,
    #[n(56)]
    BSC,
    #[n(137)]
    Polygon,
    #[n(10)]
    Optimism,
    #[n(8453)]
    Base,
}

impl EvmNetwork {
    pub fn chain_id(&self) -> u64 {
        match self {
            EvmNetwork::Ethereum => 1,
            EvmNetwork::Sepolia => 11155111,
            EvmNetwork::ArbitrumOne => 42161,
            EvmNetwork::BSC => 56,
            EvmNetwork::Polygon => 137,
            EvmNetwork::Optimism => 10,
            EvmNetwork::Base => 8453,
        }
    }
}

impl TryFrom<u64> for EvmNetwork {
    type Error = String;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EvmNetwork::Ethereum),
            11155111 => Ok(EvmNetwork::Sepolia),
            42161 => Ok(EvmNetwork::ArbitrumOne),
            56 => Ok(EvmNetwork::BSC),
            137 => Ok(EvmNetwork::Polygon),
            10 => Ok(EvmNetwork::Optimism),
            8453 => Ok(EvmNetwork::Base),
            _ => Err("Unknown EVM chain id Network".to_string()),
        }
    }
}

impl Display for EvmNetwork {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EvmNetwork::Ethereum => write!(f, "Ethereum mainnet"),
            EvmNetwork::Sepolia => write!(f, "Sepolia Testnet"),
            EvmNetwork::ArbitrumOne => write!(f, "Arbitrum one mainnet"),
            EvmNetwork::BSC => write!(f, "Binance smart chain mainnet"),
            EvmNetwork::Polygon => write!(f, "Polygon mainnet"),
            EvmNetwork::Optimism => write!(f, "Optimism mainnet"),
            EvmNetwork::Base => write!(f, "Base mainnet"),
        }
    }
}
