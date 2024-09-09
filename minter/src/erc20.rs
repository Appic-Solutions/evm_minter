// #[cfg(test)]
// pub mod test_fixtures;
// #[cfg(test)]
// mod tests;

use crate::eth_types::Address;
use crate::evm_config::EvmNetwork;
// use crate::endpoints::AddCkErc20Token;
// use crate::lifecycle::EthereumNetwork;
use crate::state::State;
use candid::Principal;
use minicbor::{Decode, Encode};
use num_traits::ToPrimitive;
use std::fmt::Display;
use std::str::FromStr;

pub const MAX_ERC20_TOKEN_SYMBOL_NUM_BYTES: usize = 20;

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct ERC20Token {
    #[n(0)]
    pub chain_id: EvmNetwork,
    #[n(1)]
    pub erc20_contract_address: Address,
    #[n(2)]
    pub erc20_token_symbol: ERC20TokenSymbol,
    #[cbor(n(3), with = "crate::cbor::principal")]
    pub erc20_ledger_id: Principal,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
#[cbor(transparent)]
pub struct ERC20TokenSymbol(#[n(0)] String);

impl ERC20TokenSymbol {
    pub fn new(symbol: String) -> Self {
        Self(symbol)
    }
}

impl Display for ERC20TokenSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ERC20TokenSymbol {
    type Err = String;

    fn from_str(token_symbol: &str) -> Result<Self, Self::Err> {
        if token_symbol.len() > MAX_ERC20_TOKEN_SYMBOL_NUM_BYTES {
            return Err(format!(
                "ERROR: token symbol is too long: expected at most {} characters, but got {}",
                MAX_ERC20_TOKEN_SYMBOL_NUM_BYTES,
                token_symbol.len()
            ));
        }
        if !token_symbol.is_ascii() {
            return Err("ERROR: token symbol contains non-ascii characters".to_string());
        }
        Ok(Self(token_symbol.to_string()))
    }
}

// impl TryFrom<AddCkErc20Token> for CkErc20Token {
//     type Error = String;

//     fn try_from(value: AddCkErc20Token) -> Result<Self, Self::Error> {
//         let erc20_ethereum_network = EthereumNetwork::try_from(
//             value
//                 .chain_id
//                 .0
//                 .to_u64()
//                 .ok_or("ERROR: chain_id does not fit in a u64")?,
//         )?;
//         let erc20_contract_address =
//             Address::from_str(&value.address).map_err(|e| format!("ERROR: {}", e))?;
//         Ok(Self {
//             erc20_ethereum_network,
//             erc20_contract_address,
//             ckerc20_token_symbol: value.ckerc20_token_symbol.parse()?,
//             ckerc20_ledger_id: value.ckerc20_ledger_id,
//         })
//     }
// }
