use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use std::fmt::{Debug, Display, Formatter, LowerHex, UpperHex};

/// Block tags.
/// See <https://ethereum.org/en/developers/docs/apis/json-rpc/#default-block>
#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BlockTag {
    /// The latest mined block.
    #[default]
    Latest,
    /// The latest safe head block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    Safe,
    /// The latest finalized block.
    /// See
    /// <https://www.alchemy.com/overviews/ethereum-commitment-levels#what-are-ethereum-commitment-levels>
    Finalized,
}

// impl From<CandidBlockTag> for BlockTag {
//     fn from(block_tag: CandidBlockTag) -> BlockTag {
//         match block_tag {
//             CandidBlockTag::Latest => BlockTag::Latest,
//             CandidBlockTag::Safe => BlockTag::Safe,
//             CandidBlockTag::Finalized => BlockTag::Finalized,
//         }
//     }
// }

// impl From<BlockTag> for CandidBlockTag {
//     fn from(value: BlockTag) -> Self {
//         match value {
//             BlockTag::Latest => CandidBlockTag::Latest,
//             BlockTag::Safe => CandidBlockTag::Safe,
//             BlockTag::Finalized => CandidBlockTag::Finalized,
//         }
//     }
// }

impl Display for BlockTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Latest => write!(f, "latest"),
            Self::Safe => write!(f, "safe"),
            Self::Finalized => write!(f, "finalized"),
        }
    }
}
