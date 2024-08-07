// use crate::{
//     numeric::BlockNumber,
//     state::{mutate_state, read_state, State},
// };

// pub async fn update_last_observed_block_number() -> Option<BlockNumber> {
//     let block_height = read_state(State::block_height);
//     match read_state(EthRpcClient::from_state)
//         .eth_get_block_by_number(BlockSpec::Tag(block_height))
//         .await
//     {
//         Ok(latest_block) => {
//             let block_number = Some(latest_block.number);
//             mutate_state(|s| s.last_observed_block_number = block_number);
//             block_number
//         }
//         Err(e) => {
//             log!(
//                 INFO,
//                 "Failed to get the latest {block_height} block number: {e:?}"
//             );
//             read_state(|s| s.last_observed_block_number)
//         }
//     }
// }
