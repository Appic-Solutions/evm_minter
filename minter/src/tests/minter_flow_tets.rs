use std::time::Duration;

use candid::{Nat, Principal};

use crate::{
    endpoints::{
        Eip1559TransactionPrice, RequestScrapingError, RetrieveNativeRequest,
        RetrieveWithdrawalStatus, TxFinalizedStatus, WithdrawalArg, WithdrawalError,
    },
    tests::pocket_ic_helpers::{five_ticks, native_ledger_principal, update_call},
    PROCESS_TOKENS_RETRIEVE_TRANSACTIONS_INTERVAL,
};

use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};

use super::pocket_ic_helpers::{
    create_pic, intialize_minter::create_and_install_minter_plus_dependency_canisters,
    minter_principal, query_call,
};

use mock_rpc_https_responses::{
    generate_and_submit_mock_http_response, MOCK_BLOCK_NUMBER, MOCK_FEE_HISTORY_RESPONSE,
    MOCK_GET_LOGS, MOCK_HIGER_BLOCK_NUMBER, MOCK_SEND_TRANSACTION_ERROR,
    MOCK_SEND_TRANSACTION_SUCCESS, MOCK_TRANSACTION_COUNT_FINALIZED, MOCK_TRANSACTION_COUNT_LATEST,
    MOCK_TRANSACTION_RECEIPT,
};

#[test]
fn should_get_estimated_eip1559_transaction_price() {
    let pic = create_pic();
    create_and_install_minter_plus_dependency_canisters(&pic);

    five_ticks(&pic);

    let canister_http_requests = pic.get_canister_http();

    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        1,
        MOCK_FEE_HISTORY_RESPONSE,
    );

    five_ticks(&pic);

    // Get eip1559 transaction price
    let transaction_price = query_call::<(), Eip1559TransactionPrice>(
        &pic,
        minter_principal(),
        "eip_1559_transaction_price",
        (),
    );
    let expected_price = Eip1559TransactionPrice {
        gas_limit: Nat::from(21000_u64),
        max_fee_per_gas: Nat::from(3000000000_u64),
        max_priority_fee_per_gas: Nat::from(3000000000_u64),
        max_transaction_fee: Nat::from(63000000000000_u64),
        timestamp: Some(1620328630000000061_u64),
    };
    assert_eq!(expected_price, transaction_price);
}

#[test]
fn should_deposit_and_withdrawal_native() {
    let pic = create_pic();
    create_and_install_minter_plus_dependency_canisters(&pic);

    // The deposit and whitdrawal http mock flow is as follow
    // 1st Step: The mock response for get_blockbynumber is generated
    // 2nd Step: The response for eth_feehistory resonse is genrated afterwards,
    // so in the time of withdrawal transaction the eip1559 transaction price is available
    // Not to forget that the price should be refreshed through a second call at the time
    // 3rd Step: There should two mock responses be generated, one for ankr and the other one for public node
    // 4th Step: The response for sendrawtransaction
    // 5th Step: An httpoutcall for geting the finalized transaction count.
    // 5th Step: and in the end get transaction receipt should be generate

    // At this time there should be 2 http reuests:
    // [0] is for eth_getBlockByNumber
    // [1] is for eth_feeHistory
    let canister_http_requests = pic.get_canister_http();

    // 1st Generating mock response for eth_getBlockByNumber
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 0, MOCK_BLOCK_NUMBER);

    // 2nd Generating mock reponse for eth_feehistory
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        1,
        MOCK_FEE_HISTORY_RESPONSE,
    );

    five_ticks(&pic);

    // 3rd generating mock response for eth_getLogs
    // At this time there should be 2 http reuests:
    // [0] is for public_node eth_getLogs
    // [1] is for ankr eth_getLogs
    let canister_http_requests = pic.get_canister_http();

    // publick_node mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 0, MOCK_GET_LOGS);

    // Ankr mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 1, MOCK_GET_LOGS);

    five_ticks(&pic);

    // Check deposit
    // Based on the logs there should be 100000000000000000 icBNB minted for Native to b4any-vxcgx-dm654-xhumb-4pl7k-5kysk-qnjlt-w7hcb-2hd2h-ttzpz-fqe
    let balance = query_call::<Account, Nat>(
        &pic,
        native_ledger_principal(),
        "icrc1_balance_of",
        Account {
            owner: Principal::from_text(
                "b4any-vxcgx-dm654-xhumb-4pl7k-5kysk-qnjlt-w7hcb-2hd2h-ttzpz-fqe",
            )
            .unwrap(),
            subaccount: None,
        },
    );

    assert_eq!(balance, Nat::from(100000000000000000_u128));

    // Withdrawal Section
    // Calling icrc2_approve and giving the permission to minter for taking funds from users principal
    let _approve_result = update_call::<ApproveArgs, Result<Nat, ApproveError>>(
        &pic,
        native_ledger_principal(),
        "icrc2_approve",
        ApproveArgs {
            from_subaccount: None,
            spender: Account {
                owner: minter_principal(),
                subaccount: None,
            },
            amount: Nat::from(
                100_000_000_000_000_000_u128, // .checked_sub(10_000_000_000_000_u128)
                                              // .unwrap(),
            ),
            expected_allowance: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        },
        Some(
            Principal::from_text("b4any-vxcgx-dm654-xhumb-4pl7k-5kysk-qnjlt-w7hcb-2hd2h-ttzpz-fqe")
                .unwrap(),
        ),
    )
    .unwrap();

    five_ticks(&pic);

    // Making the withdrawal request to minter
    let _withdrawal_request_result = update_call::<
        WithdrawalArg,
        Result<RetrieveNativeRequest, WithdrawalError>,
    >(
        &pic,
        minter_principal(),
        "withdraw_native_token",
        WithdrawalArg {
            amount: Nat::from(
                100_000_000_000_000_000_u128
                    .checked_sub(10_000_000_000_000_u128)
                    .unwrap(),
            ),
            recipient: "0x3bcE376777eCFeb93953cc6C1bB957fbAcb1A261".to_string(),
        },
        Some(
            Principal::from_text("b4any-vxcgx-dm654-xhumb-4pl7k-5kysk-qnjlt-w7hcb-2hd2h-ttzpz-fqe")
                .unwrap(),
        ),
    );

    five_ticks(&pic);

    // Advance time for PROCESS_TOKENS_RETRIEVE_TRANSACTIONS_INTERVAL amount.
    pic.advance_time(PROCESS_TOKENS_RETRIEVE_TRANSACTIONS_INTERVAL);

    five_ticks(&pic);

    // At this point there should be an http request for refreshing the fee history
    // Once there is a witdrawal request, The first attempt should be updating fee history
    // Cause there should be a maximum gap of 30 seconds between the previos gas fee estimate
    // we just advance time for amount
    let canister_http_requests = pic.get_canister_http();
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        0,
        MOCK_FEE_HISTORY_RESPONSE,
    );

    five_ticks(&pic);

    let canister_http_requests = pic.get_canister_http();

    // Generating the latest transaction count for inserting the correct noce
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        0,
        MOCK_TRANSACTION_COUNT_LATEST,
    );

    five_ticks(&pic);
    five_ticks(&pic);

    // 4th https out call for sending raw transaction.
    // At this point there should be 2 http_requests
    // [0] public_node eth_sendRawTransaction
    // [1] ankr eth_sendRawTransaction
    let canister_http_requests = pic.get_canister_http();

    // public_node request
    // Trying to simulate real sendrawtransaction since there will only be one successful result and the rest of the nodes will return
    // one of the failed responses(NonceTooLow,NonceTooHigh,etc..,)
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        0,
        MOCK_SEND_TRANSACTION_SUCCESS,
    );

    // ankr request
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        1,
        MOCK_SEND_TRANSACTION_ERROR,
    );

    five_ticks(&pic);

    // 5th getting the finalized transaction count after sending transaction was successful.
    let canister_http_requests = pic.get_canister_http();

    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        0,
        MOCK_TRANSACTION_COUNT_FINALIZED,
    );

    five_ticks(&pic);

    // 6th Getting the transaction receipt.
    // At this point there should be two requests for eth_getTransactionReceipt
    // [0] public_node
    // [1] ankr
    let canister_http_requests = pic.get_canister_http();

    // public_node
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        0,
        MOCK_TRANSACTION_RECEIPT,
    );

    // ankr
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        1,
        MOCK_TRANSACTION_RECEIPT,
    );

    five_ticks(&pic);

    // The transaction should be included into finalized transaction list.
    let get_withdrawal_transaction_by_block_index = update_call::<u64, RetrieveWithdrawalStatus>(
        &pic,
        minter_principal(),
        "retrieve_witdrawal_status",
        2_u64,
        None,
    );
    let expected_transaction_result =
        RetrieveWithdrawalStatus::TxFinalized(TxFinalizedStatus::Success {
            transaction_hash: "0x7a2b7ec2713dd7d5b6539ff683fab66003ad76b9920a9da309558b2e2f8ab3c8"
                .to_string(),
            effective_transaction_fee: Some(Nat::from(63000000000000_u128)),
        });

    assert_eq!(
        get_withdrawal_transaction_by_block_index,
        expected_transaction_result
    );
}

#[test]
fn should_not_deposit_twice() {
    let pic = create_pic();
    create_and_install_minter_plus_dependency_canisters(&pic);

    // The deposit http mock flow is as follow
    // 1st Step: The mock response for get_blockbynumber is generated
    // 2nd Step: The response for eth_feehistory resonse is genrated afterwards,
    // 3rd Step: The response for eth_getlogs response is generated,

    // At this time there should be 2 http reuests:
    // [0] is for eth_getBlockByNumber
    // [1] is for eth_feeHistory
    let canister_http_requests = pic.get_canister_http();

    // 1st Generating mock response for eth_getBlockByNumber
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 0, MOCK_BLOCK_NUMBER);

    // 2nd Generating mock reponse for eth_feehistory
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        1,
        MOCK_FEE_HISTORY_RESPONSE,
    );

    five_ticks(&pic);

    // 3rd generating mock response for eth_getLogs
    // At this time there should be 2 http reuests:
    // [0] is for public_node eth_getLogs
    // [1] is for ankr eth_getLogs
    let canister_http_requests = pic.get_canister_http();

    // publick_node mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 0, MOCK_GET_LOGS);

    // Ankr mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 1, MOCK_GET_LOGS);

    five_ticks(&pic);

    // There should be a gap of at least one minute between each log scraping so we advance time for 1 min
    pic.advance_time(Duration::from_secs(1 * 60));

    // Requesting for another log_scrapping
    let request_result = update_call::<Nat, Result<(), RequestScrapingError>>(
        &pic,
        minter_principal(),
        "request_scraping_logs",
        Nat::from(45944845_u64),
        None,
    );

    assert_eq!(request_result, Ok(()));

    five_ticks(&pic);

    // After reuesting one more time there should be another log scraping request which means we have to
    // follow the same steps but this time we will mock http requests with incorrect responses
    // to check if minter, mints the same reuest twice or not.

    // At this time there should be 1 http reuests:
    // [0] is for eth_getBlockByNumber
    let canister_http_requests = pic.get_canister_http();

    // 1st Generating mock response for eth_getBlockByNumber
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        0,
        MOCK_HIGER_BLOCK_NUMBER,
    );

    five_ticks(&pic);

    // 3rd generating mock response for eth_getLogs
    // At this time there should be 2 http reuests:
    // [0] is for public_node eth_getLogs
    // [1] is for ankr eth_getLogs
    let canister_http_requests = pic.get_canister_http();

    // Generating the same mock eth_getlogs reposne and the minter should detect that these responses are not correct
    // publick_node mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 0, MOCK_GET_LOGS);

    // Ankr mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 1, MOCK_GET_LOGS);

    five_ticks(&pic);

    // Check balance
    // there should only be 100000000000000000 icBNB minted for Native to b4any-vxcgx-dm654-xhumb-4pl7k-5kysk-qnjlt-w7hcb-2hd2h-ttzpz-fqe
    // Decpite receiving two mint events.
    let balance = query_call::<Account, Nat>(
        &pic,
        native_ledger_principal(),
        "icrc1_balance_of",
        Account {
            owner: Principal::from_text(
                "b4any-vxcgx-dm654-xhumb-4pl7k-5kysk-qnjlt-w7hcb-2hd2h-ttzpz-fqe",
            )
            .unwrap(),
            subaccount: None,
        },
    );

    assert_eq!(balance, Nat::from(100000000000000000_u128));
}

// TODO: Test the whole flow for erc20 tokens
#[test]
fn should_deposit_and_withdrawal_erc20() {}

#[test]
fn should_fail_log_scrapping_request_old_block_number() {
    let pic = create_pic();
    create_and_install_minter_plus_dependency_canisters(&pic);

    // The deposit http mock flow is as follow
    // 1st Step: The mock response for get_blockbynumber is generated
    // 2nd Step: The response for eth_feehistory resonse is genrated afterwards,
    // 3rd Step: The response for eth_getlogs response is generated,

    // At this time there should be 2 http reuests:
    // [0] is for eth_getBlockByNumber
    // [1] is for eth_feeHistory
    let canister_http_requests = pic.get_canister_http();

    // 1st Generating mock response for eth_getBlockByNumber
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 0, MOCK_BLOCK_NUMBER);

    // 2nd Generating mock reponse for eth_feehistory
    generate_and_submit_mock_http_response(
        &pic,
        &canister_http_requests,
        1,
        MOCK_FEE_HISTORY_RESPONSE,
    );

    five_ticks(&pic);

    // 3rd generating mock response for eth_getLogs
    // At this time there should be 2 http reuests:
    // [0] is for public_node eth_getLogs
    // [1] is for ankr eth_getLogs
    let canister_http_requests = pic.get_canister_http();

    // publick_node mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 0, MOCK_GET_LOGS);

    // Ankr mock submission
    generate_and_submit_mock_http_response(&pic, &canister_http_requests, 1, MOCK_GET_LOGS);

    five_ticks(&pic);

    // There should be a gap of at least one minute between each log scraping so we advance time for 1 min
    pic.advance_time(Duration::from_secs(1 * 60));

    // Requesting for another log_scrapping
    let request_result = update_call::<Nat, Result<(), RequestScrapingError>>(
        &pic,
        minter_principal(),
        "request_scraping_logs",
        Nat::from(45944645_u64),
        None,
    );

    assert_eq!(
        request_result,
        Err(RequestScrapingError::BlockAlreadyObserved)
    );
}

mod mock_rpc_https_responses {
    use pocket_ic::{common::rest::CanisterHttpRequest, PocketIc};

    use crate::tests::lsm_types::generate_successful_mock_response;

    pub const MOCK_FEE_HISTORY_RESPONSE: &str = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "oldestBlock": "0x2be4eb6",
            "reward": [
                ["0xb2d05e00"]
            ],
            "baseFeePerGas": [
                "0x0",
                "0x0"
            ],
            "gasUsedRatio": [
                0.01189926
            ]
        }
    }"#;

    pub const MOCK_BLOCK_NUMBER: &str = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "baseFeePerGas": "0x0",
            "blobGasUsed": "0x0",
            "difficulty": "0x2",
            "excessBlobGas": "0x0",
            "extraData": "0xd98301040d846765746889676f312e32312e3132856c696e757800000299d9bcf8b23fb860a6069a9c8823266060b144139b402fed5a7c6cfa64adbe236bdaf57abf6f9b826936bdbdd7b544ffba345fbd06bfdd0012edb5d44efb53d04773bebe33d108c631ba5a6e1c1258daafe10785cb919d0683068fa18a6e55ccfcf08c7c917ccce6f84c8402bd0f43a0e87d3407a7a51cc5ce929008888b5e53f8609cf0d1479e873d8e329c237d55308402bd0f44a09180e661bde5e71fbc1fa8fde5b8faafaeaefd8ef6db52290ac21cd7230f7fef806844d3d19ba58d09bf4dc94bb250903644e0dd43e0b78522be95d95dff16e9eb4eb686a35d9a069987c1361b5275e7ed7c468b8d97c6014d55ccded79c6961f101",
            "gasLimit": "0x5f5e100",
            "gasUsed": "0x4995b",
            "hash": "0xc1ff7931ceab1152c911cbb033bb5f6dad378263e3849cb7c5d90711fcbe352c",
            "logsBloom": "0x04000000800000004000004000000000000000000000000080000000000000000100300000010000008000000000000000800000000000000000004000200000000000200000002010000008002000002010000002000000000000000000000a00081020828200000000000000000800080000000000008020000010000000000000000000000000000000000000000040000400040000000000000080400020020010001000002008000000028000000000000000000000000000000040011002000002001000000000000000000000000000000000000100104002000020000010000000000000010000040000010000008000000000004000000000102000",
            "miner": "0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0000000000000000",
            "number": "0x2bd0f45",
            "parentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "parentHash": "0x9180e661bde5e71fbc1fa8fde5b8faafaeaefd8ef6db52290ac21cd7230f7fef",
            "receiptsRoot": "0x1191695d554680c98e403b2e730e6dd3cd0a7732a3f305425c001e70cfd86095",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "size": "0x7f4",
            "stateRoot": "0xa361889a0c1a6446cd37b308cf6cc3ffc6b8b4eaf9d01afe541bb80a9b2ab911",
            "timestamp": "0x6744b156",
            "totalDifficulty": "0x5767939",
            "transactions": [
                "0x92f77e7cd263c5f41d724180ab9ae40f273d601dcfb6d1ce1a4a2c9a44e96061",
                "0xcf9b50e1871932d3ce16af58dc2db2bd9ec6ec70f2dc6ac24197a95ab1f663f0",
                "0xf9617ed37c4fef311da4c37d29adc2ad9e0a8289cea8b365257b23b2a531dfa7",
                "0x5ace3bb62c01dc21e0ed3289181d8a67ce13606ea34d730f6e1983b5cec80ec0",
                "0xcde530df6850bd19f822264791dac4f6730caa8642f65bd3810389bf982babfe",
                "0xf8c98fefa467d3e3b1c4d260feefd58856904ff05c266f92b4cb662eb07801a5",
                "0xbd662557953a0e892e276ab586e2ea0dee9ed8c1ba3c129788216942e8367888"
            ],
            "transactionsRoot": "0x7a4a90d5244d734440282ca816aab466ad480bb05dace99ea23f1ac26749351c",
            "uncles": [],
            "withdrawals": [],
            "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        }
    }"#;

    pub const MOCK_HIGER_BLOCK_NUMBER: &str = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "baseFeePerGas": "0x0",
            "blobGasUsed": "0x0",
            "difficulty": "0x2",
            "excessBlobGas": "0x0",
            "extraData": "0xd98301040d846765746889676f312e32312e3132856c696e757800000299d9bcf8b23fb860a6069a9c8823266060b144139b402fed5a7c6cfa64adbe236bdaf57abf6f9b826936bdbdd7b544ffba345fbd06bfdd0012edb5d44efb53d04773bebe33d108c631ba5a6e1c1258daafe10785cb919d0683068fa18a6e55ccfcf08c7c917ccce6f84c8402bd0f43a0e87d3407a7a51cc5ce929008888b5e53f8609cf0d1479e873d8e329c237d55308402bd0f44a09180e661bde5e71fbc1fa8fde5b8faafaeaefd8ef6db52290ac21cd7230f7fef806844d3d19ba58d09bf4dc94bb250903644e0dd43e0b78522be95d95dff16e9eb4eb686a35d9a069987c1361b5275e7ed7c468b8d97c6014d55ccded79c6961f101",
            "gasLimit": "0x5f5e100",
            "gasUsed": "0x4995b",
            "hash": "0xc1ff7931ceab1152c911cbb033bb5f6dad378263e3849cb7c5d90711fcbe352c",
            "logsBloom": "0x04000000800000004000004000000000000000000000000080000000000000000100300000010000008000000000000000800000000000000000004000200000000000200000002010000008002000002010000002000000000000000000000a00081020828200000000000000000800080000000000008020000010000000000000000000000000000000000000000040000400040000000000000080400020020010001000002008000000028000000000000000000000000000000040011002000002001000000000000000000000000000000000000100104002000020000010000000000000010000040000010000008000000000004000000000102000",
            "miner": "0x1a3d9d7a717d64e6088ac937d5aacdd3e20ca963",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0000000000000000",
            "number": "0x2BD103A",
            "parentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "parentHash": "0x9180e661bde5e71fbc1fa8fde5b8faafaeaefd8ef6db52290ac21cd7230f7fef",
            "receiptsRoot": "0x1191695d554680c98e403b2e730e6dd3cd0a7732a3f305425c001e70cfd86095",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "size": "0x7f4",
            "stateRoot": "0xa361889a0c1a6446cd37b308cf6cc3ffc6b8b4eaf9d01afe541bb80a9b2ab911",
            "timestamp": "0x6744b156",
            "totalDifficulty": "0x5767939",
            "transactions": [
                "0x92f77e7cd263c5f41d724180ab9ae40f273d601dcfb6d1ce1a4a2c9a44e96061",
                "0xcf9b50e1871932d3ce16af58dc2db2bd9ec6ec70f2dc6ac24197a95ab1f663f0",
                "0xf9617ed37c4fef311da4c37d29adc2ad9e0a8289cea8b365257b23b2a531dfa7",
                "0x5ace3bb62c01dc21e0ed3289181d8a67ce13606ea34d730f6e1983b5cec80ec0",
                "0xcde530df6850bd19f822264791dac4f6730caa8642f65bd3810389bf982babfe",
                "0xf8c98fefa467d3e3b1c4d260feefd58856904ff05c266f92b4cb662eb07801a5",
                "0xbd662557953a0e892e276ab586e2ea0dee9ed8c1ba3c129788216942e8367888"
            ],
            "transactionsRoot": "0x7a4a90d5244d734440282ca816aab466ad480bb05dace99ea23f1ac26749351c",
            "uncles": [],
            "withdrawals": [],
            "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        }
    }"#;

    pub const MOCK_GET_LOGS: &str = r#"{
        "jsonrpc": "2.0",
        "id": 3,
        "result": [
            {
                "address": "0x733a1beef5a02990aad285d7ed93fc1b622eef1d",
                "topics": [
                    "0xdeaddf8708b62ae1bf8ec4693b523254aa961b2da6bc5be57f3188ee784d6275",
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x000000000000000000000000000000000000000000000000016345785d8a0000",
                    "0x1de235c6cf77973d181e3d7f5755892a0d4ae76f9c41d1c7a3ce797e4b020000"
                ],
                "data": "0x0000000000000000000000005d737f982696fe2fe4ef1c7584e914c3a8e44d540000000000000000000000000000000000000000000000000000000000000000",
                "blockNumber": "0x2bd0f45",
                "transactionHash": "0xcde530df6850bd19f822264791dac4f6730caa8642f65bd3810389bf982babfe",
                "transactionIndex": "0x4",
                "blockHash": "0xc1ff7931ceab1152c911cbb033bb5f6dad378263e3849cb7c5d90711fcbe352c",
                "logIndex": "0x3",
                "removed": false
            }
        ]
    }"#;

    pub const _MOCK_GET_LOGS_ERC20: &str = r#"{
        "jsonrpc": "2.0",
        "id": 3,
        "result": [
            {
                "address": "0x733a1beef5a02990aad285d7ed93fc1b622eef1d",
                "topics": [
                    "0xdeaddf8708b62ae1bf8ec4693b523254aa961b2da6bc5be57f3188ee784d6275",
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0x000000000000000000000000000000000000000000000000016345785d8a0000",
                    "0x1de235c6cf77973d181e3d7f5755892a0d4ae76f9c41d1c7a3ce797e4b020000"
                ],
                "data": "0x0000000000000000000000005d737f982696fe2fe4ef1c7584e914c3a8e44d540000000000000000000000000000000000000000000000000000000000000000",
                "blockNumber": "0x2bd0f45",
                "transactionHash": "0xcde530df6850bd19f822264791dac4f6730caa8642f65bd3810389bf982babfe",
                "transactionIndex": "0x4",
                "blockHash": "0xc1ff7931ceab1152c911cbb033bb5f6dad378263e3849cb7c5d90711fcbe352c",
                "logIndex": "0x3",
                "removed": false
            }
        ]
    }"#;

    pub const MOCK_TRANSACTION_COUNT_LATEST: &str = r#"{"id":1,"jsonrpc":"2.0","result":"0x0"}"#;
    pub const MOCK_TRANSACTION_COUNT_FINALIZED: &str = r#"{"id":1,"jsonrpc":"2.0","result":"0x1"}"#;

    pub const MOCK_TRANSACTION_RECEIPT: &str = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "blockHash": "0xa99ddaae8a1488af78eab4942d91e7c3640479ee7162c5ae3d1e3fe325599b9c",
            "blockNumber": "0x2bcf802",
            "contractAddress": null,
            "cumulativeGasUsed": "0x1f00c",
            "effectiveGasPrice": "0xb2d05e00",
            "from": "0xffd465f2655e4ee9164856715518f4287b22a49d",
            "gasUsed": "0x5208",
            "logs": [],
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "status": "0x1",
            "to": "0x3bce376777ecfeb93953cc6c1bb957fbacb1a261",
            "transactionHash": "0x7a2b7ec2713dd7d5b6539ff683fab66003ad76b9920a9da309558b2e2f8ab3c8",
            "transactionIndex": "0x3",
            "type": "0x2"
        }
    }"#;

    pub const MOCK_SEND_TRANSACTION_ERROR: &str = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32000,
            "message": "already known"
        }
    }"#;

    pub const MOCK_SEND_TRANSACTION_SUCCESS: &str = r#"{
        "jsonrpc": "2.0",
        "id": 1,
        "result": "0x7a2b7ec2713dd7d5b6539ff683fab66003ad76b9920a9da309558b2e2f8ab3c8"
    }"#;

    pub fn generate_and_submit_mock_http_response(
        pic: &PocketIc,
        http_requests_list: &Vec<CanisterHttpRequest>,
        https_request_index: usize,
        http_json_response: &str,
    ) {
        let http_request = &http_requests_list[https_request_index];

        let generated_mock_response = generate_successful_mock_response(
            http_request.subnet_id,
            http_request.request_id,
            http_json_response.as_bytes().to_vec(),
        );

        pic.mock_canister_http_response(generated_mock_response);
    }
}
