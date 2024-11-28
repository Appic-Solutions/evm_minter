use candid::Nat;
use pocket_ic::common::rest::{CanisterHttpReply, CanisterHttpResponse, MockCanisterHttpResponse};

use crate::{endpoints::Eip1559TransactionPrice, tests::pocket_ic_helpers::five_ticks};

use super::pocket_ic_helpers::{
    create_pic, intialize_minter::create_and_install_minter_plus_dependency_canisters,
    minter_principal, query_call,
};

#[test]
fn should_get_estimated_eip1559_transaction_price() {
    let pic = create_pic();
    create_and_install_minter_plus_dependency_canisters(&pic);

    let canister_http_requests = pic.get_canister_http();

    let fee_history_http_request = &canister_http_requests[1];

    let body = 
        r#"{"jsonrpc":"2.0","id":1,"result":{"oldestBlock":"0x2be4eb6","reward":[["0xb2d05e00"]],"baseFeePerGas":["0x0","0x0"],"gasUsedRatio":[0.01189926]}}"#.as_bytes();

    let mock_canister_http_response = MockCanisterHttpResponse {
        subnet_id: fee_history_http_request.subnet_id,
        request_id: fee_history_http_request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![],
            body: body.to_vec(),
        }),
        additional_responses: vec![],
    };

    pic.mock_canister_http_response(mock_canister_http_response);

    five_ticks(&pic);

    // Get eip1559 transaction price
    let transaction_price = query_call::<(), Eip1559TransactionPrice>(
        &pic,
        minter_principal(),
        "eip_1559_transaction_price",
        (),
    );
    let expected_price=Eip1559TransactionPrice { gas_limit: Nat::from(21000_u64), max_fee_per_gas: Nat::from(3000000000_u64), max_priority_fee_per_gas: Nat::from(3000000000_u64), max_transaction_fee: Nat::from(63000000000000_u64), timestamp: Some(1620328630000000056_u64) };
    assert_eq!(expected_price,transaction_price);

}

#[test]
fn should_deposit_and_withdrawal_native() {}

#[test]
fn should_not_deposit_twice() {}

#[test]
fn should_deposit_and_withdrawal_erc20() {}

#[test]
fn should_not_allow_withdrawal_request_from_same_principal_more_than_once() {}

#[test]
fn should_reimburse() {}

#[test]
fn should_fail_log_scrapping_request_invalid_block_number() {}
