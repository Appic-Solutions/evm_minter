const MINTER_WASM_BYTES: &[u8] =
    include_bytes!("../../../target/wasm32-unknown-unknown/release/evm_minter.wasm");

use candid::{encode_one, Nat, Principal};
use minicbor::Encode;
use pocket_ic::{
    common::rest::RawEffectivePrincipal, management_canister::CanisterSettings, PocketIc,
};
use serde::Serialize;

use crate::{
    endpoints::{CandidBlockTag, MinterInfo},
    lifecycle::{InitArg, MinterArg},
};

#[test]
fn should_create_and_install_minter_casniter() {
    let pic = PocketIc::new();
    let canister_id = pic
        .create_canister_with_id(
            Some(
                Principal::from_text(
                    "matbl-u2myk-jsllo-b5aw6-bxboq-7oon2-h6wmo-awsxf-pcebc-4wpgx-4qe",
                )
                .unwrap(),
            ),
            None,
            Principal::from_text("2ztvj-yaaaa-aaaap-ahiza-cai").unwrap(),
        )
        .expect("Should create the casniter");

    assert_eq!(
        canister_id,
        Principal::from_text("2ztvj-yaaaa-aaaap-ahiza-cai").unwrap()
    );

    pic.add_cycles(canister_id, 1_000_000_000_000);

    let init_args = MinterArg::InitArg(InitArg {
        evm_network: crate::evm_config::EvmNetwork::BSCTestnet,
        ecdsa_key_name: "key_1".to_string(),
        helper_contract_address: Some("0x733a1beef5a02990aad285d7ed93fc1b622eef1d".to_string()),
        native_ledger_id: "n44gr-qyaaa-aaaam-qbuha-cai".parse().unwrap(),
        native_index_id: "eysav-tyaaa-aaaap-akqfq-cai".parse().unwrap(),
        native_symbol: "icTestBNB".to_string(),
        block_height: CandidBlockTag::Latest,
        native_minimum_withdrawal_amount: Nat::from(100_000_000_000_000_u128),
        native_ledger_transfer_fee: Nat::from(10_000_000_000_000_u128),
        next_transaction_nonce: Nat::from(0_u128),
        last_scraped_block_number: Nat::from(45935911_u128),
        min_max_priority_fee_per_gas: Nat::from(3_000_000_000_u128),
        ledger_suite_manager_id: "kmcdp-4yaaa-aaaag-ats3q-cai".parse().unwrap(),
    });
    let init_bytes = candid::encode_one(init_args).unwrap();

    pic.install_canister(
        canister_id,
        MINTER_WASM_BYTES.to_vec(),
        init_bytes,
        Some(
            Principal::from_text("matbl-u2myk-jsllo-b5aw6-bxboq-7oon2-h6wmo-awsxf-pcebc-4wpgx-4qe")
                .unwrap(),
        ),
    );

    let call_result = pic
        .query_call(
            canister_id,
            Principal::from_text("matbl-u2myk-jsllo-b5aw6-bxboq-7oon2-h6wmo-awsxf-pcebc-4wpgx-4qe")
                .unwrap(),
            "get_minter_info",
            encode_one(()).unwrap(),
        )
        .unwrap();

    let decoded_result: Result<MinterInfo, ()> = match call_result {
        pocket_ic::WasmResult::Reply(vec) => Ok(candid::decode_one(&vec).unwrap()),
        pocket_ic::WasmResult::Reject(_) => Err(()),
    };

    assert_eq!(
        decoded_result,
        Ok(MinterInfo {
            minter_address: None,
            helper_smart_contract_address: Some(
                "0x733a1BEeF5A02990aAD285d7ED93fc1b622EeF1d".to_string()
            ),
            supported_erc20_tokens: Some(vec![]),
            minimum_withdrawal_amount: Some(Nat::from(100000000000000_u128)),
            block_height: Some(CandidBlockTag::Latest),
            last_observed_block_number: None,
            native_balance: Some(Nat::from(0_u128)),
            last_gas_fee_estimate: None,
            erc20_balances: Some(vec![]),
            last_scraped_block_number: Some(Nat::from(45935911_u128)),
            native_twin_token_ledger_id: Some("n44gr-qyaaa-aaaam-qbuha-cai".parse().unwrap()),
            swap_canister_id: None,
            ledger_suite_manager_id: Some("kmcdp-4yaaa-aaaag-ats3q-cai".parse().unwrap())
        })
    );
}
