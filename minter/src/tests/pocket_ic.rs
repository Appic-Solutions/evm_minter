const MINTER_WASM_BYTES: &[u8] =
    include_bytes!("../../../target/wasm32-unknown-unknown/release/evm_minter.wasm");

use candid::{encode_one, CandidType, Nat, Principal};
use ic_management_canister_types::Payload;
use pocket_ic::{PocketIc, PocketIcBuilder, WasmResult};

use crate::{
    endpoints::{CandidBlockTag, MinterInfo},
    lifecycle::{InitArg, MinterArg, UpgradeArg},
};

#[test]
fn should_create_and_install_and_upgrade_minter_casniter() {
    let pic = create_pic();

    let canister_id = create_minter_canister(&pic);

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

    install_minter_canister(&pic, canister_id, init_bytes);

    five_ticks(&pic);

    let minter_info = query_call::<_, MinterInfo>(&pic, canister_id, "get_minter_info", ());

    assert_eq!(
        minter_info,
        MinterInfo {
            minter_address: Some("0x3b13DAFE68a5FDe26eACb4064559d97c1e4FB41a".to_string()),
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
        }
    );

    let upgrade_args = MinterArg::UpgradeArg(UpgradeArg {
        native_minimum_withdrawal_amount: Some(Nat::from(200_000_000_000_000_u128)),
        native_ledger_transfer_fee: None,
        next_transaction_nonce: None,
        last_scraped_block_number: Some(Nat::from(100935911_u128)),
        evm_rpc_id: Some("7hfb6-caaaa-aaaar-qadga-cai".parse().unwrap()),
        helper_contract_address: None,
        block_height: None,
    });
    let upgrade_bytes = candid::encode_one(upgrade_args).unwrap();

    upgrade_minter_casniter(&pic, canister_id, upgrade_bytes);

    five_ticks(&pic);

    let minter_info_after_upgrade =
        query_call::<_, MinterInfo>(&pic, canister_id, "get_minter_info", ());

    assert_eq!(
        minter_info_after_upgrade,
        MinterInfo {
            minter_address: Some("0x3b13DAFE68a5FDe26eACb4064559d97c1e4FB41a".to_string()),
            helper_smart_contract_address: Some(
                "0x733a1BEeF5A02990aAD285d7ED93fc1b622EeF1d".to_string()
            ),
            supported_erc20_tokens: Some(vec![]),
            minimum_withdrawal_amount: Some(Nat::from(200000000000000_u128)),
            block_height: Some(CandidBlockTag::Latest),
            last_observed_block_number: None,
            native_balance: Some(Nat::from(0_u128)),
            last_gas_fee_estimate: None,
            erc20_balances: Some(vec![]),
            last_scraped_block_number: Some(Nat::from(100935911_u128)),
            native_twin_token_ledger_id: Some("n44gr-qyaaa-aaaam-qbuha-cai".parse().unwrap()),
            swap_canister_id: None,
            ledger_suite_manager_id: Some("kmcdp-4yaaa-aaaag-ats3q-cai".parse().unwrap())
        }
    );
}

fn query_call<I, O>(pic: &PocketIc, canister_id: Principal, method: &str, payload: I) -> O
where
    O: CandidType + for<'a> serde::Deserialize<'a>,
    I: CandidType,
{
    let wasm_result = pic
        .query_call(
            canister_id,
            sender_principal(),
            method,
            encode_call_args(payload).unwrap(),
        )
        .unwrap();

    decode_wasm_result::<O>(wasm_result).unwrap()
}

fn encode_call_args<I>(args: I) -> Result<Vec<u8>, ()>
where
    I: CandidType,
{
    Ok(candid::encode_one(args).unwrap())
}

fn decode_wasm_result<O>(wasm_result: WasmResult) -> Result<O, ()>
where
    O: CandidType + for<'a> serde::Deserialize<'a>,
{
    match wasm_result {
        pocket_ic::WasmResult::Reply(vec) => Ok(candid::decode_one(&vec).unwrap()),
        pocket_ic::WasmResult::Reject(_) => Err(()),
    }
}

fn create_pic() -> PocketIc {
    PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .build()
}

fn create_minter_canister(pic: &PocketIc) -> Principal {
    pic.create_canister_with_id(
        Some(sender_principal()),
        None,
        Principal::from_text("2ztvj-yaaaa-aaaap-ahiza-cai").unwrap(),
    )
    .expect("Should create the casniter")
}

fn install_minter_canister(pic: &PocketIc, canister_id: Principal, init_bytes: Vec<u8>) {
    pic.install_canister(
        canister_id,
        MINTER_WASM_BYTES.to_vec(),
        init_bytes,
        Some(sender_principal()),
    );
}

fn upgrade_minter_casniter(pic: &PocketIc, canister_id: Principal, upgrade_bytes: Vec<u8>) {
    pic.upgrade_canister(
        canister_id,
        MINTER_WASM_BYTES.to_vec(),
        upgrade_bytes,
        Some(sender_principal()),
    )
    .unwrap()
}

fn five_ticks(pic: &PocketIc) {
    pic.tick();
    pic.tick();
    pic.tick();
    pic.tick();
    pic.tick();
}

fn sender_principal() -> Principal {
    Principal::from_text("matbl-u2myk-jsllo-b5aw6-bxboq-7oon2-h6wmo-awsxf-pcebc-4wpgx-4qe").unwrap()
}
