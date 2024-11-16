// Ledger suite manager helper functions
// This module produces the wasm hashes that are used by native twin ledger and index casniters
// With the produced wasm hash the necessary type for calling the add_new_native_ls function of lsm(Ledger suite manager) is then produced.
// As a next step an intercasniter call will happen at the init time to add the native Ledger suite the the LSM(ledger suite manager).
// This mechanism is desgined to maintain cycles balance of twin native ledger suite checked through the manager casniter.

use std::fmt::{Debug, Display, Formatter};

use crate::management::Reason;
use crate::{lifecycle::InitArg, logs::DEBUG, management::CallError};
use candid::{self, CandidType, Nat, Principal};
use ic_canister_log::log;
use ic_cdk;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::ByteArray;

pub(crate) const LEDGER_BYTECODE: &[u8] =
    include_bytes!("../../wasm/index_ng_canister_u256.raw.wasm");
pub(crate) const INDEX_BYTECODE: &[u8] = include_bytes!("../../wasm/ledger_canister_u256.raw.wasm");

const ADD_NATIVE_LS_METHOD: &str = "add_new_native_ls";

// Define Hash types
const WASM_HASH_LENGTH: usize = 32;
pub type WasmHash = Hash<WASM_HASH_LENGTH>;

impl WasmHash {
    pub fn new(binary: Vec<u8>) -> Self {
        WasmHash::from(ic_crypto_sha2::Sha256::hash(binary.as_slice()))
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize)]
#[serde(from = "serde_bytes::ByteArray<N>", into = "serde_bytes::ByteArray<N>")]
pub struct Hash<const N: usize>([u8; N]);

impl<const N: usize> Default for Hash<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> Display for Hash<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> From<ByteArray<N>> for Hash<N> {
    fn from(value: ByteArray<N>) -> Self {
        Self(value.into_array())
    }
}

impl<const N: usize> From<Hash<N>> for ByteArray<N> {
    fn from(value: Hash<N>) -> Self {
        ByteArray::new(value.0)
    }
}

impl<const N: usize> AsRef<[u8]> for Hash<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Hash<N> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> From<Hash<N>> for [u8; N] {
    fn from(value: Hash<N>) -> Self {
        value.0
    }
}

#[derive(Clone, PartialEq, Debug, CandidType, Serialize, candid::Deserialize)]
pub struct InstalledNativeLedgerSuite {
    pub symbol: String,
    pub ledger: Principal,
    pub ledger_wasm_hash: String,
    pub index: Principal,
    pub index_wasm_hash: String,
    pub archives: Vec<Principal>,
    pub chain_id: Nat,
}

#[derive(Clone, PartialEq, Debug, CandidType, Serialize, candid::Deserialize)]
pub enum InvalidNativeInstalledCanistersError {
    WasmHashError,
    TokenAlreadyManaged,
    AlreadyManagedPrincipals,
}

#[derive(Clone, PartialEq, Debug)]
pub struct LSMClient(Principal);

impl LSMClient {
    pub fn new(lsm_id: Principal) -> Self {
        Self(lsm_id)
    }
    pub fn new_native_ls(
        &self,
        symbol: String,
        ledger_id: Principal,
        index_id: Principal,
        chain_id: u64,
    ) -> InstalledNativeLedgerSuite {
        return InstalledNativeLedgerSuite {
            symbol,
            ledger: ledger_id,
            ledger_wasm_hash: WasmHash::new(LEDGER_BYTECODE.to_vec()).to_string(),
            index: index_id,
            index_wasm_hash: WasmHash::new(INDEX_BYTECODE.to_vec()).to_string(),
            archives: vec![],
            chain_id: Nat::from(chain_id),
        };
    }
    // Priduces the InstalledNativeLedgerSuite through init args
    pub async fn call_lsm_to_add_twin_native(
        self,
        inti_args: InitArg,
    ) -> Result<(), InvalidNativeInstalledCanistersError> {
        let chain_id = inti_args.evm_network.chain_id();

        let native_ls_args = self.new_native_ls(
            inti_args.native_symbol,
            inti_args.native_ledger_id,
            inti_args.native_index_id,
            chain_id,
        );

        let result: Result<(), InvalidNativeInstalledCanistersError> = self
            .call_canister(self.0, ADD_NATIVE_LS_METHOD, native_ls_args)
            .await
            .expect("This call should be successful for a successful initilization");

        result
    }

    async fn call_canister<I, O>(
        &self,
        canister_id: Principal,
        method: &str,
        args: I,
    ) -> Result<O, CallError>
    where
        I: CandidType + Debug + Send + 'static,
        O: CandidType + DeserializeOwned + Debug + 'static,
    {
        log!(
            DEBUG,
            "Calling canister '{}' with method '{}' and payload '{:?}'",
            canister_id,
            method,
            args
        );
        let res: Result<(O,), _> = ic_cdk::api::call::call(canister_id, method, (&args,)).await;
        log!(
            DEBUG,
            "Result of calling canister '{}' with method '{}' and payload '{:?}': {:?}",
            canister_id,
            method,
            args,
            res
        );

        match res {
            Ok((output,)) => Ok(output),
            Err((code, msg)) => Err(CallError {
                method: method.to_string(),
                reason: Reason::from_reject(code, msg),
            }),
        }
    }
}
