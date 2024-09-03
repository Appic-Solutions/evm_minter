use crate::map::MultiKeyMap;
use crate::numeric::{LedgerMintIndex, TransactionNonce};
use crate::rpc_declrations::Hash;
use crate::tx::{FinalizedEip1559Transaction, SignedTransactionRequest, TransactionRequest};
use crate::{
    checked_amount::CheckedAmountOf,
    eth_types::Address,
    numeric::{Erc20TokenAmount, Erc20Value, LedgerBurnIndex, Wei},
};
use candid::Principal;
use icrc_ledger_types::icrc1::account::Account;
use minicbor::{Decode, Encode};
use serde::de::value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use super::audit::EventType;

#[derive(Clone, Eq, PartialEq, Encode, Decode)]
#[cbor(transparent)]
pub struct Subaccount(#[cbor(n(0), with = "minicbor::bytes")] pub [u8; 32]);

impl fmt::Debug for Subaccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Naticve token withdrawal request issued by the user.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct NativeWithdrawlRequest {
    /// The NAtive token amount that the receiver will get, not accounting for the EVM transaction fees.
    #[n(0)]
    pub withdrawal_amount: Wei,
    /// The address to which the minter will send ETH.
    #[n(1)]
    pub destination: Address,
    /// The transaction ID of the native burn operation.
    #[cbor(n(2), with = "crate::cbor::id")]
    pub ledger_burn_index: LedgerBurnIndex,
    /// The owner of the account from which the minter burned native.
    #[cbor(n(3), with = "crate::cbor::principal")]
    pub from: Principal,
    /// The subaccount from which the minter burned native.
    #[n(4)]
    pub from_subaccount: Option<Subaccount>,
    /// The IC time at which the withdrawal request arrived.
    #[n(5)]
    pub created_at: Option<u64>,
}

/// ERC-20 withdrawal request issued by the user.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct Erc20WithdrawalRequest {
    /// Amount of burn Native token that can be used to pay for the EVM transaction fees.
    #[n(0)]
    pub max_transaction_fee: Wei,
    /// The ERC-20 amount that the receiver will get.
    #[n(1)]
    pub withdrawal_amount: Erc20Value,
    /// The recipient's address of the sent ERC-20 tokens.
    #[n(2)]
    pub destination: Address,
    /// The transaction ID of the Native token burn operation on the native token ledger.
    #[cbor(n(3), with = "crate::cbor::id")]
    pub native_ledger_burn_index: LedgerBurnIndex,
    /// Address of the ERC-20 smart contract that is the message call's recipient.
    #[n(4)]
    pub erc20_contract_address: Address,
    /// The ERC20 ledger on which the minter burned the ERC20 tokens.
    #[cbor(n(5), with = "crate::cbor::principal")]
    pub erc20_ledger_id: Principal,
    /// The transaction ID of the ERC20 burn operation on the ERC20 ledger.
    #[cbor(n(6), with = "crate::cbor::id")]
    pub erc20_ledger_burn_index: LedgerBurnIndex,
    /// The owner of the account from which the minter burned native.
    #[cbor(n(7), with = "crate::cbor::principal")]
    pub from: Principal,
    /// The subaccount from which the minter burned native.
    #[n(8)]
    pub from_subaccount: Option<Subaccount>,
    /// The IC time at which the withdrawal request arrived.
    #[n(9)]
    pub created_at: u64,
}

struct DebugPrincipal<'a>(&'a Principal);

impl fmt::Debug for DebugPrincipal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for NativeWithdrawlRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let NativeWithdrawlRequest {
            withdrawal_amount,
            destination,
            ledger_burn_index,
            from,
            from_subaccount,
            created_at,
        } = self;
        f.debug_struct("NativeWithdrawRequest")
            .field("withdrawal_amount", withdrawal_amount)
            .field("destination", destination)
            .field("ledger_burn_index", ledger_burn_index)
            .field("from", &DebugPrincipal(from))
            .field("from_subaccount", from_subaccount)
            .field("created_at", created_at)
            .finish()
    }
}

impl fmt::Debug for Erc20WithdrawalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let Erc20WithdrawalRequest {
            max_transaction_fee,
            withdrawal_amount,
            destination,
            native_ledger_burn_index,
            erc20_contract_address,
            erc20_ledger_id,
            erc20_ledger_burn_index,
            from,
            from_subaccount,
            created_at,
        } = self;
        f.debug_struct("Erc20WithdrawalRequest")
            .field("max_transaction_fee", max_transaction_fee)
            .field("withdrawal_amount", withdrawal_amount)
            .field("erc20_contract_address", erc20_contract_address)
            .field("destination", destination)
            .field("native_ledger_burn_index", native_ledger_burn_index)
            .field("ckerc20_ledger_id", &DebugPrincipal(erc20_ledger_id))
            .field("ckerc20_ledger_burn_index", erc20_ledger_burn_index)
            .field("from", &DebugPrincipal(from))
            .field("from_subaccount", from_subaccount)
            .field("created_at", created_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum WithdrawalSearchParameter {
    ByWithdrawalId(LedgerBurnIndex),
    ByRecipient(Address),
    BySenderAccount(Account),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum WithdrawalRequest {
    Native(NativeWithdrawlRequest),
    Erc20(Erc20WithdrawalRequest),
}

impl WithdrawalRequest {
    pub fn native_ledger_burn_index(&self) -> LedgerBurnIndex {
        match self {
            WithdrawalRequest::Native(request) => request.ledger_burn_index,
            WithdrawalRequest::Erc20(request) => request.native_ledger_burn_index,
        }
    }

    pub fn created_at(&self) -> Option<u64> {
        match self {
            WithdrawalRequest::Native(request) => request.created_at,
            WithdrawalRequest::Erc20(request) => Some(request.created_at),
        }
    }

    /// Address to which the funds are to be sent to.
    pub fn payee(&self) -> Address {
        match self {
            WithdrawalRequest::Native(request) => request.destination,
            WithdrawalRequest::Erc20(request) => request.destination,
        }
    }

    /// Address to which the transaction is to be sent to.
    pub fn destination(&self) -> Address {
        match self {
            WithdrawalRequest::Native(request) => request.destination,
            WithdrawalRequest::Erc20(request) => request.erc20_contract_address,
        }
    }

    pub fn from(&self) -> Principal {
        match self {
            WithdrawalRequest::Native(request) => request.from,
            WithdrawalRequest::Erc20(request) => request.from,
        }
    }

    pub fn from_subaccount(&self) -> &Option<Subaccount> {
        match self {
            WithdrawalRequest::Native(request) => &request.from_subaccount,
            WithdrawalRequest::Erc20(request) => &request.from_subaccount,
        }
    }

    pub fn into_accepted_withdrawal_request_event(self) -> EventType {
        match self {
            WithdrawalRequest::Native(request) => {
                EventType::AcceptedNativeWithdrawalRequest(request)
            }
            WithdrawalRequest::Erc20(request) => EventType::AcceptedErc20WithdrawalRequest(request),
        }
    }

    pub fn match_parameter(&self, parameter: &WithdrawalSearchParameter) -> bool {
        use WithdrawalSearchParameter::*;
        match parameter {
            ByWithdrawalId(index) => &self.native_ledger_burn_index() == index,
            ByRecipient(address) => &self.payee() == address,
            BySenderAccount(Account { owner, subaccount }) => {
                &self.from() == owner && self.from_subaccount() == &subaccount.map(Subaccount)
            }
        }
    }
}

impl From<NativeWithdrawlRequest> for WithdrawalRequest {
    fn from(value: NativeWithdrawlRequest) -> Self {
        WithdrawalRequest::Native(value)
    }
}

impl From<Erc20WithdrawalRequest> for WithdrawalRequest {
    fn from(value: Erc20WithdrawalRequest) -> Self {
        WithdrawalRequest::Erc20(value)
    }
}

// Reimbursed Types
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub enum ReimbursementIndex {
    #[n(0)]
    Native {
        /// Burn index on the Native token ledger ledger
        #[cbor(n(0), with = "crate::cbor::id")]
        ledger_burn_index: LedgerBurnIndex,
    },
    #[n(1)]
    Erc20 {
        #[cbor(n(0), with = "crate::cbor::id")]
        native_ledger_burn_index: LedgerBurnIndex,
        /// The Erc20 ledger canister ID identifying the ledger on which the burn to be reimbursed was made.
        #[cbor(n(1), with = "crate::cbor::principal")]
        ledger_id: Principal,
        /// Burn index on the Erc20 ledger
        #[cbor(n(2), with = "crate::cbor::id")]
        erc20_ledger_burn_index: LedgerBurnIndex,
    },
}

impl From<&WithdrawalRequest> for ReimbursementIndex {
    fn from(value: &WithdrawalRequest) -> Self {
        match value {
            WithdrawalRequest::Native(request) => ReimbursementIndex::Native {
                ledger_burn_index: request.ledger_burn_index,
            },
            WithdrawalRequest::Erc20(request) => ReimbursementIndex::Erc20 {
                native_ledger_burn_index: request.native_ledger_burn_index,
                ledger_id: request.erc20_ledger_id,
                erc20_ledger_burn_index: request.erc20_ledger_burn_index,
            },
        }
    }
}

impl ReimbursementIndex {
    pub fn withdrawal_id(&self) -> LedgerBurnIndex {
        match self {
            ReimbursementIndex::Native { ledger_burn_index } => *ledger_burn_index,
            ReimbursementIndex::Erc20 {
                native_ledger_burn_index,
                ..
            } => *native_ledger_burn_index,
        }
    }
    pub fn burn_in_block(&self) -> LedgerBurnIndex {
        match self {
            ReimbursementIndex::Native { ledger_burn_index } => *ledger_burn_index,
            ReimbursementIndex::Erc20 {
                erc20_ledger_burn_index,
                ..
            } => *erc20_ledger_burn_index,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct ReimbursementRequest {
    /// Burn index on the ledger that should be reimbursed.
    #[cbor(n(0), with = "crate::cbor::id")]
    pub ledger_burn_index: LedgerBurnIndex,
    /// The amount that should be reimbursed in the smallest denomination.
    #[n(1)]
    pub reimbursed_amount: Erc20TokenAmount,
    #[cbor(n(2), with = "crate::cbor::principal")]
    pub to: Principal,
    #[n(3)]
    pub to_subaccount: Option<Subaccount>,
    /// Transaction hash of the failed ETH transaction.
    /// We use this hash to link the mint reimbursement transaction
    /// on the ledger with the failed ETH transaction.
    #[n(4)]
    pub transaction_hash: Option<Hash>,
}

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct Reimbursed {
    #[cbor(n(0), with = "crate::cbor::id")]
    pub reimbursed_in_block: LedgerMintIndex,
    #[cbor(n(1), with = "crate::cbor::id")]
    pub burn_in_block: LedgerBurnIndex,
    /// The amount reimbursed in the smallest denomination.
    #[n(2)]
    pub reimbursed_amount: Erc20TokenAmount,
    #[n(3)]
    pub transaction_hash: Option<Hash>,
}

pub type ReimbursedResult = Result<Reimbursed, ReimbursedError>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReimbursedError {
    /// Whether reimbursement was minted or not is unknown,
    /// most likely because there was an unexpected panic in the callback.
    /// The reimbursement request is quarantined to avoid any double minting and
    /// will not be further processed without manual intervention.
    Quarantined,
}

/// State machine holding EVM transactions issued by the minter.
/// Overall the transaction lifecycle is as follows:
/// 1. The user's withdrawal request is enqueued and processed in a FIFO order.
/// 2. A transaction is created by either consuming a withdrawal request
///    (the first time a transaction is created for that nonce and burn index)
///    or re-submitting an already sent transaction for that nonce and burn index.
/// 3. The transaction is signed via threshold ECDSA and recorded by either consuming the
///    previously created transaction or re-submitting an already sent transaction as is.
/// 4. The transaction is sent to EVM. There may have been multiple
///    sent transactions for that nonce and burn index in case of resubmissions.
/// 5. For a given nonce (and burn index), at most one sent transaction is finalized.
///    The others sent transactions for that nonce were never mined and can be discarded.
/// 6. If a given transaction fails the minter will reimburse the user who requested the
///    withdrawal with the corresponding amount minus fees.
/// #[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transactions {
    pub(in crate::state) pending_withdrawal_requests: VecDeque<WithdrawalRequest>,
    // Processed withdrawal requests (transaction created, sent, or finalized).
    pub(in crate::state) processed_withdrawal_requests:
        BTreeMap<LedgerBurnIndex, WithdrawalRequest>,
    pub(in crate::state) created_tx:
        MultiKeyMap<TransactionNonce, LedgerBurnIndex, TransactionRequest>,
    pub(in crate::state) sent_tx:
        MultiKeyMap<TransactionNonce, LedgerBurnIndex, Vec<SignedTransactionRequest>>,
    pub(in crate::state) finalized_tx:
        MultiKeyMap<TransactionNonce, LedgerBurnIndex, FinalizedEip1559Transaction>,
    pub(in crate::state) next_nonce: TransactionNonce,

    pub(in crate::state) maybe_reimburse: BTreeSet<LedgerBurnIndex>,
    pub(in crate::state) reimbursement_requests: BTreeMap<ReimbursementIndex, ReimbursementRequest>,
    pub(in crate::state) reimbursed: BTreeMap<ReimbursementIndex, ReimbursedResult>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateTransactionError {
    InsufficientTransactionFee {
        native_ledger_burn_index: LedgerBurnIndex,
        allowed_max_transaction_fee: Wei,
        actual_max_transaction_fee: Wei,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResubmitTransactionError {
    InsufficientTransactionFee {
        ledger_burn_index: LedgerBurnIndex,
        transaction_nonce: TransactionNonce,
        allowed_max_transaction_fee: Wei,
        max_transaction_fee: Wei,
    },
}

impl Transactions {
    pub fn new(next_nonce: TransactionNonce) -> Self {
        Self {
            pending_withdrawal_requests: VecDeque::new(),
            processed_withdrawal_requests: BTreeMap::new(),
            created_tx: MultiKeyMap::default(),
            sent_tx: MultiKeyMap::default(),
            finalized_tx: MultiKeyMap::default(),
            next_nonce,
            maybe_reimburse: Default::default(),
            reimbursement_requests: Default::default(),
            reimbursed: Default::default(),
        }
    }

    pub fn next_transaction_nonce(&self) -> TransactionNonce {
        self.next_nonce
    }

    pub fn update_next_transaction_nonce(&mut self, new_nonce: TransactionNonce) {
        self.next_nonce = new_nonce;
    }

    pub fn reimbursement_requests_iter(
        &self,
    ) -> impl Iterator<Item = (&ReimbursementIndex, &ReimbursementRequest)> {
        self.reimbursement_requests.iter()
    }

    pub fn reimbursed_transactions_iter(
        &self,
    ) -> impl Iterator<Item = (&ReimbursementIndex, &ReimbursedResult)> {
        self.reimbursed.iter()
    }

    fn find_reimbursed_transaction_by_native_token_ledger_burn_index(
        &self,
        searched_burn_index: &LedgerBurnIndex,
    ) -> Option<&ReimbursedResult> {
        self.reimbursed
            .iter()
            .find_map(|(index, value)| match index {
                ReimbursementIndex::Native { ledger_burn_index }
                    if ledger_burn_index == searched_burn_index =>
                {
                    Some(value)
                }
                ReimbursementIndex::Erc20 {
                    native_ledger_burn_index,
                    ..
                } if native_ledger_burn_index == searched_burn_index => Some(value),
                _ => None,
            })
    }

    pub fn record_withdrawal_request<R: Into<WithdrawalRequest>>(&mut self, request: R) {
        let request: WithdrawalRequest = request.into();
        let burn_index = request.native_ledger_burn_index();
        if self
            .pending_withdrawal_requests
            .iter()
            .any(|r| r.native_ledger_burn_index() == burn_index)
            || self.created_tx.contains_alt(&burn_index)
            || self.sent_tx.contains_alt(&burn_index)
            || self.finalized_tx.contains_alt(&burn_index)
        {
            panic!("BUG: duplicate Native ledger burn index {burn_index}");
        }
        self.pending_withdrawal_requests.push_back(request);
    }

    /// Move an existing withdrawal request to the back of the queue.
    pub fn reschedule_withdrawal_request<R: Into<WithdrawalRequest>>(&mut self, request: R) {
        let request = request.into();
        assert_eq!(
            self.pending_withdrawal_requests
                .iter()
                .filter(|r| r.native_ledger_burn_index() == request.native_ledger_burn_index())
                .count(),
            1,
            "BUG: expected exactly one withdrawal request with ckETH ledger burn index {}",
            request.native_ledger_burn_index()
        );
        self.remove_withdrawal_request(&request);
        self.record_withdrawal_request(request);
    }
}
