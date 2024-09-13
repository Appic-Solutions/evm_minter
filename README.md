# EVM Minter Canister
This repository contains the code for the Minter Canister, which is responsible for minting and burning tokens on the Internet Computer (ICP) from various EVM-compatible chains. Twin tokens are tokens that are linked to a corresponding token on an EVM chain with a 1:1 ratio. For each Twin Token minted on ICP, one corresponding token must be locked on the respective EVM chain.

---

# Deposit Flow
![image](https://github.com/user-attachments/assets/af6a6d3e-9c12-4a99-bb69-7b50925cf5f5)

The **deposit process** starts when a user calls the `deposit` function in the helper smart contract. This function accepts both **native tokens** and **ERC20 tokens**, meaning there's no need for separate contracts. The tokens are transferred to an account created using **ECDSA** for the **minter canister**, and an event is logged to record the deposit. Here’s the structure of the event:

```solidity
    // Event to log token deposits
    event TokensLocked(
        address user,
        address indexed token,
        uint256 indexed amount,
        bytes indexed principalId
    );
```

Next, the contract's **deposit logs** are collected using multiple **RPC providers**, which ensures we aren’t relying on just one source. The `eth_getLogs` function is called regularly, with timing adjusted based on each EVM chain’s block speed. These logs are converted into **deposit events** and saved in the **canister’s state**. If some logs contain errors (like invalid principals or ERC20 addresses), they are saved as **invalid deposit events**.

```rust
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct ReceivedDepositEvent {
    #[n(0)]
    pub transaction_hash: Hash,
    #[n(1)]
    pub block_number: BlockNumber,
    #[cbor(n(2))]
    pub log_index: LogIndex,
    #[n(3)]
    pub from_address: Address,
    #[n(4)]
    pub value: Erc20Value,
    #[cbor(n(5), with = "crate::cbor::principal")]
    pub principal: Principal,
    #[n(6)]
    pub erc20_contract_address: Address,
}
```

After the deposit events are recorded in the canister state, a **timer** triggers the **mint function** to mint new **twin tokens** based on these deposit events. The minted tokens are transferred to the users, and these minting actions are also logged.

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintedEvent {
    pub deposit_event: ReceivedDepositEvent,
    pub mint_block_index: LedgerMintIndex,
    pub token_symbol: String,
    pub erc20_contract_address: Option<Address>,
}
```

# Withdrawal Flow
![image (1)](https://github.com/user-attachments/assets/38900b1e-cb67-48b4-9ca5-2677f0f16605)

The **withdrawal process** starts when a user **approves the burning of tokens** to the minter principal address and then calls either the `withdraw_erc20` or `withdraw_native_token` function from the canister’s interface.

After approval, the **minter canister burns tokens** using the **ICRC ledger client**. Based on the burn, a **withdrawal request** is created. Here’s what it looks like for both native tokens and ERC20 tokens:

```rust
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct NativeWithdrawalRequest {
    pub withdrawal_amount: Wei,
    pub destination: Address,
    pub ledger_burn_index: LedgerBurnIndex,
    pub from: Principal,
    pub from_subaccount: Option<Subaccount>,
    pub created_at: Option<u64>,
}

/// ERC-20 withdrawal request
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct Erc20WithdrawalRequest {
    pub max_transaction_fee: Wei,
    pub withdrawal_amount: Erc20Value,
    pub destination: Address,
    pub native_ledger_burn_index: LedgerBurnIndex,
    pub erc20_contract_address: Address,
    pub erc20_ledger_id: Principal,
    pub erc20_ledger_burn_index: LedgerBurnIndex,
    pub from: Principal,
    pub from_subaccount: Option<Subaccount>,
    pub created_at: u64,
}
```

These requests are saved in the **canister’s state**. A **timer** runs regularly to process these requests in four steps:

1. `create_transactions_batch()`
2. `sign_transactions_batch()`
3. `send_transactions_batch()`
4. `finalize_transactions_batch()`

If a transaction fails due to low gas, it is resubmitted with a 10% gas increase. If it fails for other reasons, the **twin tokens** are **refunded** to the user on the IC network.

---

# Key Modules

- **EVM_RPC_CLIENT module**: Handles calls to the `evm_rpc_canister`. If the response is an error with "TooFewCycles," the call repeats until a successful result is returned.
  
- **RpcClient module**: Converts responses from `evm_rpc_canister` into formats the minter canister can use. It also works to make inconsistent results consistent.

- **State module**: Tracks general information about the minter canister and keeps logs of all events, including deposits, withdrawals, and other key tasks.

```rust
#[derive(Debug, PartialEq, Clone)]
pub struct State {
    pub evm_network: EvmNetwork,
    pub ecdsa_key_name: String,
    pub native_ledger_id: Principal,
    pub native_symbol: ERC20TokenSymbol,
    pub helper_contract_address: Option<Address>,
    pub evm_canister_id: Principal,
    pub ecdsa_public_key: Option<EcdsaPublicKeyResponse>,
    pub native_ledger_transfer_fee: Wei,
    pub native_minimum_withdrawal_amount: Wei,
    pub block_height: BlockTag,
    pub first_scraped_block_number: BlockNumber,
    pub last_scraped_block_number: BlockNumber,
    pub last_observed_block_number: Option<BlockNumber>,
    pub events_to_mint: BTreeMap<EventSource, ReceivedDepositEvent>,
    pub minted_events: BTreeMap<EventSource, MintedEvent>,
    pub invalid_events: BTreeMap<EventSource, InvalidEventReason>,
    pub withdrawal_transactions: WithdrawalTransactions,
    pub native_balance: NativeBalance,
    pub erc20_balances: Erc20Balances,
    pub pending_withdrawal_principals: BTreeSet<Principal>,
    pub active_tasks: HashSet<TaskType>,
    pub last_transaction_price_estimate: Option<(u64, GasFeeEstimate)>,
    pub erc20_tokens: DedupMultiKeyMap<Principal, Address, ERC20TokenSymbol>,
    pub min_max_priority_fee_per_gas: WeiPerGas,
}
```

- **LedgerClient**: Handles calls to **ICRC ledgers** for minting and burning twin tokens (`icrc1_transfer`, `icrc2_transfer_from`).

---

This is the first version of the EVM Minter Canister. Improvements and new features, like paying withdrawal fees using native tokens instead of twin tokens on IC, are planned for future updates.
