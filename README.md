# EVM-MINTER

This repository contains code for three distinct modules designed to mint and burn twin tokens on the Internet Computer (ICP) based on interactions with Ethereum Virtual Machine (EVM) chains through RPC providers.

## Modules

### 1. **EVM_RPC_CLIENT**
   - This module makes intercanister calls to the EVM-RPC-Canister or an equivalent instance. If the call fails due to limited cycles, it retries with more cycles until a consistent or successful response is received.

### 2. **HELPER_SMART_CONTRACT**
   - This smart contract captures deposit events via RPC providers, which are used to mint twin tokens.

### 3. **MINTER**
   - The Minter module manages the minting and burning of twin tokens on the Internet Computer, ensuring synchronization with the EVM chains.
