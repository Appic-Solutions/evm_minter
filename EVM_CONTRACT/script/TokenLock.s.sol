// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "forge-std/Script.sol";
import "../src/TokenLock.sol";

contract DeployTokenLock is Script {
    TokenLock public tokenLock;

    function run() public {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        console.log("Deploying TokenLock contract with address", vm.addr(pk));
        vm.startBroadcast(pk);
        _deployTokenLock();
        vm.stopBroadcast();
        console.log(
            "TokenLock contract deployed at address",
            address(tokenLock)
        );
    }

    function _deployTokenLock() internal {
        // Deploy the TokenLock contract
        tokenLock = new TokenLock();
        console.log("TokenLock contract initialized");
    }
}
