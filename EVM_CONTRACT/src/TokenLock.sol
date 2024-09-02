// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.20;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title Token Locking Smart Contract
 * @notice This contract allows users to lock their tokens, with the contract owner having the exclusive right to withdraw the locked tokens.
 */
contract TokenLock is Ownable, AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    address public minter;
    mapping(address => uint256) public tokenAmount;
    mapping(address => uint256) public feeTank;

    // Custom errors for specific revert reasons
    error NotOwner();
    error TransferFailed(address _user, uint256 _amount);

    // Event to log token deposits into the contract
    event TokensLocked(
        address user,
        address indexed token,
        uint256 indexed amount,
        bytes indexed principalId
    );

    // Event to log gas fees added
    event gasFeeAdded(address user, uint256 amount);

    /**
     * @dev Constructor initializes the contract.
     * Sets the contract deployer as the initial owner and grants them the `MINTER_ROLE`.
     */
    constructor() Ownable(msg.sender) {
        minter = msg.sender;
        _grantRole(MINTER_ROLE, msg.sender);
    }

    /**
     * @dev Grants `MINTER_ROLE` to the specified user.
     * Can only be called by the contract owner.
     * @param user The address of the user to be granted the `MINTER_ROLE`.
     */
    function grantMinterRole(address user) public onlyOwner {
        minter = user;
        _grantRole(MINTER_ROLE, user);
    }

    /**
     * @dev Revokes `MINTER_ROLE` from the specified user.
     * Can only be called by the contract owner.
     * @param user The address of the user to be revoked of the `MINTER_ROLE`.
     */
    function rovokeMinterRole(address user) public onlyOwner {
        _revokeRole(MINTER_ROLE, user);
    }

    /**
     * @dev Locks the specified amount of tokens or native currency from the user.
     * Transfers the assets to the minter address.
     * @param token The address of the token to lock. Use `address(0)` for native currency.
     * @param amount The amount of tokens to lock.
     * @param principalId A unique identifier associated with the lock operation.
     */
    function lockTokens(
        address token,
        uint256 amount,
        bytes memory principalId
    ) external payable {
        if (msg.value > 0) {
            tokenAmount[address(0)] += msg.value;
            // Transfer native currency from contract to minter
            (bool success, ) = minter.call{value: msg.value}("");
            if (!success) {
                revert("Transfer to minter failed!");
            }

            emit TokensLocked(msg.sender, address(0), msg.value, principalId);
        } else {
            IERC20 tokenContract = IERC20(token);
            tokenAmount[token] += amount;
            tokenContract.safeTransferFrom(msg.sender, address(this), amount);
            tokenContract.safeTransfer(minter, amount);

            emit TokensLocked(msg.sender, token, amount, principalId);
        }
    }

    /**
     * @dev Allows users to add a fee in native currency, transferred directly to the minter.
     */
    function addFee() external payable {
        feeTank[msg.sender] += msg.value;
        (bool success, ) = minter.call{value: msg.value}("");
        if (!success) {
            revert("Transfer to minter failed!");
        }
        emit gasFeeAdded(msg.sender, feeTank[msg.sender]);
    }

    /**
     * @dev Allows the minter to withdraw locked tokens or native currency from the contract.
     * Can only be called by an account with the `MINTER_ROLE`.
     * @param user The address of the user to whom the tokens are being withdrawn.
     * @param token The address of the token to withdraw. Use `address(0)` for native currency.
     * @param amount The amount of tokens or native currency to withdraw.
     * @param fee The fee associated with the withdrawal.
     */
    function withdrawTokens(
        address user,
        address token,
        uint256 amount,
        uint256 fee
    ) public payable {
        require(hasRole(MINTER_ROLE, msg.sender), "MINTER_ROLE required");
        feeTank[user] -= fee;
        tokenAmount[token] -= amount;
        if (token == address(0)) {
            (bool success, ) = user.call{value: amount}("");
            if (!success) {
                revert TransferFailed(user, amount);
            }
        } else {
            IERC20 tokenContract = IERC20(token);

            bool success = tokenContract.transfer(user, amount);
            if (!success) {
                revert TransferFailed(user, amount);
            }
        }
    }

    /**
     * @dev Allows the minter to withdraw locked tokens or native currency from the contract for multiple users.
     * Can only be called by an account with the `MINTER_ROLE`.
     * @param user An array of user addresses to whom the tokens are being withdrawn.
     * @param token An array of token addresses to withdraw. Use `address(0)` for native currency.
     * @param amount An array of amounts to withdraw for each user.
     * @param fee An array of fees associated with each withdrawal.
     */
    function withdrawTokensMultipleUsers(
        address[] calldata user,
        address[] calldata token,
        uint256[] calldata amount,
        uint256[] calldata fee
    ) external payable {
        for (uint256 i = 0; i < user.length; i++) {
            withdrawTokens(user[i], token[i], amount[i], fee[i]);
        }
    }
}
