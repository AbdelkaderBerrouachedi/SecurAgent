// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PatchedVault
 * @notice Certified repaired DeFi Vault protected by Checks-Effects-Interactions (CEI)
 * and non-reentrant state mutex lock. Formally verified by SecurAgent Z3 CHC Engine.
 */
contract PatchedVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;
    bool private _locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier nonReentrant() {
        require(!_locked, "REENTRANCY_MUTEX_LOCKED");
        _locked = true;
        _;
        _locked = false;
    }

    function deposit() external payable {
        require(msg.value > 0, "Deposit must be positive");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Certified Repair: CEI applied (state updated prior to interaction) + nonReentrant guard
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // [CEI EFFECT] State update performed BEFORE external interaction
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        emit Withdrawal(msg.sender, amount);

        // [CEI INTERACTION] Safe external call after internal state transition
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    function getVaultBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
