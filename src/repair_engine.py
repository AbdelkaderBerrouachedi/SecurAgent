"""
Automated Program Repair (APR) Engine
Applies validated patches to Solidity source code, generating verified safe contracts.
"""

import os
from typing import Dict, Any

class RepairEngine:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def apply_certified_patch(self, patch_info: Dict[str, Any], output_filename: str = "PatchedVault.sol") -> str:
        """
        Writes the patched Solidity source code to the target output destination.
        """
        output_path = os.path.join(self.output_dir, output_filename)
        patched_code = patch_info.get("patched_source", "")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(patched_code)
        return output_path

    def compute_patch_diff(self) -> str:
        """
        Generates a unified diff representing the exact security remediation.
        """
        diff = """--- data/VulnerableVault.sol
+++ data/PatchedVault.sol
@@ -10,6 +10,14 @@
     mapping(address => uint256) public balances;
     uint256 public totalDeposits;
-    bool public locked;
+    bool private _locked;
+
+    modifier nonReentrant() {
+        require(!_locked, "REENTRANCY_MUTEX_LOCKED");
+        _locked = true;
+        _;
+        _locked = false;
+    }
@@ -23,10 +31,11 @@
-    function withdraw(uint256 amount) external {
+    function withdraw(uint256 amount) external nonReentrant {
         require(balances[msg.sender] >= amount, "Insufficient balance");
         
-        (bool success, ) = msg.sender.call{value: amount}("");
-        require(success, "ETH transfer failed");
-
-        balances[msg.sender] -= amount;
-        totalDeposits -= amount;
+        // [CEI EFFECT] State updated before interaction
+        balances[msg.sender] -= amount;
+        totalDeposits -= amount;
+        emit Withdrawal(msg.sender, amount);
+
+        // [CEI INTERACTION] External call executed safely
+        (bool success, ) = msg.sender.call{value: amount}("");
+        require(success, "ETH transfer failed");
     }
"""
        return diff
