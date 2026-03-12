// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title MockVerifier
/// @notice A minimal verifier contract for local testing. It implements
/// `verifyAggregatedProof(bytes,bytes) -> bool`. This mock returns `true`
/// for any non-empty proof. Use only in testnets / local dev.
contract MockVerifier {
    event Verified(address indexed caller, uint256 proofLength, uint256 publicInputsLength);

    function verifyAggregatedProof(bytes calldata proof, bytes calldata publicInputs) external pure returns (bool) {
        // Trivial policy: succeed if proof is non-empty. Replace with a real
        // verifier implementation for integration tests that require real checks.
        return proof.length > 0;
    }

    // Convenience helper for testing via calls
    function verifyAndEmit(bytes calldata proof, bytes calldata publicInputs) external returns (bool) {
        bool ok = verifyAggregatedProof(proof, publicInputs);
        emit Verified(msg.sender, proof.length, publicInputs.length);
        return ok;
    }
}
