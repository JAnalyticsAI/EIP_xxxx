// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title VerifierWrapper
/// @notice Lightweight wrapper that calls the on-chain verifier (precompile or deployed address).
/// @dev By default this wrapper targets address(0x0B) which is the precompile slot proposed
/// in EIP-xxxx. For testing deploys you may pass an alternative verifier address to the constructor.
contract VerifierWrapper {
    address public immutable verifier;

    /// @param _verifier address of the verifier implementation (precompile or contract). If zero, uses 0x0B.
    constructor(address _verifier) {
        if (_verifier == address(0)) {
            verifier = address(0x0B);
        } else {
            verifier = _verifier;
        }
    }

    /// @notice Verify an aggregated proof via the configured verifier.
    /// @param proof aggregated proof bytes
    /// @param publicInputs serialized public inputs
    /// @return ok true if the verifier accepts the proof
    function verifyAggregatedProof(bytes calldata proof, bytes calldata publicInputs) external view returns (bool ok) {
        // ABI-encode call to the verifier's `verifyAggregatedProof(bytes,bytes)`
        bytes memory data = abi.encodeWithSignature("verifyAggregatedProof(bytes,bytes)", proof, publicInputs);
        (bool success, bytes memory ret) = verifier.staticcall(data);
        if (!success) return false;
        // Expect a single boolean in return data
        if (ret.length == 32) {
            uint256 v;
            assembly { v := mload(add(ret, 32)) }
            return (v != 0);
        }
        return false;
    }
}
