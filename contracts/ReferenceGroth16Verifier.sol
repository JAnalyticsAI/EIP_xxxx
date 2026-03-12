// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @title Reference Groth16 Verifier
/// @notice Reference verifier implementation for Groth16 proofs using bn128 precompiles.
/// @dev This contract accepts a serialized proof and serialized public inputs (ABI-encoded),
/// and verifies the proof against an on-chain verifying key set at construction time.
/// This is a reference implementation intended for testing and demonstration; do not
/// use it as-is in production without careful review.
contract ReferenceGroth16Verifier {
    uint256 constant FIELD_Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    struct G1Point { uint256 X; uint256 Y; }
    struct G2Point { uint256[2] X; uint256[2] Y; }

    // Verifying key elements
    G1Point public vk_alpha;
    G2Point public vk_beta;
    G2Point public vk_gamma;
    G2Point public vk_delta;
    G1Point[] public vk_ic; // IC[0] + sum(input[i] * IC[i+1])

    /// @param _vk_alpha [X, Y]
    /// @param _vk_beta [X1, X0, Y1, Y0]
    /// @param _vk_gamma [X1, X0, Y1, Y0]
    /// @param _vk_delta [X1, X0, Y1, Y0]
    /// @param _vk_ic flattened pairs: [X0, Y0, X1, Y1, X2, Y2, ...]
    constructor(
        uint256[2] memory _vk_alpha,
        uint256[4] memory _vk_beta,
        uint256[4] memory _vk_gamma,
        uint256[4] memory _vk_delta,
        uint256[] memory _vk_ic
    ) {
        vk_alpha = G1Point(_vk_alpha[0], _vk_alpha[1]);
        vk_beta = G2Point([_vk_beta[0], _vk_beta[1]], [_vk_beta[2], _vk_beta[3]]);
        vk_gamma = G2Point([_vk_gamma[0], _vk_gamma[1]], [_vk_gamma[2], _vk_gamma[3]]);
        vk_delta = G2Point([_vk_delta[0], _vk_delta[1]], [_vk_delta[2], _vk_delta[3]]);

        require(_vk_ic.length % 2 == 0, "vk_ic length must be even");
        uint256 n = _vk_ic.length / 2;
        vk_ic = new G1Point[](n);
        for (uint256 i = 0; i < n; i++) {
            vk_ic[i] = G1Point(_vk_ic[2*i], _vk_ic[2*i + 1]);
        }
    }

    // --- elliptic curve helpers using precompiles ---
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, FIELD_Q - (p.Y % FIELD_Q));
    }

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input = [p1.X, p1.Y, p2.X, p2.Y];
        bool success;
        assembly {
            // call bn256Add precompile (0x06)
            success := staticcall(gas(), 0x06, input, 0x80, r, 0x40)
        }
        require(success, "ec add failed");
    }

    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input = [p.X, p.Y, s];
        bool success;
        assembly {
            // call bn256ScalarMul precompile (0x07)
            success := staticcall(gas(), 0x07, input, 0x60, r, 0x40)
        }
        require(success, "ec mul failed");
    }

    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length, "pairing length mismatch");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            uint256 idx = i * 6;
            input[idx + 0] = p1[i].X;
            input[idx + 1] = p1[i].Y;
            input[idx + 2] = p2[i].X[0];
            input[idx + 3] = p2[i].X[1];
            input[idx + 4] = p2[i].Y[0];
            input[idx + 5] = p2[i].Y[1];
        }

        uint256 inputBytes = inputSize * 0x20;
        bool success;
        uint256[1] memory out;
        assembly {
            let ptr := add(input, 0x20)
            success := staticcall(gas(), 0x08, ptr, inputBytes, out, 0x20)
        }
        require(success, "pairing call failed");
        return out[0] != 0;
    }

    // --- public API ---
    /// @notice Verify a Groth16 proof. `proof` must be abi.encode(a, b, c) where
    /// a = uint256[2], b = uint256[2][2], c = uint256[2]. `publicInputs` must be abi.encode(uint256[]).
    function verifyAggregatedProof(bytes calldata proof, bytes calldata publicInputs) external view returns (bool) {
        // decode proof
        // expects (uint256[2], uint256[2][2], uint256[2])
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        // decode public inputs
        uint256[] memory input = abi.decode(publicInputs, (uint256[]));
        require(input.length + 1 == vk_ic.length, "bad input length");

        // compute linear combination vk_x
        G1Point memory vk_x = vk_ic[0];
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < FIELD_Q, "input out of range");
            G1Point memory term = scalar_mul(vk_ic[i + 1], input[i]);
            vk_x = addition(vk_x, term);
        }

        // prepare pairing check
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);

        // e(a, b)
        p1[0] = G1Point(a[0], a[1]);
        p2[0] = G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);

        // e(-vk_x, vk_gamma)
        p1[1] = negate(vk_x);
        p2[1] = vk_gamma;

        // e(-vk_alpha, vk_beta)
        p1[2] = negate(vk_alpha);
        p2[2] = vk_beta;

        // e(-c, vk_delta)
        p1[3] = negate(G1Point(c[0], c[1]));
        p2[3] = vk_delta;

        return pairing(p1, p2);
    }
}
