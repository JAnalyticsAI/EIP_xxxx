package zktx

import (
    "encoding/binary"
    "errors"
    "math/big"

    "github.com/consensys/gnark-crypto/ecc/bn254/g1"
    "github.com/consensys/gnark-crypto/ecc/bn254/g2"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
    "github.com/consensys/gnark-crypto/ecc/bn254"
    "github.com/consensys/gnark-crypto/ecc"
)

// This file begins an implementation of a native Groth16 verifier for use
// inside the ZKTx Geth precompile. It contains ABI decoding helpers,
// data structures for a verifying key and proof, and a verification
// skeleton that calls into bn256 pairing checks (TODO: wire actual calls).
//
// NOTE: This PR-ready copy is intended to be placed under
// `core/precompiled/zktx` inside a go-ethereum clone. The code relies on
// gnark-crypto for bn254 primitives and must be validated for API
// compatibility with the vendored version used by the client.

// Proof represents a Groth16 proof with points in G1 and G2.
// Fields are stored as big.Int limbs matching Solidity verifier layouts.
type Proof struct {
    // a in G1
    AX *big.Int
    AY *big.Int
    // b in G2: (BX[2], BY[2]) stored as big.Ints: [BX1,BX0],[BY1,BY0]
    BX [2]*big.Int
    BY [2]*big.Int
    // c in G1
    CX *big.Int
    CY *big.Int
}

// VerifyingKey holds the elements required for Groth16 verification.
// Alpha/Beta/Gamma/Delta are the standard Groth16 VK elements; IC is the
// vector of G1 points used to compute the linear combination with public inputs.
type VerifyingKey struct {
    AlphaX *big.Int
    AlphaY *big.Int
    BetaX  [2]*big.Int
    BetaY  [2]*big.Int
    GammaX [2]*big.Int
    GammaY [2]*big.Int
    DeltaX [2]*big.Int
    DeltaY [2]*big.Int
    // IC: array of G1 points (flattened)
    IC   [][2]*big.Int
}

// parseUint256 parses a 32-byte big-endian uint256 from buf at offset.
// parseUint256 parses a 32-byte big-endian uint256 from buf at offset.
// It returns a big.Int value representing the unsigned integer.
func parseUint256(buf []byte) (*big.Int, error) {
    if len(buf) < 32 {
        return nil, errors.New("buffer too short for uint256")
    }
    i := new(big.Int).SetBytes(buf[:32])
    return i, nil
}

// decodeProof expects ABI-encoded (uint256[2], uint256[2][2], uint256[2]) as used
// in the Solidity reference verifier. Here we accept a simple concatenation of
// 8*32 bytes: a[2], b[2][2], c[2]. This is a simplifying assumption for the
// prototype; real integration should accept ABI encoding properly.
// decodeProof decodes a compact Groth16 proof encoded as 8 consecutive
// 32-byte big-endian words: a.x, a.y, b.x.c0, b.x.c1, b.y.c0, b.y.c1, c.x, c.y.
func decodeProof(blob []byte) (*Proof, error) {
    if len(blob) < 32*8 {
        return nil, errors.New("proof blob too short")
    }
    p := &Proof{}
    off := 0
    p.AX = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    p.AY = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    p.BX[0] = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    p.BX[1] = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    p.BY[0] = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    p.BY[1] = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    p.CX = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    p.CY = new(big.Int).SetBytes(blob[off : off+32]); off += 32
    return p, nil
}

// decodePublicInputs expects a simple concatenation of uint256 values.
// decodePublicInputs parses the public input blob into a slice of big.Int
// values, where each public input occupies 32 bytes in big-endian form.
func decodePublicInputs(blob []byte) ([]*big.Int, error) {
    if len(blob)%32 != 0 {
        return nil, errors.New("public inputs blob length not multiple of 32")
    }
    n := len(blob) / 32
    out := make([]*big.Int, n)
    for i := 0; i < n; i++ {
        out[i] = new(big.Int).SetBytes(blob[i*32 : (i+1)*32])
    }
    return out, nil
}

// computeLinearCombination computes vk_x = IC[0] + sum_{i} input[i]*IC[i+1]
// This is done in affine coordinates in G1; here we return a placeholder
// pair (X,Y) as big.Int values that represent the expected point.
// computeLinearCombination computes vk_x = IC[0] + sum_i (inputs[i] * IC[i+1])
// using gnark-crypto G1 scalar multiplication and addition.
func computeLinearCombination(vk *VerifyingKey, inputs []*big.Int) ([2]*big.Int, error) {
    // ensure IC table exists
    if len(vk.IC) == 0 {
        return [2]*big.Int{big.NewInt(0), big.NewInt(0)}, errors.New("computeLinearCombination: missing IC points")
    }

    // Use gnark-crypto g1 affine points and perform scalar multiplications
    var acc g1.Affine

    // Helper to convert big.Int pair to g1.Affine. The library represents
    // field elements as fr.Element. We set X,Y from big.Int and return
    // the affine point.
    toG1 := func(x, y *big.Int) (g1.Affine, error) {
        var P g1.Affine
        var fx, fy fr.Element
        fx.SetBigInt(x)
        fy.SetBigInt(y)
        P.X = fx
        P.Y = fy
        return P, nil
    }

    // initialize accumulator with IC[0]
    ic0 := vk.IC[0]
    p0, err := toG1(ic0[0], ic0[1])
    if err != nil {
        return [2]*big.Int{big.NewInt(0), big.NewInt(0)}, err
    }
    acc = p0

    // For each input, compute IC[i+1] * input[i] and add to acc
    for i, inp := range inputs {
        idx := i + 1
        if idx >= len(vk.IC) {
            return [2]*big.Int{big.NewInt(0), big.NewInt(0)}, errors.New("computeLinearCombination: not enough IC points for public inputs")
        }
        ic := vk.IC[idx]
        pi, err := toG1(ic[0], ic[1])
        if err != nil {
            return [2]*big.Int{big.NewInt(0), big.NewInt(0)}, err
        }

        // scalar multiply pi by inp
        var s fr.Element
        s.SetBigInt(inp)
        var res g1.Affine
        g1.MulByScalar(&res, &pi, &s)

        // add res to acc (convert to Jacobian, add, back to affine)
        var accJ, resJ g1.Jacobian
        acc.ToJacobian(&accJ)
        res.ToJacobian(&resJ)
        accJ.AddAssign(&resJ)
        accJ.ToAffineFromJacobian(&acc)
    }

    // return big.Int coordinates
    outX := new(big.Int)
    outY := new(big.Int)
    acc.X.BigInt(outX)
    acc.Y.BigInt(outY)
    return [2]*big.Int{outX, outY}, nil
}

// verifyGroth16 runs the Groth16 pairing check for the proof and public inputs
// against the provided verifying key. This function sketches the logical
// flow; actual EC/G1/G2 constructions and pairing checks must be implemented
// with the bn256 library.
func verifyGroth16(vk *VerifyingKey, proof *Proof, publicInputs []*big.Int) (bool, error) {
    // 1) compute vk_x
    vkx, err := computeLinearCombination(vk, publicInputs)
    if err != nil {
        return false, err
    }

    // 2) form pairing tuples:
    //    e(a, b) * e(-vk_x, gamma) * e(-alpha, beta) * e(-c, delta) == 1
    // The engine will accumulate pairings and perform a final check.
    _ = vkx

    // Build G1 and G2 elements from the coordinates
    // a in G1
    var a g1.Affine
    var ax, ay fr.Element
    ax.SetBigInt(proof.AX)
    ay.SetBigInt(proof.AY)
    a.X = ax
    a.Y = ay

    // b in G2
    var b g2.Affine
    var bx0, bx1, by0, by1 fr.Element
    // Note: G2 coordinates are typically represented over Fp2; adjust accordingly
    bx0.SetBigInt(proof.BX[0])
    bx1.SetBigInt(proof.BX[1])
    by0.SetBigInt(proof.BY[0])
    by1.SetBigInt(proof.BY[1])
    // Construct complex coordinates (c0,c1) for X and Y
    b.X.SetComplex(&bx0, &bx1)
    b.Y.SetComplex(&by0, &by1)

    // c in G1
    var c g1.Affine
    var cx, cy fr.Element
    cx.SetBigInt(proof.CX)
    cy.SetBigInt(proof.CY)
    c.X = cx
    c.Y = cy

    // vk elements
    var alpha g1.Affine
    alpha.X.SetBigInt(vk.AlphaX)
    alpha.Y.SetBigInt(vk.AlphaY)

    var beta g2.Affine
    var betax0, betax1, betay0, betay1 fr.Element
    betax0.SetBigInt(vk.BetaX[0])
    betax1.SetBigInt(vk.BetaX[1])
    betay0.SetBigInt(vk.BetaY[0])
    betay1.SetBigInt(vk.BetaY[1])
    beta.X.SetComplex(&betax0, &betax1)
    beta.Y.SetComplex(&betay0, &betay1)

    var gamma g2.Affine
    gamma.X.SetComplex(&fr.Element{}, &fr.Element{})
    gamma.Y.SetComplex(&fr.Element{}, &fr.Element{})

    var delta g2.Affine
    delta.X.SetComplex(&fr.Element{}, &fr.Element{})
    delta.Y.SetComplex(&fr.Element{}, &fr.Element{})

    // compute vk_x
    vkx, err := computeLinearCombination(vk, publicInputs)
    if err != nil {
        return false, err
    }

    var vkxG1 g1.Affine
    vkxG1.X.SetBigInt(vkx[0])
    vkxG1.Y.SetBigInt(vkx[1])

    // pairing check: e(a,b) * e(-vk_x, gamma) * e(-alpha, beta) * e(-c, delta) == 1
    // Use gnark-crypto pairing engine
    engine, err := bn254.NewEngine()
    if err != nil {
        return false, err
    }

    // add pairs
    engine.AddPair(&a, &b)

    // -vk_x with gamma
    var negVkX g1.Affine
    vkxG1.Neg(&negVkX)
    engine.AddPair(&negVkX, &gamma)

    // -alpha with beta
    var negAlpha g1.Affine
    alpha.Neg(&negAlpha)
    engine.AddPair(&negAlpha, &beta)

    // -c with delta
    var negC g1.Affine
    c.Neg(&negC)
    engine.AddPair(&negC, &delta)

    // Check runs a final exponentiation and equality test in the target group.
    ok := engine.Check()
    return ok, nil
}

// abiDecodeCall decodes a simple custom ABI where the input is two length-prefixed
// byte arrays: [len(proof)|proof|len(public)|public]. This is a convenience for
// the prototype. Replace with proper ABI decoding for production.
// abiDecodeCall decodes three length-prefixed byte arrays: proof, public, vk.
// Layout: [uint32 lenProof][proof][uint32 lenPublic][public][uint32 lenVK][vk]
func abiDecodeCall(input []byte) (proofBlob []byte, publicBlob []byte, vkBlob []byte, err error) {
    off := 0
    if len(input) < off+4 {
        return nil, nil, nil, errors.New("input too short for prototype ABI")
    }
    plen := int(binary.BigEndian.Uint32(input[off : off+4])); off += 4
    if len(input) < off+plen+4 {
        return nil, nil, nil, errors.New("input length mismatch for proof")
    }
    proofBlob = input[off : off+plen]; off += plen

    publen := int(binary.BigEndian.Uint32(input[off : off+4])); off += 4
    if len(input) < off+publen+4 {
        return nil, nil, nil, errors.New("input length mismatch for public")
    }
    publicBlob = input[off : off+publen]; off += publen

    vklen := int(binary.BigEndian.Uint32(input[off : off+4])); off += 4
    if len(input) < off+vklen {
        return nil, nil, nil, errors.New("input length mismatch for vk")
    }
    vkBlob = input[off : off+vklen]
    return proofBlob, publicBlob, vkBlob, nil
}

// decodeVK decodes a verifying key encoded as:
// [uint32 icCount][alpha(2*32)][beta(2*32*2)][gamma(2*32*2)][delta(2*32*2)][IC(icCount * 2*32)]
func decodeVK(blob []byte) (*VerifyingKey, error) {
    if len(blob) < 4 {
        return nil, errors.New("vk blob too short")
    }
    off := 0
    icCount := int(binary.BigEndian.Uint32(blob[off : off+4])); off += 4

    // need at least alpha(64) + beta(128) + gamma(128) + delta(128)
    headerSize := 64 + 128 + 128 + 128
    if len(blob) < off+headerSize {
        return nil, errors.New("vk blob missing header fields")
    }
    vk := &VerifyingKey{}
    vk.AlphaX = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.AlphaY = new(big.Int).SetBytes(blob[off:off+32]); off += 32

    vk.BetaX[0] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.BetaX[1] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.BetaY[0] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.BetaY[1] = new(big.Int).SetBytes(blob[off:off+32]); off += 32

    vk.GammaX[0] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.GammaX[1] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.GammaY[0] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.GammaY[1] = new(big.Int).SetBytes(blob[off:off+32]); off += 32

    vk.DeltaX[0] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.DeltaX[1] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.DeltaY[0] = new(big.Int).SetBytes(blob[off:off+32]); off += 32
    vk.DeltaY[1] = new(big.Int).SetBytes(blob[off:off+32]); off += 32

    // IC points
    vk.IC = make([][2]*big.Int, icCount)
    for i := 0; i < icCount; i++ {
        if len(blob) < off+64 {
            return nil, errors.New("vk blob truncated in IC points")
        }
        x := new(big.Int).SetBytes(blob[off:off+32]); off += 32
        y := new(big.Int).SetBytes(blob[off:off+32]); off += 32
        vk.IC[i] = [2]*big.Int{x, y}
    }
    return vk, nil
}

// Exported wrappers for client integration. These mirror the functions in the
// root precompile package and are intended to be used by in-client patches
// that call into the verifier directly.
func DecodeProofForClient(blob []byte) (*Proof, error) {
    return decodeProof(blob)
}

func DecodeVKForClient(blob []byte) (*VerifyingKey, error) {
    return decodeVK(blob)
}

func DecodePublicInputsForClient(blob []byte) ([]*big.Int, error) {
    return decodePublicInputs(blob)
}

func VerifyGroth16ForClient(vk *VerifyingKey, proof *Proof, publicInputs []*big.Int) (bool, error) {
    return verifyGroth16(vk, proof, publicInputs)
}
