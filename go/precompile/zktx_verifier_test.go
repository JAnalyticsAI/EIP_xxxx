package zktx

import (
    "math/big"
    "strings"
    "testing"
)

func TestDecodeProof_Short(t *testing.T) {
    _, err := decodeProof([]byte{1, 2, 3})
    if err == nil {
        t.Fatal("expected error for short proof blob")
    }
}

func TestDecodePublicInputs_OK(t *testing.T) {
    buf := make([]byte, 64)
    buf[31] = 1
    buf[63] = 2
    vals, err := decodePublicInputs(buf)
    if err != nil {
        t.Fatalf("unexpected err: %v", err)
    }
    if len(vals) != 2 {
        t.Fatalf("expected 2 inputs got %d", len(vals))
    }
    if vals[0].Cmp(big.NewInt(1)) != 0 || vals[1].Cmp(big.NewInt(2)) != 0 {
        t.Fatalf("unexpected values: %v %v", vals[0], vals[1])
    }
}

func TestVerifyGroth16_NotImplemented(t *testing.T) {
    vk := &VerifyingKey{}
    proof := &Proof{}
    ok, err := verifyGroth16(vk, proof, []*big.Int{})
    if err == nil {
        t.Fatalf("expected not-implemented error, got nil")
    }
    if !strings.Contains(err.Error(), "not implemented") {
        t.Fatalf("unexpected error: %v", err)
    }
    if ok {
        t.Fatalf("expected ok==false")
    }
}
