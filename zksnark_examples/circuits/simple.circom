pragma circom 2.0.0;

// Simple circuit: proves that out = in * in
template Square() {
    signal input in;
    signal output out;
    out <== in * in;
}

component main = Square();
