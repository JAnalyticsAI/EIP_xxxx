mod circuit;

use pasta_curves::pallas::Base as Fp;
use halo2_proofs::dev::MockProver;
use circuit::TxCircuit;

fn main() {
    // Example values: leaf = 1, siblings = [2,3], all path bits = 0
    // With the placeholder additive hash out = left + right, final root = 1+2+3 = 6
    let leaf = Fp::from(1u64);
    let siblings = vec![Fp::from(2u64), Fp::from(3u64)];
    let path_bits = vec![Some(false), Some(false)];

    let circuit = TxCircuit {
        leaf: Some(leaf),
        siblings: siblings.iter().map(|&v| Some(v)).collect(),
        path_bits,
    };

    let root = leaf + siblings[0] + siblings[1];
    let public_inputs = vec![vec![root]];

    // small k for testing
    let k = 4;

    let prover = MockProver::run(k, &circuit, public_inputs).expect("prover run");
    match prover.verify() {
        Ok(_) => println!("Mock prover succeeded: constraints satisfied."),
        Err(e) => println!("Mock prover failed: {:?}", e),
    }
}
