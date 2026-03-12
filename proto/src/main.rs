mod circuit;
mod runner;

use pasta_curves::pallas::Base as Fp;
use halo2_proofs::dev::MockProver;
use circuit::TxCircuit;
use runner::export_witness;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    // Example values: leaf = 1, siblings = [2,3], all path bits = 0
    let leaf = Fp::from(1u64);
    let siblings = vec![Fp::from(2u64), Fp::from(3u64)];
    let path_bits = vec![Some(false), Some(false)];

    let circuit = TxCircuit {
        leaf: Some(leaf),
        siblings: siblings.iter().map(|&v| Some(v)).collect(),
        path_bits: path_bits.clone(),
    };

    let root = leaf + siblings[0] + siblings[1];

    if args.len() > 1 && args[1] == "export" {
        match export_witness(leaf, &siblings, &path_bits, root) {
            Ok(_) => println!("Exported witness/public to proto/out/"),
            Err(e) => println!("Failed to export witness: {}", e),
        }
        return;
    }

    // Otherwise run a MockProver verification as a quick test
    let public_inputs = vec![vec![root]];
    let k = 4;
    let prover = MockProver::run(k, &circuit, public_inputs).expect("prover run");
    match prover.verify() {
        Ok(_) => println!("Mock prover succeeded: constraints satisfied."),
        Err(e) => println!("Mock prover failed: {:?}" , e),
    }
}
