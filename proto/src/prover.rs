use std::fs;
use std::path::Path;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use pasta_curves::pallas::Base as Fp;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::{keygen_pk, keygen_vk, create_proof, verify_proof};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bWrite, Blake2bRead, Challenge255};
use halo2_proofs::poly::commitment::strategy::SingleStrategy;
use crate::circuit::TxCircuit;

pub fn run_prover_example(k: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Example instantiation: same values as main runner
    let leaf = Fp::from(1u64);
    let siblings = vec![Fp::from(2u64), Fp::from(3u64)];
    let path_bits = vec![Some(false), Some(false)];

    let circuit = TxCircuit {
        leaf: Some(leaf),
        siblings: siblings.iter().map(|&v| Some(v)).collect(),
        path_bits: path_bits.clone(),
    };

    let root = leaf + siblings[0] + siblings[1];
    let public_inputs = vec![vec![root]];

    // Initialize randomness
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // Create universal params (may be expensive for large k)
    let params: Params<pasta_curves::pallas::Affine> = Params::new(k);

    // Key generation
    let vk = keygen_vk(&params, &circuit)?;
    let pk = keygen_pk(&params, vk.clone(), &circuit)?;

    // Create proof
    let mut transcript = Blake2bWrite::<Vec<u8>, _, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&public_inputs[0]]],
        &mut rng,
        &mut transcript,
    )?;
    let proof = transcript.finalize();

    // Verify proof locally
    let strategy = SingleStrategy::new(&params);
    let mut verifier_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let verified = verify_proof(&params, &vk, strategy, &[&[&public_inputs[0]]], &mut verifier_transcript)?;

    if verified {
        // Write proof and public inputs to disk
        let out_dir = Path::new("proto/out");
        fs::create_dir_all(out_dir)?;
        fs::write(out_dir.join("proof.bin"), &proof)?;
        let pub_ser = bincode::serialize(&public_inputs)?;
        fs::write(out_dir.join("public.bin"), &pub_ser)?;
        println!("Proof generated and verified locally. Files written to proto/out/");
        Ok(())
    } else {
        Err("Proof failed verification".into())
    }
}
