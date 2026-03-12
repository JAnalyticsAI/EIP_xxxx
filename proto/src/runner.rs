use std::fs;
use std::path::Path;
use serde::{Serialize};
use pasta_curves::pallas::Base as Fp;

#[derive(Serialize)]
struct WitnessExport {
    leaf: String,
    siblings: Vec<String>,
    path_bits: Vec<u8>,
}

#[derive(Serialize)]
struct PublicExport {
    root: String,
}

fn fe_to_hex(f: &Fp) -> String {
    // Serialize field element as hex of big-endian bytes
    let mut bytes = [0u8; 32];
    f.to_repr().as_ref().read_exact(&mut bytes).ok();
    hex::encode(bytes)
}

pub fn export_witness(leaf: Fp, siblings: &[Fp], path_bits: &[Option<bool>], root: Fp) -> std::io::Result<()> {
    let out_dir = Path::new("proto/out");
    fs::create_dir_all(out_dir)?;

    let w = WitnessExport {
        leaf: fe_to_hex(&leaf),
        siblings: siblings.iter().map(|s| fe_to_hex(s)).collect(),
        path_bits: path_bits.iter().map(|b| if *b == Some(true) { 1u8 } else { 0u8 }).collect(),
    };

    let p = PublicExport { root: fe_to_hex(&root) };

    let w_json = serde_json::to_string_pretty(&w).expect("serialize witness");
    let p_json = serde_json::to_string_pretty(&p).expect("serialize public");

    fs::write(out_dir.join("witness.json"), w_json)?;
    fs::write(out_dir.join("public.json"), p_json)?;
    Ok(())
}
