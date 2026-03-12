use std::env;

#[derive(Debug)]
pub struct ZKTx {
    pub version: u8,
    pub eph_pub: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub commitment: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub tx_id: u64,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "help" {
        println!("zk_aggregator_proto: skeleton. See README.md in proto/");
        return;
    }

    // Skeleton runner: real implementation will parse mempool, build witnesses,
    // call prover (halo2/arkworks), then output an aggregated proof blob.
    println!("zk_aggregator_proto skeleton. Next: implement circuit and aggregator.");
}
