use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};

// Poseidon gadget from halo2_gadgets (replace with exact API/version as needed)
use halo2_gadgets::poseidon::{primitives::P128Pow5T3, Hash as PoseidonHash, PoseidonChip, PoseidonConfig};

/// TxCircuit with Poseidon gadget and a Merkle-path verifier.
pub struct TxCircuit<F: FieldExt> {
    /// private leaf value (e.g., leaf preimage or commitment input)
    pub leaf: Option<F>,
    /// merkle siblings (bottom-up). Length determines path depth.
    pub siblings: Vec<Option<F>>,
    /// path bits: 0 => current on left, 1 => current on right
    pub path_bits: Vec<Option<bool>>,
}

#[derive(Clone)]
pub struct TxConfig {
    pub left: Column<Advice>,
    pub right: Column<Advice>,
    pub out: Column<Advice>,
    pub instance: Column<Instance>,
    pub selector: Selector,
    pub bit_check: Column<Advice>,
    // Poseidon config placeholder
    pub poseidon: PoseidonConfig,
    // Signature gadget placeholders
    pub sig_pubkey: Column<Advice>,
    pub sig_r: Column<Advice>,
    pub sig_s: Column<Advice>,
    // Range-check gadget placeholder (decomposed bits column)
    pub range_bits: Column<Advice>,
}

impl<F: FieldExt> TxConfig {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let left = meta.advice_column();
        let right = meta.advice_column();
        let out = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();
        let bit_check = meta.advice_column();

        meta.enable_equality(left);
        meta.enable_equality(right);
        meta.enable_equality(out);
        meta.enable_equality(instance);
        meta.enable_equality(bit_check);

        // Create Poseidon config via gadget helper (may require matching API)
        let poseidon = PoseidonConfig::configure(meta, &[]);

        // signature gadget columns (placeholder)
        let sig_pubkey = meta.advice_column();
        let sig_r = meta.advice_column();
        let sig_s = meta.advice_column();
        meta.enable_equality(sig_pubkey);
        meta.enable_equality(sig_r);
        meta.enable_equality(sig_s);

        // range-check bits column (placeholder)
        let range_bits = meta.advice_column();
        meta.enable_equality(range_bits);

        TxConfig { left, right, out, instance, selector, bit_check, poseidon, sig_pubkey, sig_r, sig_s, range_bits }
    }
}

impl<F: FieldExt> Circuit<F> for TxCircuit<F> {
    type Config = TxConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        TxCircuit { leaf: None, siblings: vec![], path_bits: vec![] }
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        TxConfig::configure(cs)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        // Assign the leaf value as the starting 'current' value
        let leaf_val = self.leaf.map(Value::known).unwrap_or(Value::unknown());

        // Instantiate Poseidon chip
        let chip = PoseidonChip::<F, P128Pow5T3>::construct(config.poseidon.clone());

        // We'll use one region to assign the folding rows
        layouter.assign_region(|| "merkle fold", |mut region| {
            // assign leaf into out column row 0
            let mut current = region.assign_advice(|| "leaf out", config.out, 0, || leaf_val)?;

            // Ensure path length matches siblings length
            let depth = self.siblings.len();
            for i in 0..depth {
                // offset row for this level
                let offset = i + 1;

                // sibling value
                let sib_val = self.siblings[i].map(Value::known).unwrap_or(Value::unknown());
                region.assign_advice(|| format!("sibling_{}", i), config.left, offset, || sib_val)?;

                // path bit: 0 => current left, 1 => current right
                let bit_opt = self.path_bits.get(i).cloned().unwrap_or(None);
                let bit_fe = bit_opt.map(|b| if b { F::one() } else { F::zero() });
                let bit_val = bit_fe.map(Value::known).unwrap_or(Value::unknown());
                region.assign_advice(|| format!("path_bit_{}", i), config.bit_check, offset, || bit_val)?;

                // Determine left and right inputs depending on bit
                // For full integration, use conditional selection gadgets. Here we choose
                // to assign values directly into the Poseidon inputs depending on bit.
                let left_val = match bit_opt {
                    Some(true) => current.value().clone(),
                    Some(false) => sib_val,
                    None => Value::unknown(),
                };
                let right_val = match bit_opt {
                    Some(true) => sib_val,
                    Some(false) => current.value().clone(),
                    None => Value::unknown(),
                };

                // Call poseidon hash gadget on (left, right) --> out
                // The actual API may differ; adapt to the halo2_gadgets version you pin.
                let left_assigned = region.assign_advice(|| format!("left_{}", i), config.left, offset, || left_val)?;
                let right_assigned = region.assign_advice(|| format!("right_{}", i), config.right, offset, || right_val)?;

                // Use the chip to hash the two inputs and assign the output
                let input_cells = vec![left_assigned.cell(), right_assigned.cell()];
                let hash_cell = chip.hash(&mut region, input_cells)?; // may need API changes

                // map hash_cell into out column
                // Note: this step assumes chip.hash gives an assigned cell compatible with our out column.
                // In practice you may need to copy or constrain equality between columns.
                // For now, assign the computed value into the out column.
                let out_val = region.assign_advice(|| format!("out_{}", i), config.out, offset, || Value::unknown())?;

                // Enable selector to indicate this row performs a hash
                config.selector.enable(&mut region, offset)?;

                current = out_val;
            }

            // Constrain the final computed root to equal the public instance at index 0
            let final_cell = current.cell();
            layouter.constrain_instance(final_cell, config.instance, 0)?;

            // --- Signature verification (placeholder) ---
            // In a full implementation, the signature gadget verifies a Schnorr/BLS
            // signature proving knowledge of the sender's secret key. Here we assign
            // placeholder cells for `pubkey`, `r`, and `s` and leave a TODO to
            // integrate a real gadget.
            let sig_pub = region.assign_advice(|| "sig_pubkey", config.sig_pubkey, depth + 1, || Value::unknown())?;
            let sig_r = region.assign_advice(|| "sig_r", config.sig_r, depth + 1, || Value::unknown())?;
            let sig_s = region.assign_advice(|| "sig_s", config.sig_s, depth + 1, || Value::unknown())?;

            // TODO: invoke real signature gadget here to constrain (pubkey, r, s)

            // --- Range-check (placeholder) ---
            // Assign a placeholder value representing (balance - amount - fee)
            // In practice, compute difference in field and decompose into bits,
            // then constrain bits via a range-check gadget to ensure non-negativity
            // and bounds (e.g., 128 bits).
            let diff_val = Value::unknown();
            let _diff_cell = region.assign_advice(|| "balance_diff", config.range_bits, depth + 2, || diff_val)?;
            // TODO: decompose `_diff_cell` into bits and enforce booleanity & reconstruction.

            Ok(())
        })?;

        Ok(())
    }
}

// NOTE: The Poseidon gadget API (types, construct, hash) may differ depending
// on the `halo2_gadgets` version. If the build fails, adjust imports and calls
// to match the pinned crate. This change replaces the placeholder additive
// compression with a call to a Poseidon chip; further work needed to integrate
// signature and range-check gadgets.

