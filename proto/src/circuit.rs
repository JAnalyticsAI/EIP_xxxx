use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};

/// TxCircuit with a placeholder Poseidon gadget and a Merkle-path verifier.
///
/// NOTE: For prototyping we implement a dummy "Poseidon" gadget (additive
/// compression) to keep the example compact. Replace `poseidon_hash_gadget`
/// with a real Poseidon permutation gadget (from a maintained crate) before
/// using in production.
pub struct TxCircuit<F: FieldExt> {
    /// private leaf value (e.g., leaf preimage or commitment input)
    pub leaf: Option<F>,
    /// merkle siblings (bottom-up). Length determines path depth.
    pub siblings: Vec<Option<F>>,
    /// path bits: 0 => current on left, 1 => current on right
    pub path_bits: Vec<Option<bool>>,
}

#[derive(Clone)]n
pub struct TxConfig {
    pub left: Column<Advice>,
    pub right: Column<Advice>,
    pub out: Column<Advice>,
    pub instance: Column<Instance>,
    pub selector: Selector,
    pub bit_check: Column<Advice>,
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

        // Gate: when selector enabled, enforce out = H(left, right)
        // Here H is a placeholder additive compression: out = left + right.
        meta.create_gate("hash gate (placeholder Poseidon)", |meta| {
            let s = meta.query_selector(selector);
            let l = meta.query_advice(left, halo2_proofs::plonk::Rotation::cur());
            let r = meta.query_advice(right, halo2_proofs::plonk::Rotation::cur());
            let o = meta.query_advice(out, halo2_proofs::plonk::Rotation::cur());
            vec![s * (o - (l + r))]
        });

        // Gate: enforce bit is boolean: bit * (bit - 1) = 0
        meta.create_gate("bit booleanity", |meta| {
            let b = meta.query_advice(bit_check, halo2_proofs::plonk::Rotation::cur());
            vec![b.clone() * (b - halo2_proofs::plonk::Expression::Constant(F::one()))]
        });

        TxConfig { left, right, out, instance, selector, bit_check }
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

        // We'll use one region to assign the folding rows
        layouter.assign_region(|| "merkle fold", |mut region| {
            let mut current = region.assign_advice(|| "leaf out", config.out, 0, || leaf_val)?;

            // Ensure path length matches siblings length
            let depth = self.siblings.len();
            for i in 0..depth {
                // offset row for this level
                let offset = i + 1;

                // sibling value
                let sib_val = self.siblings[i].map(Value::known).unwrap_or(Value::unknown());
                let sib_cell = region.assign_advice(|| format!("sibling_{}", i), config.left, offset, || sib_val)?;

                // path bit: 0 => current left, 1 => current right
                let bit_opt = self.path_bits.get(i).cloned().unwrap_or(None);
                let bit_fe = bit_opt.map(|b| if b { F::one() } else { F::zero() });
                let bit_val = bit_fe.map(Value::known).unwrap_or(Value::unknown());
                region.assign_advice(|| format!("path_bit_{}", i), config.bit_check, offset, || bit_val)?;

                // Decide left/right placement using bit: left = bit * sib + (1-bit) * current
                // right = bit * current + (1-bit) * sib
                // For brevity in this skeleton, we'll assign left=sib and right=current when bit=0,
                // and left=current, right=sib when bit=1. The gate enforces out = left + right.

                // Map cells into the expected columns: we reuse columns by assigning appropriately.
                // left column at this row will hold the chosen left value
                let (left_val, right_val) = match bit_opt {
                    Some(true) => (current.value().clone(), sib_val),
                    Some(false) => (sib_val, current.value().clone()),
                    None => (Value::unknown(), Value::unknown()),
                };

                region.assign_advice(|| format!("left_{}", i), config.left, offset, || left_val)?;
                region.assign_advice(|| format!("right_{}", i), config.right, offset, || right_val)?;

                // Enable selector to enforce hash gate at this row
                config.selector.enable(&mut region, offset)?;

                // Compute out = left + right (placeholder for Poseidon)
                // For witness assignment we need to compute the expected out value here
                let out_val = match (left_val, right_val) {
                    (Value::Known(a), Value::Known(b)) => Value::known(*a + *b),
                    _ => Value::unknown(),
                };

                current = region.assign_advice(|| format!("out_{}", i), config.out, offset, || out_val)?;
            }

            // Constrain the final computed root to equal the public instance at index 0
            // get final cell
            let final_cell = current.cell();
            layouter.constrain_instance(final_cell, config.instance, 0)?;

            Ok(())
        })?;

        Ok(())
    }
}

// TODO: Replace placeholder additive compression with a real Poseidon gadget.
// There are multiple community-provided Poseidon gadgets for Halo2; when
// integrating, import the gadget and replace the gate and witness computation
// with the gadget's API. Also add range-check gadgets and signature gadgets
// to complete the per-transaction circuit as specified in `docs/CIRCUIT_SPEC.md`.

