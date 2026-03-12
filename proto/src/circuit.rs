use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector};

/// Minimal example Halo2 circuit skeleton.
///
/// This circuit proves knowledge of a private scalar `preimage` whose
/// committed value equals a public instance. This is a placeholder for a
/// real per-transaction circuit (where Poseidon commitments, Merkle paths,
/// signature checks, and range proofs would be implemented).
pub struct TxCircuit<F: FieldExt> {
    /// private preimage value (optional for prover)
    pub preimage: Option<F>,
}

#[derive(Clone)]
pub struct TxConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

impl<F: FieldExt> TxConfig {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();

        // Enable equality so values can be copied between regions/columns
        meta.enable_equality(advice);
        meta.enable_equality(instance);

        // Simple gate: when selector is enabled, constrain advice == instance
        meta.create_gate("match advice to instance", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice, halo2_proofs::plonk::Rotation::cur());
            let i = meta.query_instance(instance, halo2_proofs::plonk::Rotation::cur());
            vec![s * (a - i)]
        });

        TxConfig { advice, instance, selector }
    }
}

impl<F: FieldExt> Circuit<F> for TxCircuit<F> {
    type Config = TxConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        TxCircuit { preimage: None }
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        TxConfig::configure(cs)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        // Assign the private preimage into the advice column and expose it
        // as a public instance via a simple equality constraint.
        layouter.assign_region(|| "assign preimage", |mut region| {
            config.selector.enable(&mut region, 0)?;

            let offset = 0;
            let value = self.preimage.map(Value::known).unwrap_or(Value::unknown());
            region.assign_advice(|| "preimage", config.advice, offset, || value)?;

            Ok(())
        })?;

        // Expose instance at row 0. In a real circuit, the public inputs would
        // include `state_root_before`, `state_root_after`, and other batch roots.
        layouter.constrain_instance(
            layouter.assign_region(|| "instance zero", |mut region| {
                // This region exists only to provide an accessible cell for constrain_instance.
                region.assign_advice(|| "zero", config.advice, 0, || Value::unknown())?;
                Ok(())
            })?.cell(),
            config.instance,
            0,
        )?;

        Ok(())
    }
}

// Note: This minimal circuit is a starting point. Replace the simple equality
// gate with real Poseidon commitment checks, Merkle path verification gadgets,
// signature-verification gadgets, and range-check tables. Use existing Halo2
// crates/gadgets for Poseidon and ECC when available.
