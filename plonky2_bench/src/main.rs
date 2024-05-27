use num::{BigUint, Num};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_bench::biguint::biguint::{CircuitBuilderBiguint, WitnessBigUint};
// use rand::rngs::OsRng;

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;

fn bench_circuit() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // let mut rng = OsRng;

    let x_value =
        BigUint::from_str_radix("91343852333181432387730302044767688728495783935", 10).unwrap();
    let y_value = BigUint::from_str_radix("1152921504606846975", 10).unwrap();
    let expected_z_value = &x_value + &y_value;

    // Init circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Fill targets & connect expected values
    let x = builder.add_virtual_biguint_target(x_value.to_u32_digits().len());
    let y = builder.add_virtual_biguint_target(y_value.to_u32_digits().len());
    let z = builder.add_biguint(&x, &y);
    let expected_z = builder.add_virtual_biguint_target(expected_z_value.to_u32_digits().len());
    builder.connect_biguint(&z, &expected_z);

    pw.set_biguint_target(&x, &x_value);
    pw.set_biguint_target(&y, &y_value);
    pw.set_biguint_target(&expected_z, &expected_z_value);

    // Comparison
    for _ in 0..1280 {
        let lte = builder.cmp_biguint(&y, &x);
        let expected_lte = builder.constant_bool(y_value <= x_value);
        builder.connect(lte.target, expected_lte.target);
    }

    // Asserted Comparison
    for _ in 0..1024 {
        let lte = builder.cmp_biguint(&y, &x);
        let expected_lte = builder.constant_bool(y_value <= x_value);
        builder.connect(lte.target, expected_lte.target);
    }

    // Build the circuit
    let data = builder.build::<C>();

    // Prove
    let proof = data.prove(pw).unwrap();

    // Verify
    data.verify(proof).unwrap();
}

fn main() {
    // standard_circuit();
    bench_circuit();
}
