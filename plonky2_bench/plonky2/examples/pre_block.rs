use num::{BigUint, Num};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    fri::{reduction_strategies::FriReductionStrategy, FriConfig},
    iop::witness::PartialWitness,
    nonnative::biguint::biguint::{CircuitBuilderBiguint, WitnessBigUint},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use std::time::Instant;
// use rand::rngs::OsRng;
use jemallocator::Jemalloc;
use std::fs;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // let mut rng = OsRng;

    let x_value =
        BigUint::from_str_radix("91343852333181432387730302044767688728495783935", 10).unwrap();
    let y_value = BigUint::from_str_radix("1152921504606846975", 10).unwrap();

    // Init circuit
    let config = CircuitConfig {
        num_wires: 135,
        num_routed_wires: 80,
        num_constants: 2,
        use_base_arithmetic_gate: true,
        security_bits: 100,
        num_challenges: 2,
        zero_knowledge: false,
        max_quotient_degree_factor: 8,
        fri_config: FriConfig {
            rate_bits: 3,
            cap_height: 4,
            proof_of_work_bits: 16,
            reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
            num_query_rounds: 28,
        },
    };
    let mut pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Fill targets & connect expected values
    let x = builder.add_virtual_biguint_target(x_value.to_u32_digits().len());
    let y = builder.add_virtual_biguint_target(y_value.to_u32_digits().len());

    pw.set_biguint_target(&x, &x_value);
    pw.set_biguint_target(&y, &y_value);

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

    // Integer division
    for _ in 0..256 {
        let div_result = builder.div_biguint(&x, &y);
        let expected_div = builder.constant_biguint(&(&x_value / &y_value));
        builder.connect_biguint(&div_result, &expected_div);
    }

    let constant_2_to_160_value =
        BigUint::from_str_radix("91343852333181432387730302044767688728495783935", 10).unwrap();
    let constant_2_to_160 = builder.constant_biguint(&constant_2_to_160_value); // 2^160 - 1

    let _true = builder.constant_bool(x_value <= constant_2_to_160_value);

    // IsNegative, which is <160 bits in our case
    for _ in 0..256 {
        let lte = builder.cmp_biguint(&constant_2_to_160, &x);
        builder.connect(lte.target, _true.target);
    }

    // Build the circuit
    let data = builder.build::<C>();

    // Prove
    let start = Instant::now();
    let proof = data.prove(pw).unwrap();
    let duration = start.elapsed();
    println!("Proved in: {:?}", duration);
    fs::write("proof.bin", proof.to_bytes()).expect("Unable to write proof to file");

    // Verify
    let start = Instant::now();
    data.verify(proof).unwrap();
    let duration = start.elapsed();
    println!("Verified in: {:?}", duration);
}
