use jemallocator::Jemalloc;
use num::{BigUint, Num};
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::nonnative::biguint::nonnative::CircuitBuilderNonNative;
use plonky2::nonnative::biguint::nonnative::NonNativeTarget;
use plonky2::nonnative::biguint::split_nonnative::CircuitBuilderSplit;
use plonky2::plonk::config::Hasher;
use plonky2::{
    fri::{reduction_strategies::FriReductionStrategy, FriConfig},
    iop::witness::{PartialWitness, WitnessWrite},
    nonnative::biguint::biguint::{CircuitBuilderBiguint, WitnessBigUint},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use std::fs;
use std::time::Instant;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

fn main() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // let mut rng = OsRng;

    let negative_example_value =
        BigUint::from_str_radix("91343852333181432387730302044767688728495783945", 10).unwrap(); // 2^160+16
    let upper_limit_value =
        BigUint::from_str_radix("91343852333181432387730302044767688728495783935", 10).unwrap(); // 2^160
    let x_value =
        BigUint::from_str_radix("91343852333181432387730302044767688728495783934", 10).unwrap(); // 2^160-1
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
    let upper_limit = builder.add_virtual_biguint_target(upper_limit_value.to_u32_digits().len());
    let negative_example =
        builder.add_virtual_biguint_target(negative_example_value.to_u32_digits().len());

    pw.set_biguint_target(&x, &x_value);
    pw.set_biguint_target(&y, &y_value);
    pw.set_biguint_target(&upper_limit, &upper_limit_value);
    pw.set_biguint_target(&negative_example, &negative_example_value);

    // Poseidon (Instead of MiMC)
    let x_limbs: Vec<F> = x_value
        .to_u32_digits()
        .iter()
        .map(|u32_val| F::from_canonical_u32(*u32_val))
        .collect();
    let expected_hash_out = PoseidonHash::hash_no_pad(x_limbs.as_slice());
    for _ in 0..5648 {
        let public_inputs_hash = builder
            .hash_n_to_hash_no_pad::<<C as GenericConfig<D>>::InnerHasher>(
                x.limbs.iter().map(|u32_target| u32_target.0).collect(),
            );
        pw.set_hash_target(public_inputs_hash, expected_hash_out);
    }

    // To binary
    let nonnative_x = builder.biguint_to_nonnative::<F>(&x);
    let split = builder.split_nonnative_to_1_bit_limbs(&nonnative_x);
    let combined: NonNativeTarget<F> = builder.recombine_nonnative_bits(&split);
    builder.connect_nonnative(&nonnative_x, &combined);
    for _ in 0..64 {
        let nonnative_x = builder.biguint_to_nonnative::<F>(&x);
        let split = builder.split_nonnative_to_1_bit_limbs(&nonnative_x);
        let combined = builder.recombine_nonnative_bits(&split);
        builder.connect_nonnative(&nonnative_x, &combined);
    }

    // From binary
    for _ in 0..(236 - 65) {
        let combined = builder.recombine_nonnative_bits(&split);
        builder.connect_nonnative(&nonnative_x, &combined);
    }

    // Comparison
    for _ in 0..49 {
        let lte = builder.cmp_biguint(&y, &x);
        let expected_lte = builder.constant_bool(y_value <= x_value);
        builder.connect(lte.target, expected_lte.target);
    }

    // Asserted Comparison
    for _ in 0..19 {
        let lte = builder.cmp_biguint(&y, &x);
        let expected_lte = builder.constant_bool(y_value <= x_value);
        builder.connect(lte.target, expected_lte.target);
    }

    // Integer division
    for _ in 0..13 {
        let div_result = builder.div_biguint(&x, &y);
        let expected_div = builder.constant_biguint(&(&x_value / &y_value));
        builder.connect_biguint(&div_result, &expected_div);
    }

    let _true = builder.constant_bool(x_value <= upper_limit_value);

    // IsNegative, which is <160 bits in our case
    for _ in 0..6 {
        let lte = builder.cmp_biguint(&x, &upper_limit);
        builder.connect(lte.target, _true.target);
    }

    // Abs
    for _ in 0..4 {
        let lte = builder.cmp_biguint(&upper_limit, &negative_example);
        builder.connect(lte.target, _true.target);
        builder.sub_biguint(&negative_example, &upper_limit);
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
