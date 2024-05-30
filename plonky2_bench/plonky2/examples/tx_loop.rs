use jemallocator::Jemalloc;
use num::{BigUint, Num};
use plonky2::field::cosets::get_unique_coset_shifts;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::fft::fft_root_table;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::fri::FriParams;
use plonky2::gadgets::hash::*;
use plonky2::gadgets::polynomial::PolynomialCoeffsExtTarget;
use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::gate::Gate;
use plonky2::gates::gate::{CurrentSlot, GateInstance, GateRef};
use plonky2::gates::gate_testing::{test_eval_fns, test_low_degree};
use plonky2::gates::lookup::{Lookup, LookupGate};
use plonky2::gates::lookup_table::LookupTable;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, MerkleCapTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::generator::generate_partial_witness;
use plonky2::iop::generator::{
    ConstantGenerator, CopyGenerator, RandomValueGenerator, SimpleGenerator, WitnessGeneratorRef,
};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::nonnative::biguint::nonnative::CircuitBuilderNonNative;
use plonky2::nonnative::biguint::nonnative::NonNativeTarget;
use plonky2::nonnative::biguint::split_nonnative::CircuitBuilderSplit;
use plonky2::plonk::circuit_data::{
    CircuitData, CommonCircuitData, MockCircuitData, ProverCircuitData, ProverOnlyCircuitData,
    VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::{AlgebraicHasher, Hasher};
use plonky2::plonk::plonk_common::PlonkOracle;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::util::{log2_ceil, log2_strict, transpose};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    fri::{reduction_strategies::FriReductionStrategy, FriConfig},
    gates::poseidon::PoseidonGate,
    hash::{hash_types::RichField, poseidon::SPONGE_WIDTH},
    iop::{
        wire::Wire,
        witness::{PartialWitness, WitnessWrite},
    },
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

    // // Poseidon
    // let x_limbs: Vec<F> = x_value
    //     .to_u32_digits()
    //     .iter()
    //     .map(|u32_val| F::from_canonical_u32(*u32_val))
    //     .collect();
    // let expected_hash_out = PoseidonHash::hash_no_pad(x_limbs.as_slice());
    // for _ in 0..5648 {
    //     let public_inputs_hash = builder
    //         .hash_n_to_hash_no_pad::<<C as GenericConfig<D>>::InnerHasher>(
    //             x.limbs.iter().map(|u32_target| u32_target.0).collect(),
    //         );
    //     pw.set_hash_target(public_inputs_hash, expected_hash_out);
    // }

    // To binary
    for _ in 0..64 {
        println!("{}", x.num_limbs());
        let nonnative_target = builder.biguint_to_nonnative::<F>(&x);
        let split = builder.split_nonnative_to_1_bit_limbs(&nonnative_target);
        let combined = builder.recombine_nonnative_bits(&split);
        // let combined: NonNativeTarget<F> =
        //     builder.recombine_nonnative_bits(split.iter().map(|t| t.target).collect());

        builder.connect_nonnative(&nonnative_target, &combined);
    }

    // From binary
    for _ in 0..236 {}

    // // Comparison
    // for _ in 0..1280 {
    //     let lte = builder.cmp_biguint(&y, &x);
    //     let expected_lte = builder.constant_bool(y_value <= x_value);
    //     builder.connect(lte.target, expected_lte.target);
    // }

    // // Asserted Comparison
    // for _ in 0..1024 {
    //     let lte = builder.cmp_biguint(&y, &x);
    //     let expected_lte = builder.constant_bool(y_value <= x_value);
    //     builder.connect(lte.target, expected_lte.target);
    // }

    // // Integer division
    // for _ in 0..256 {
    //     let div_result = builder.div_biguint(&x, &y);
    //     let expected_div = builder.constant_biguint(&(&x_value / &y_value));
    //     builder.connect_biguint(&div_result, &expected_div);
    // }

    // let constant_2_to_160_value =
    //     BigUint::from_str_radix("91343852333181432387730302044767688728495783935", 10).unwrap();
    // let constant_2_to_160 = builder.constant_biguint(&constant_2_to_160_value); // 2^160 - 1

    // let _true = builder.constant_bool(x_value <= constant_2_to_160_value);

    // // IsNegative, which is <160 bits in our case
    // for _ in 0..256 {
    //     let lte = builder.cmp_biguint(&constant_2_to_160, &x);
    //     builder.connect(lte.target, _true.target);
    // }

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
