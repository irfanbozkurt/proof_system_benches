#![allow(warnings)]

use clap::Parser;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::{GateChip, GateInstructions, RangeInstructions};
use halo2_base::poseidon::{hasher::spec::OptimizedPoseidonSpec, hasher::PoseidonHasher};
use halo2_base::utils::BigPrimeField;
use halo2_base::{safe_types, AssignedValue};
use halo2_base::{safe_types::*, QuantumCell};
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::snark_verifier::loader::halo2::IntegerInstructions;
use zkevm_hashes::keccak::component::encode::{encode_fix_len_bytes_vec, encode_native_input};
use zkevm_hashes::util::eth_types::Field;

const KECCAK_BYTE_SIZE: usize = 244;
const KECCAK_ITER_COUNT: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {}

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 56;

fn verify_block<F: Field + BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    _: CircuitInput,
    _: &mut Vec<AssignedValue<F>>,
) {
    let range = builder.range_chip();
    let gate = GateChip::<F>::default();

    let safe_type = SafeTypeChip::new(&range);

    let ctx: &mut halo2_base::Context<F> = builder.main(0);

    let x = ctx.load_witness(
        F::from_str_vartime("91343852333181432387730302044767688728495783934").unwrap(),
    ); // 2^160 - 1
    let y = ctx.load_witness(F::from_str_vartime("1152921504606846975").unwrap());

    // Poseidon (instead of GkrMimc)
    let mut poseidon =
        PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
    poseidon.initialize_consts(ctx, &gate);
    for _ in 0..1 {
        poseidon.hash_fix_len_array(ctx, &gate, &[x, y]);
    }

    // Keccak
    for _ in 0..KECCAK_ITER_COUNT {
        let raw_input: Vec<u8> = x
            .value()
            .to_bytes_le()
            .into_iter()
            .cycle()
            .take(KECCAK_BYTE_SIZE)
            .collect::<Vec<_>>();

        let assigned_input: Vec<AssignedValue<F>> = range
            .decompose_le(ctx, x, 8, 32)
            .into_iter()
            .cycle()
            .take(KECCAK_BYTE_SIZE)
            .collect();
        let len = assigned_input.len();
        let fix_len_bytes_vec = safe_type.raw_to_fix_len_bytes_vec(ctx, assigned_input, len);

        let keccak = encode_fix_len_bytes_vec(ctx, &gate, &poseidon, &fix_len_bytes_vec);

        let expected_value = encode_native_input::<F>(&raw_input);
        let expected = ctx.load_witness(expected_value);
        gate.is_equal(ctx, expected, keccak);
    }

    // To binary
    let x_bits = range.decompose_le(ctx, x, 1, 160);
    for _ in 0..83 {
        range.decompose_le(ctx, x, 1, 160);
    }

    // From binary
    for _ in 0..484 {
        let x_from_bits = range.limbs_to_num(ctx, &x_bits, 1);
        gate.is_equal(ctx, x, x_from_bits);
    }

    // Comparison
    for _ in 0..3 {
        let lte = range.is_less_than(ctx, y, x, 160);
        gate.is_zero(ctx, lte);
    }

    // Asserted comparison
    for _ in 0..1 {
        range.check_less_than(ctx, y, x, 160);
    }

    // Integer division
    for _ in 0..1 {
        gate.div_unsafe(ctx, x, y);
    }
}

fn main() {
    env_logger::init();
    run(verify_block, Cli::parse());
}
