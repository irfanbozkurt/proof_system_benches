use clap::Parser;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::{GateChip, GateInstructions, RangeInstructions};
use halo2_base::poseidon::{hasher::spec::OptimizedPoseidonSpec, hasher::PoseidonHasher};
use halo2_base::safe_types::*;
use halo2_base::utils::BigPrimeField;
use halo2_base::{safe_types, AssignedValue};
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::snark_verifier::loader::halo2::IntegerInstructions;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {}

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 56;

fn tx_loop<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    _: CircuitInput,
    _: &mut Vec<AssignedValue<F>>,
) {
    // Init the context

    let range = builder.range_chip();
    let gate = GateChip::<F>::default();

    let safe_type = SafeTypeChip::new(&range);

    let ctx: &mut halo2_base::Context<F> = builder.main(0);

    let upper = ctx.load_witness(
        F::from_str_vartime("91343852333181432387730302044767688728495783935").unwrap(),
    ); // 2^160
    let x = ctx.load_witness(
        F::from_str_vartime("91343852333181432387730302044767688728495783934").unwrap(),
    ); // 2^160 - 1
    let y = ctx.load_witness(F::from_str_vartime("1152921504606846975").unwrap());

    // Poseidon (instead of MiMC)
    let mut poseidon =
        PoseidonHasher::<F, T, RATE>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
    poseidon.initialize_consts(ctx, &gate);

    for _ in 0..5648 {
        poseidon.hash_fix_len_array(ctx, &gate, &[x, y]);
    }

    // To binary
    let x_bits = range.decompose_le(ctx, x, 1, 160);
    for _ in 0..64 {
        range.decompose_le(ctx, x, 1, 160);
    }

    // From binary
    for _ in 0..236 {
        let x_from_bits = range.limbs_to_num(ctx, &x_bits, 1);
        gate.is_equal(ctx, x, x_from_bits);
    }

    // Comparison
    for _ in 0..49 {
        let lte = range.is_less_than(ctx, y, x, 160);
        gate.is_zero(ctx, lte);
    }

    // Asserted comparison
    for _ in 0..19 {
        range.check_less_than(ctx, y, x, 160);
    }

    // Integer division
    for _ in 0..13 {
        gate.div_unsafe(ctx, x, y);
    }

    // IsNegative
    for _ in 0..6 {
        range.range_check(ctx, x, 160);
    }

    // Abs
    for _ in 0..4 {
        range.range_check(ctx, x, 160);
        // Always add to consider the worst case
        gate.add(ctx, x, upper); // add 2^160 to make negative
    }
}

fn main() {
    env_logger::init();
    run(tx_loop, Cli::parse());
}
