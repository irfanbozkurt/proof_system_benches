use clap::Parser;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::{GateChip, GateInstructions, RangeInstructions};
use halo2_base::utils::ScalarField;
use halo2_base::AssignedValue;
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {}

fn pre_block<F: ScalarField>(
    builder: &mut BaseCircuitBuilder<F>,
    _: CircuitInput,
    _: &mut Vec<AssignedValue<F>>,
) {
    // Init the context
    // Start the chips
    let range = builder.range_chip();
    let gate = GateChip::<F>::default();
    let ctx: &mut halo2_base::Context<F> = builder.main(0);

    let x = ctx.load_witness(
        F::from_str_vartime("91343852333181432387730302044767688728495783935").unwrap(),
    ); // 2^160 - 1
    let y = ctx.load_witness(F::from_str_vartime("1152921504606846975").unwrap());

    // Comparison
    for _ in 0..1280 {
        let _ = range.is_less_than(ctx, y, x, 160);
    }

    // Asserted comparison
    for _ in 0..1024 {
        range.check_less_than(ctx, y, x, 160);
    }

    // Integer division
    for _ in 0..256 {
        gate.div_unsafe(ctx, x, y);
    }

    // IsNegative
    for _ in 0..256 {
        range.range_check(ctx, x, 160);
    }
}

fn main() {
    env_logger::init();
    run(pre_block, Cli::parse());
}
