extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::field::extension::Extendable;
use crate::hash::hash_types::RichField;
use crate::iop::target::Target;
use crate::plonk::circuit_builder::CircuitBuilder;

use crate::nonnative::u32::gadgets::arithmetic_u32::U32Target;
use crate::nonnative::u32::gates::range_check_u32::U32RangeCheckGate;

pub fn range_check_u32_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    vals: Vec<U32Target>,
) {
    let num_input_limbs = vals.len();
    let gate = U32RangeCheckGate::<F, D>::new(num_input_limbs);
    let row = builder.add_gate(gate, vec![]);

    for i in 0..num_input_limbs {
        builder.connect(Target::wire(row, gate.wire_ith_input_limb(i)), vals[i].0);
    }
}
