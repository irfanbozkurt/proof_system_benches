use crate::gates::arithmetic_base::ArithmeticGate;
use crate::gates::arithmetic_extension::ArithmeticExtensionGate;
use crate::gates::base_sum::BaseSumGate;
use crate::hash::hash_types::RichField;
use crate::iop::generator::{GeneratedValues, SimpleGenerator};
use crate::iop::target::{BoolTarget, Target};
use crate::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use crate::plonk::circuit_builder::CircuitBuilder;
use itertools::Itertools;
use plonky2_field::extension::Extendable;
use std::borrow::Borrow;

pub trait CircuitBuilderSplit<F: RichField + Extendable<D>, const D: usize> {
    fn split_le_base<const B: usize>(&mut self, x: Target, num_limbs: usize) -> Vec<Target>;
    fn assert_leading_zeros(&mut self, x: Target, leading_zeros: u32);
    fn num_ext_arithmetic_ops_per_gate(&self) -> usize;
    fn num_base_arithmetic_ops_per_gate(&self) -> usize;
    fn le_sum(&mut self, bits: impl Iterator<Item = impl Borrow<BoolTarget>>) -> Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSplit<F, D>
    for CircuitBuilder<F, D>
{
    /// Split the given element into a list of targets, where each one represents a
    /// base-B limb of the element, with little-endian ordering.
    fn split_le_base<const B: usize>(&mut self, x: Target, num_limbs: usize) -> Vec<Target> {
        let gate_type = BaseSumGate::<B>::new(num_limbs);
        let gate = self.add_gate(gate_type, vec![]);
        let sum = Target::wire(gate, BaseSumGate::<B>::WIRE_SUM);
        self.connect(x, sum);

        Target::wires_from_range(gate, gate_type.limbs())
    }

    /// Asserts that `x`'s big-endian bit representation has at least `leading_zeros` leading zeros.
    fn assert_leading_zeros(&mut self, x: Target, leading_zeros: u32) {
        self.range_check(x, (64 - leading_zeros) as usize);
    }

    fn num_ext_arithmetic_ops_per_gate(&self) -> usize {
        ArithmeticExtensionGate::<D>::new_from_config(&self.config).num_ops
    }

    fn num_base_arithmetic_ops_per_gate(&self) -> usize {
        if self.config.use_base_arithmetic_gate {
            ArithmeticGate::new_from_config(&self.config).num_ops
        } else {
            self.num_ext_arithmetic_ops_per_gate()
        }
    }

    /// Takes an iterator of bits `(b_i)` and returns `sum b_i * 2^i`, i.e.,
    /// the number with little-endian bit representation given by `bits`.
    fn le_sum(&mut self, bits: impl Iterator<Item = impl Borrow<BoolTarget>>) -> Target {
        let bits = bits.map(|b| *b.borrow()).collect_vec();
        let num_bits = bits.len();
        if num_bits == 0 {
            return self.zero();
        }

        // Check if it's cheaper to just do this with arithmetic operations.
        let arithmetic_ops = num_bits - 1;
        if arithmetic_ops <= self.num_base_arithmetic_ops_per_gate() {
            let two = self.two();
            let mut rev_bits = bits.iter().rev();
            let mut sum = rev_bits.next().unwrap().target;
            for &bit in rev_bits {
                sum = self.mul_add(two, sum, bit.target);
            }
            return sum;
        }

        debug_assert!(
            BaseSumGate::<2>::START_LIMBS + num_bits <= self.config.num_routed_wires,
            "Not enough routed wires."
        );
        let gate_type = BaseSumGate::<2>::new_from_config::<F>(&self.config);
        let row = self.add_gate(gate_type, vec![]);
        for (limb, wire) in bits
            .iter()
            .zip(BaseSumGate::<2>::START_LIMBS..BaseSumGate::<2>::START_LIMBS + num_bits)
        {
            self.connect(limb.target, Target::wire(row, wire));
        }
        for l in gate_type.limbs().skip(num_bits) {
            self.assert_zero(Target::wire(row, l));
        }

        self.add_simple_generator(BaseSumGenerator::<D> { row, limbs: bits });

        Target::wire(row, BaseSumGate::<D>::WIRE_SUM)
    }
}

#[derive(Debug)]
struct BaseSumGenerator<const B: usize> {
    row: usize,
    limbs: Vec<BoolTarget>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for BaseSumGenerator<D> {
    fn dependencies(&self) -> Vec<Target> {
        self.limbs.iter().map(|b| b.target).collect()
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let sum = self
            .limbs
            .iter()
            .map(|&t| witness.get_bool_target(t))
            .rev()
            .fold(F::ZERO, |acc, limb| {
                acc * F::from_canonical_usize(D) + F::from_bool(limb)
            });

        out_buffer.set_target(Target::wire(self.row, BaseSumGate::<D>::WIRE_SUM), sum);
    }

    fn id(&self) -> String {
        todo!()
    }

    fn serialize(
        &self,
        _: &mut Vec<u8>,
        _: &crate::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> crate::util::serialization::IoResult<()> {
        todo!()
    }

    fn deserialize(
        _: &mut crate::util::serialization::Buffer,
        _: &crate::plonk::circuit_data::CommonCircuitData<F, D>,
    ) -> crate::util::serialization::IoResult<Self>
    where
        Self: Sized,
    {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::iop::witness::PartialWitness;
    use crate::plonk::circuit_builder::CircuitBuilder;
    use crate::plonk::circuit_data::CircuitConfig;
    use crate::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use anyhow::Result;
    use plonky2_field::types::Field;
    use rand::prelude::*;

    #[test]
    fn test_split_base() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let x = F::from_canonical_usize(0b110100000); // 416 = 1532 in base 6.
        let xt = builder.constant(x);
        let limbs = builder.split_le_base::<6>(xt, 24);
        let one = builder.one();
        let two = builder.two();
        let three = builder.constant(F::from_canonical_u64(3));
        let five = builder.constant(F::from_canonical_u64(5));
        builder.connect(limbs[0], two);
        builder.connect(limbs[1], three);
        builder.connect(limbs[2], five);
        builder.connect(limbs[3], one);

        builder.assert_leading_zeros(xt, 64 - 9);
        let data = builder.build::<C>();

        let proof = data.prove(pw)?;

        data.verify(proof)
    }

    #[test]
    fn test_base_sum() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let n = thread_rng().gen_range(0..(1 << 30));
        let x = builder.constant(F::from_canonical_usize(n));

        let zero = builder._false();
        let one = builder._true();

        let y = builder.le_sum(
            (0..30)
                .scan(n, |acc, _| {
                    let tmp = *acc % 2;
                    *acc /= 2;
                    Some(if tmp == 1 { one } else { zero })
                })
                .collect::<Vec<_>>()
                .iter(),
        );

        builder.connect(x, y);

        let data = builder.build::<C>();

        let proof = data.prove(pw)?;

        data.verify(proof)
    }
}
