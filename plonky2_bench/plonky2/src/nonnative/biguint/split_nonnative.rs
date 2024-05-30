extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::field::extension::Extendable;
use crate::field::types::Field;
use crate::hash::hash_types::RichField;
use crate::iop::target::Target;
use crate::nonnative::u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::plonk::circuit_builder::CircuitBuilder;
use itertools::Itertools;

use crate::nonnative::biguint::biguint::BigUintTarget;
use crate::nonnative::biguint::nonnative::NonNativeTarget;

pub trait CircuitBuilderSplit<F: RichField + Extendable<D>, const D: usize> {
    fn split_u32_to_4_bit_limbs(&mut self, val: U32Target) -> Vec<Target>;

    fn split_nonnative_to_4_bit_limbs<FF: Field>(
        &mut self,
        val: &NonNativeTarget<FF>,
    ) -> Vec<Target>;

    fn split_nonnative_to_2_bit_limbs<FF: Field>(
        &mut self,
        val: &NonNativeTarget<FF>,
    ) -> Vec<Target>;

    // Note: assumes its inputs are 4-bit limbs, and does not range-check.
    fn recombine_nonnative_4_bit_limbs<FF: Field>(
        &mut self,
        limbs: Vec<Target>,
    ) -> NonNativeTarget<FF>;

    fn split_nonnative_to_1_bit_limbs<FF: Field>(
        &mut self,
        val: &NonNativeTarget<FF>,
    ) -> Vec<Target>;

    // Note: assumes its inputs are 4-bit limbs, and does not range-check.
    fn recombine_nonnative_bits<FF: Field>(&mut self, limbs: &[Target]) -> NonNativeTarget<FF>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSplit<F, D>
    for CircuitBuilder<F, D>
{
    fn split_u32_to_4_bit_limbs(&mut self, val: U32Target) -> Vec<Target> {
        let two_bit_limbs = self.split_le_base::<4>(val.0, 16);
        let four = self.constant(F::from_canonical_usize(4));
        let combined_limbs = two_bit_limbs
            .iter()
            .tuples()
            .map(|(&a, &b)| self.mul_add(b, four, a))
            .collect();

        combined_limbs
    }

    fn split_nonnative_to_4_bit_limbs<FF: Field>(
        &mut self,
        val: &NonNativeTarget<FF>,
    ) -> Vec<Target> {
        val.value
            .limbs
            .iter()
            .flat_map(|&l| self.split_u32_to_4_bit_limbs(l))
            .collect()
    }

    fn split_nonnative_to_2_bit_limbs<FF: Field>(
        &mut self,
        val: &NonNativeTarget<FF>,
    ) -> Vec<Target> {
        val.value
            .limbs
            .iter()
            .flat_map(|&l| self.split_le_base::<4>(l.0, 16))
            .collect()
    }

    fn split_nonnative_to_1_bit_limbs<FF: Field>(
        &mut self,
        val: &NonNativeTarget<FF>,
    ) -> Vec<Target> {
        val.value
            .limbs
            .iter()
            .flat_map(|&l| self.split_le_base::<2>(l.0, 32))
            .collect()
    }

    fn recombine_nonnative_bits<FF: Field>(&mut self, limbs: &[Target]) -> NonNativeTarget<FF> {
        let base = self.constant_u32(1 << 1);
        let u32_limbs = limbs
            .chunks(32)
            .map(|chunk| {
                let mut combined_chunk = self.zero_u32();
                for i in (0..32).rev() {
                    let (low, _high) = self.mul_add_u32(combined_chunk, base, U32Target(chunk[i]));
                    combined_chunk = low;
                }
                combined_chunk
            })
            .collect();

        NonNativeTarget {
            value: BigUintTarget { limbs: u32_limbs },
            _phantom: PhantomData,
        }
    }
    // Note: assumes its inputs are 4-bit limbs, and does not range-check.
    fn recombine_nonnative_4_bit_limbs<FF: Field>(
        &mut self,
        limbs: Vec<Target>,
    ) -> NonNativeTarget<FF> {
        let base = self.constant_u32(1 << 4);
        let u32_limbs = limbs
            .chunks(8)
            .map(|chunk| {
                let mut combined_chunk = self.zero_u32();
                for i in (0..8).rev() {
                    let (low, _high) = self.mul_add_u32(combined_chunk, base, U32Target(chunk[i]));
                    combined_chunk = low;
                }
                combined_chunk
            })
            .collect();

        NonNativeTarget {
            value: BigUintTarget { limbs: u32_limbs },
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::field::secp256k1_scalar::Secp256K1Scalar;
    use crate::field::types::Sample;
    use crate::iop::witness::PartialWitness;
    use crate::plonk::circuit_data::CircuitConfig;
    use crate::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use anyhow::Result;

    use super::*;
    use crate::nonnative::biguint::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

    #[test]
    fn test_split_nonnative() -> Result<()> {
        type FF = Secp256K1Scalar;
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_ecc_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = FF::rand();
        let x_target = builder.constant_nonnative(x);
        let split = builder.split_nonnative_to_4_bit_limbs(&x_target);
        let combined: NonNativeTarget<Secp256K1Scalar> =
            builder.recombine_nonnative_4_bit_limbs(split);
        builder.connect_nonnative(&x_target, &combined);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
