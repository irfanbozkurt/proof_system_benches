use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use core::str::FromStr;
use num_bigint::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::extension::FieldExtension;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

#[derive(Copy, Clone)]
struct PreBlockStark<F: RichField + Extendable<D>, const D: usize> {
    num_rows: usize,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> PreBlockStark<F, D> {
    // 2^160
    fn neg_limit() -> BigUint {
        BigUint::from_str("91343852333181432387730302044767688728495783935").unwrap()
    }
    // 2^160-1
    fn x() -> BigUint {
        BigUint::from_str("91343852333181432387730302044767688728495783934").unwrap()
    }
    fn y() -> BigUint {
        BigUint::from_str("1152921504606846975").unwrap()
    }

    const fn new(num_rows: usize) -> Self {
        Self {
            num_rows,
            _phantom: PhantomData,
        }
    }

    // Work with u32 registers
    // [0..1279] -> non-asserted comparison [u32; 4], write result to 9th register
    // [1280..2304] -> asserted comparison [u32; 4], [u32; 4], no result
    // [2305..2559] -> is_negative [u32; 4], write result to 9th register
    // [2560..2815] -> integer division [u32; 4], [u32; 4], write result to 10..15 registers
    fn generate_trace(&self, row: [u32; 15]) -> Vec<PolynomialValues<F>> {
        let trace_rows: Vec<[F; 15]> = (0..self.num_rows)
            .scan(row, |acc, idx| {
                // Non-asserted comparison
                // We store the result in a register.
                if idx < 1280 {
                    let _x: [u32; 5] = acc[0..5].try_into().unwrap();
                    let _y: [u32; 5] = acc[5..10].try_into().unwrap();

                    // If y < x, cmp_result = 1, otherwise 0
                    let _x_biguint = BigUint::from_slice(&_x);
                    let _y_biguint = BigUint::from_slice(&_y);

                    // Store the result in 11th u32 register
                    acc[11] = _x_biguint.cmp(&_y_biguint).is_gt() as u32;
                }
                // Asserted comparison.
                // Just store the numbers in registers, and leave them unchanged.
                else if idx < 2304 {
                    let _x: [u32; 5] = acc[0..5].try_into().unwrap();
                    let _y: [u32; 5] = acc[5..10].try_into().unwrap();
                }
                // IsNegative
                // Check if the number has more than 160 bits
                // Write the result in 9th register
                else if idx < 2560 {
                    let _x: [u32; 5] = acc[0..5].try_into().unwrap();
                    let _x_biguint = BigUint::from_slice(&_x);

                    // Store the result in 11th u32 register
                    acc[11] = _x_biguint.cmp(&Self::neg_limit()).is_gt() as u32;
                }
                // Integer division for numbers with
                else if idx < 2816 {
                    let _x: [u32; 5] = acc[0..5].try_into().unwrap();
                    let _y: [u32; 5] = acc[5..10].try_into().unwrap();

                    // If y < x, cmp_result = 1, otherwise 0
                    let _x_biguint = BigUint::from_slice(&_x);
                    let _y_biguint = BigUint::from_slice(&_y);

                    // Store the result in registers 10..15
                    let res: [u32; 5] = (_x_biguint / _y_biguint)
                        .to_u32_digits()
                        .try_into()
                        .unwrap();
                    acc[10..15].copy_from_slice(&res);
                }

                // Somewhere else, we'll also define the constraints.
                Some(*acc)
            })
            .map(|row| {
                row.iter()
                    .map(|&x| F::from_canonical_u32(x))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        trace_rows_to_poly_values(trace_rows)
    }
}

const BENCH_COLUMNS: usize = 15;
const FIBONACCI_PUBLIC_INPUTS: usize = 2;

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for PreBlockStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, P::Scalar, BENCH_COLUMNS, FIBONACCI_PUBLIC_INPUTS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget =
        StarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, BENCH_COLUMNS, FIBONACCI_PUBLIC_INPUTS>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        // Put constraints

        let local_values = vars.get_local_values();
        // let next_values = vars.get_next_values(); // No transition constraints
        let public_inputs = vars.get_public_inputs();

        // Check public inputs.
        for _ in 0..1280 {
            yield_constr.constraint_first_row(local_values[11] - FE::ONE);
        }
        for _ in 1280..2304 {
            // Bitify limbs one by one to assert >=

            // This doesn't look correct
            let constraint = (local_values[0] - local_values[5])
                * (local_values[1] - local_values[6])
                * (local_values[2] - local_values[7])
                * (local_values[3] - local_values[8])
                * (local_values[4] - local_values[9]);
            yield_constr.constraint_first_row(constraint);
        }

        // if idx < 1280 {
        //     let _x: [u32; 5] = acc[0..5].try_into().unwrap();
        //     let _y: [u32; 5] = acc[5..10].try_into().unwrap();

        //     // If y < x, cmp_result = 1, otherwise 0
        //     let _x_biguint = BigUint::from_slice(&_x);
        //     let _y_biguint = BigUint::from_slice(&_y);

        //     // Store the result in 11th u32 register
        //     acc[11] = _x_biguint.cmp(&_y_biguint).is_gt() as u32;
        // }
        // // Asserted comparison.
        // // Just store the numbers in registers, and leave them unchanged.
        // else if idx <  {
        //     let _x: [u32; 5] = acc[0..5].try_into().unwrap();
        //     let _y: [u32; 5] = acc[5..10].try_into().unwrap();
        // }
        // // IsNegative
        // // Check if the number has more than 160 bits
        // // Write the result in 9th register
        // else if idx < 2560 {
        //     let _x: [u32; 5] = acc[0..5].try_into().unwrap();
        //     let _x_biguint = BigUint::from_slice(&_x);

        //     // Store the result in 11th u32 register
        //     acc[11] = _x_biguint.cmp(&Self::neg_limit()).is_gt() as u32;
        // }
        // // Integer division for numbers with
        // else if idx < 2816 {
        // }
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: &Self::EvaluationFrameTarget,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values = vars.get_local_values();
        let next_values = vars.get_next_values();
        let public_inputs = vars.get_public_inputs();
        // Check public inputs.
        let pis_constraints = [
            builder.sub_extension(local_values[0], public_inputs[Self::X]),
            builder.sub_extension(local_values[1], public_inputs[Self::Y]),
            builder.sub_extension(local_values[1], public_inputs[Self::LAST_EXPECTED_RES]),
        ];
        yield_constr.constraint_first_row(builder, pis_constraints[0]);
        yield_constr.constraint_first_row(builder, pis_constraints[1]);
        yield_constr.constraint_last_row(builder, pis_constraints[2]);

        // x0' <- x1
        let first_col_constraint = builder.sub_extension(next_values[0], local_values[1]);
        yield_constr.constraint_transition(builder, first_col_constraint);
        // x1' <- x0 + x1
        let second_col_constraint = {
            let tmp = builder.sub_extension(next_values[1], local_values[0]);
            builder.sub_extension(tmp, local_values[1])
        };
        yield_constr.constraint_transition(builder, second_col_constraint);
    }

    fn constraint_degree(&self) -> usize {
        2
    }
}

// #[cfg(test)]
// mod tests {
//     use anyhow::Result;
//     use plonky2::field::extension::Extendable;
//     use plonky2::field::types::Field;
//     use plonky2::hash::hash_types::RichField;
//     use plonky2::iop::witness::PartialWitness;
//     use plonky2::plonk::circuit_builder::CircuitBuilder;
//     use plonky2::plonk::circuit_data::CircuitConfig;
//     use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
//     use plonky2::util::timing::TimingTree;

//     use crate::config::StarkConfig;
//     use crate::pre_block_stark::PreBlockStark;
//     use crate::proof::StarkProofWithPublicInputs;
//     use crate::prover::prove;
//     use crate::recursive_verifier::{
//         add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target,
//         verify_stark_proof_circuit,
//     };
//     use crate::stark::Stark;
//     use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
//     use crate::verifier::verify_stark_proof;

//     fn fibonacci<F: Field>(n: usize, x0: F, x1: F) -> F {
//         (0..n).fold((x0, x1), |x, _| (x.1, x.0 + x.1)).1
//     }

//     #[test]
//     fn test_fibonacci_stark() -> Result<()> {
//         const D: usize = 2;
//         type C = PoseidonGoldilocksConfig;
//         type F = <C as GenericConfig<D>>::F;
//         type S = PreBlockStark<F, D>;

//         let config = StarkConfig::standard_fast_config();
//         let num_rows = 1 << 5;
//         let public_inputs = [F::ZERO, F::ONE, fibonacci(num_rows - 1, F::ZERO, F::ONE)];

//         let stark = S::new(num_rows);
//         let trace = stark.generate_trace(public_inputs[0], public_inputs[1]);
//         let proof = prove::<F, C, S, D>(
//             stark,
//             &config,
//             trace,
//             &public_inputs,
//             &mut TimingTree::default(),
//         )?;

//         verify_stark_proof(stark, proof, &config)
//     }

//     #[test]
//     fn test_fibonacci_stark_degree() -> Result<()> {
//         const D: usize = 2;
//         type C = PoseidonGoldilocksConfig;
//         type F = <C as GenericConfig<D>>::F;
//         type S = PreBlockStark<F, D>;

//         let num_rows = 1 << 5;
//         let stark = S::new(num_rows);
//         test_stark_low_degree(stark)
//     }

//     #[test]
//     fn test_fibonacci_stark_circuit() -> Result<()> {
//         const D: usize = 2;
//         type C = PoseidonGoldilocksConfig;
//         type F = <C as GenericConfig<D>>::F;
//         type S = PreBlockStark<F, D>;

//         let num_rows = 1 << 5;
//         let stark = S::new(num_rows);
//         test_stark_circuit_constraints::<F, C, S, D>(stark)
//     }

//     #[test]
//     fn test_recursive_stark_verifier() -> Result<()> {
//         init_logger();
//         const D: usize = 2;
//         type C = PoseidonGoldilocksConfig;
//         type F = <C as GenericConfig<D>>::F;
//         type S = PreBlockStark<F, D>;

//         let config = StarkConfig::standard_fast_config();
//         let num_rows = 1 << 5;
//         let public_inputs = [F::ZERO, F::ONE, fibonacci(num_rows - 1, F::ZERO, F::ONE)];

//         // Test first STARK
//         let stark = S::new(num_rows);
//         let trace = stark.generate_trace(public_inputs[0], public_inputs[1]);
//         let proof = prove::<F, C, S, D>(
//             stark,
//             &config,
//             trace,
//             &public_inputs,
//             &mut TimingTree::default(),
//         )?;
//         verify_stark_proof(stark, proof.clone(), &config)?;

//         recursive_proof::<F, C, S, C, D>(stark, proof, &config, true)
//     }

//     fn recursive_proof<
//         F: RichField + Extendable<D>,
//         C: GenericConfig<D, F = F>,
//         S: Stark<F, D> + Copy,
//         InnerC: GenericConfig<D, F = F>,
//         const D: usize,
//     >(
//         stark: S,
//         inner_proof: StarkProofWithPublicInputs<F, InnerC, D>,
//         inner_config: &StarkConfig,
//         print_gate_counts: bool,
//     ) -> Result<()>
//     where
//         InnerC::Hasher: AlgebraicHasher<F>,
//     {
//         let circuit_config = CircuitConfig::standard_recursion_config();
//         let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
//         let mut pw = PartialWitness::new();
//         let degree_bits = inner_proof.proof.recover_degree_bits(inner_config);
//         let pt =
//             add_virtual_stark_proof_with_pis(&mut builder, &stark, inner_config, degree_bits, 0, 0);
//         set_stark_proof_with_pis_target(&mut pw, &pt, &inner_proof, builder.zero());

//         verify_stark_proof_circuit::<F, InnerC, S, D>(&mut builder, stark, pt, inner_config);

//         if print_gate_counts {
//             builder.print_gate_counts(0);
//         }

//         let data = builder.build::<C>();
//         let proof = data.prove(pw)?;
//         data.verify(proof)
//     }

//     fn init_logger() {
//         let _ = env_logger::builder().format_timestamp(None).try_init();
//     }
// }
