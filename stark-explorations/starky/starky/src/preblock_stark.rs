use std::marker::PhantomData;

use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::permutation::PermutationPair;
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};

/// Toy STARK system used for testing.
///
/// - Integer division
///
#[derive(Copy, Clone)]
struct PreBlockStark<F: RichField + Extendable<D>, const D: usize> {
    floor_div_rows: usize,
    cmp_rows: usize,
    asserted_cmp_rows: usize,
    is_negative_rows: usize,
    _phantom: PhantomData<F>,
}

///////////
/////////// TRACE GENERATION
///////////
impl<F: RichField + Extendable<D>, const D: usize> PreBlockStark<F, D> {
    ///////////
    ///////////  PUBLIC INPUTS
    ///////////

    ///////////
    ///////////  CONSTANTS
    ///////////

    fn new(
        floor_div_rows: usize,
        cmp_rows: usize,
        asserted_cmp_rows: usize,
        is_negative_rows: usize,
    ) -> Self {
        Self {
            floor_div_rows,
            cmp_rows,
            asserted_cmp_rows,
            is_negative_rows,
            _phantom: PhantomData,
        }
    }

    /// No initial public inputs.
    /// Integer division. For now, let's work with 64 bit Goldilocks numbers only
    fn generate_trace(&self) -> Vec<PolynomialValues<F>> {
        let x: F = F::from_canonical_usize(15); // p-1
        let y: F = F::from_canonical_usize(3); // p-1

        // x, y, y_inv, x * y_inv
        let mut trace_rows = (0..self.floor_div_rows)
            .scan([x, y, F::ZERO, F::ZERO], |next_row, _| {
                let current_row = *next_row;

                next_row[0] = x;
                next_row[1] = y;
                next_row[2] = F::from_canonical_u64((x / y).to_canonical_u64());

                println!("{:?}", next_row);
                println!("{:?}", current_row);

                println!("----------------");
                println!("----------------");
                println!("----------------");

                Some(current_row)
            })
            .collect::<Vec<_>>();

        // // print trace_rows row by row
        // println!("trace_rows:");
        // for row in trace_rows.iter() {
        //     println!("{:?}", row);
        // }

        // trace_rows[self.floor_div_rows - 1][3] = F::ZERO; // So that column 2 and 3 are permutation of one another.

        trace_rows_to_poly_values(trace_rows)
    }
}

///////////
/////////// eval_packed_generic, eval_ext_circuit (recursive)
///////////
impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for PreBlockStark<F, D> {
    const COLUMNS: usize = 4;
    const PUBLIC_INPUTS: usize = 0;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        println!();
        println!("eval_packed_generic");
        println!();

        println!("{:?}", vars.local_values[0]);
        println!("{:?}", vars.local_values[1]);
        println!("{:?}", vars.local_values[2]);

        // println!(
        //     "{:?}",
        //     FE::from_arr((vars.local_values[1] * vars.local_values[2]).as_arr())
        // );

        // println!(
        //     "{:?}",
        //     FE::from_canonical_u64(vars.local_values[1])
        //         * FE::from_canonical_u64(vars.local_values[2])
        // );
        // println!("{:?}", P::ONES);

        println!();
        println!("{:?}", vars.local_values[1] * vars.local_values[2]);

        // x, y, y_inv, x * y_inv
        // yield_constr.constraint_first_row(
        //     vars.local_values[0] - vars.local_values[1] * vars.local_values[2],
        // );

        yield_constr.constraint_first_row(
            vars.local_values[0] - vars.local_values[1] * vars.local_values[2],
        );

        // No transition constraints for now
        // // x0' <- x1
        // yield_constr.constraint_transition(vars.next_values[0] - vars.local_values[1]);
        // // x1' <- x0 + x1
        // yield_constr.constraint_transition(
        //     vars.next_values[1] - vars.local_values[0] - vars.local_values[1],
        // );
    }

    ///////////
    /////////// Only for recursion
    ///////////
    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        println!("qwepıwqopıreqwopıropewır");

        // X * Y = Z
        let constraint = {
            let tmp = builder.mul_extension(vars.local_values[0], vars.local_values[1]);

            builder.sub_extension(tmp, vars.local_values[2])
        };
        yield_constr.constraint_first_row(builder, constraint);

        // // Check public inputs.
        // yield_constr.constraint_first_row(
        //     builder,
        //     builder.sub_extension(vars.local_values[0], vars.public_inputs[Self::PI_INDEX_X0]),
        // );
        // yield_constr.constraint_first_row(
        //     builder,
        //     builder.sub_extension(vars.local_values[1], vars.public_inputs[Self::PI_INDEX_X1]),
        // );
        // yield_constr.constraint_last_row(
        //     builder,
        //     builder.sub_extension(vars.local_values[1], vars.public_inputs[Self::PI_INDEX_RES]),
        // );

        // No transition constraints
        // // x0' <- x1
        // let first_col_constraint = builder.sub_extension(vars.next_values[0], vars.local_values[1]);
        // yield_constr.constraint_transition(builder, first_col_constraint);
        // // x1' <- x0 + x1
        // let second_col_constraint = {
        //     let tmp = builder.sub_extension(vars.next_values[1], vars.local_values[0]);
        //     builder.sub_extension(tmp, vars.local_values[1])
        // };
        // yield_constr.constraint_transition(builder, second_col_constraint);
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type S = PreBlockStark<F, D>;

    use anyhow::Result;
    use plonky2::field::extension::Extendable;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::goldilocks_field::*;
    use plonky2::field::types::{Field, Field64, PrimeField64};
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{
        AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig,
    };
    use plonky2::util::timing::TimingTree;

    use crate::config::StarkConfig;
    use crate::preblock_stark::PreBlockStark;
    use crate::proof::StarkProofWithPublicInputs;
    use crate::prover::prove;
    use crate::recursive_verifier::{
        add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target,
        verify_stark_proof_circuit,
    };
    use crate::stark::Stark;
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use crate::verifier::verify_stark_proof;

    fn preblock<F: Field>(n: usize, x0: F, x1: F) -> F {
        (0..n).fold((x0, x1), |x, _| (x.1, x.0 + x.1)).1
    }

    #[test]
    fn test_preblock_stark_overall() -> Result<()> {
        let x = F::from_canonical_usize(15); // p - 1
        let y = F::from_canonical_usize(3); // random

        let config = StarkConfig::standard_fast_config();
        let floor_div_rows = 1 << 4;

        let stark = S::new(floor_div_rows, 0, 0, 0);
        let trace = stark.generate_trace();

        let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut TimingTree::default())?;

        verify_stark_proof(stark, proof, &config)
    }

    #[test]
    fn test_preblock_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PreBlockStark<F, D>;

        let floor_div_rows = 1 << 5;
        let stark = S::new(floor_div_rows, 0, 0, 0);
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_preblock_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PreBlockStark<F, D>;

        let floor_div_rows = 1 << 5;
        let stark = S::new(floor_div_rows, 0, 0, 0);
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    // #[test]
    // fn test_recursive_preblock_stark_verifier() -> Result<()> {
    //     init_logger();
    //     const D: usize = 2;
    //     type C = PoseidonGoldilocksConfig;
    //     type F = <C as GenericConfig<D>>::F;
    //     type S = PreBlockStark<F, D>;

    //     let config = StarkConfig::standard_fast_config();
    //     let floor_div_rows = 1 << 5;
    // let stark = S::new(floor_div_rows, 0, 0, 0);
    //     let trace = stark.generate_trace();
    //     let proof = prove::<F, C, S, D>(stark, &config, trace, [], &mut TimingTree::default())?;
    //     verify_stark_proof(stark, proof.clone(), &config)?;

    //     recursive_preblock_proof::<F, C, S, C, D>(stark, proof, &config, true)
    // }

    fn recursive_preblock_proof<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        S: Stark<F, D> + Copy,
        InnerC: GenericConfig<D, F = F>,
        const D: usize,
    >(
        stark: S,
        inner_proof: StarkProofWithPublicInputs<F, InnerC, D>,
        inner_config: &StarkConfig,
        print_gate_counts: bool,
    ) -> Result<()>
    where
        InnerC::Hasher: AlgebraicHasher<F>,
        [(); S::COLUMNS]:,
        [(); S::PUBLIC_INPUTS]:,
        [(); C::Hasher::HASH_SIZE]:,
    {
        let circuit_config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
        let mut pw = PartialWitness::new();
        let degree_bits = inner_proof.proof.recover_degree_bits(inner_config);
        let pt = add_virtual_stark_proof_with_pis(&mut builder, stark, inner_config, degree_bits);
        set_stark_proof_with_pis_target(&mut pw, &pt, &inner_proof);

        verify_stark_proof_circuit::<F, InnerC, S, D>(&mut builder, stark, pt, inner_config);

        if print_gate_counts {
            builder.print_gate_counts(0);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    fn init_logger() {
        let _ = env_logger::builder().format_timestamp(None).try_init();
    }
}
