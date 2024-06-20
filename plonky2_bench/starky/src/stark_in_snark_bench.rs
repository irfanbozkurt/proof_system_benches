use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::evaluation_frame::{StarkEvaluationFrame, StarkFrame};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Toy STARK system used for testing.
/// Computes a Fibonacci sequence with state `[x0, x1]` using the state transition
/// `x0' <- x1, x1' <- x0 + x1.
#[derive(Copy, Clone)]
struct FibonacciStark<F: RichField + Extendable<D>, const D: usize> {
    num_rows: usize,
    _phantom: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> FibonacciStark<F, D> {
    // The first public input is `x0`.
    const PI_INDEX_X0: usize = 0;
    // The second public input is `x1`.
    const PI_INDEX_X1: usize = 1;
    // The third public input is the second element of the last row, which should be equal to the
    // `num_rows`-th Fibonacci number.
    const PI_INDEX_RES: usize = 2;

    const fn new(num_rows: usize) -> Self {
        Self {
            num_rows,
            _phantom: PhantomData,
        }
    }

    /// Generate the trace using `x0, x1` as initial state values.
    fn generate_trace(&self, x0: F, x1: F) -> Vec<PolynomialValues<F>> {
        let trace_rows = (0..self.num_rows)
            .scan([x0, x1], |acc, _| {
                let tmp = *acc;
                acc[0] = tmp[1];
                acc[1] = tmp[0] + tmp[1];
                Some(tmp)
            })
            .collect::<Vec<_>>();
        trace_rows_to_poly_values(trace_rows)
    }
}

const FIBONACCI_COLUMNS: usize = 2;
const FIBONACCI_PUBLIC_INPUTS: usize = 3;

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for FibonacciStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, P::Scalar, FIBONACCI_COLUMNS, FIBONACCI_PUBLIC_INPUTS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    type EvaluationFrameTarget = StarkFrame<
        ExtensionTarget<D>,
        ExtensionTarget<D>,
        FIBONACCI_COLUMNS,
        FIBONACCI_PUBLIC_INPUTS,
    >;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values = vars.get_local_values();
        let next_values = vars.get_next_values();
        let public_inputs = vars.get_public_inputs();

        // Check public inputs.
        yield_constr.constraint_first_row(local_values[0] - public_inputs[Self::PI_INDEX_X0]);
        yield_constr.constraint_first_row(local_values[1] - public_inputs[Self::PI_INDEX_X1]);
        yield_constr.constraint_last_row(local_values[1] - public_inputs[Self::PI_INDEX_RES]);

        // x0' <- x1
        yield_constr.constraint_transition(next_values[0] - local_values[1]);
        // x1' <- x0 + x1
        yield_constr.constraint_transition(next_values[1] - local_values[0] - local_values[1]);
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
            builder.sub_extension(local_values[0], public_inputs[Self::PI_INDEX_X0]),
            builder.sub_extension(local_values[1], public_inputs[Self::PI_INDEX_X1]),
            builder.sub_extension(local_values[1], public_inputs[Self::PI_INDEX_RES]),
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

#[cfg(test)]
mod tests {
    use crate::config::StarkConfig;
    use crate::proof::StarkProofWithPublicInputs;
    use crate::prover::prove;
    use crate::recursive_verifier::{
        add_virtual_stark_proof_with_pis, set_stark_proof_with_pis_target,
        verify_stark_proof_circuit,
    };
    use crate::stark::Stark;
    use crate::stark_in_snark_bench::FibonacciStark;
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};
    use crate::verifier::verify_stark_proof;
    use anyhow::Result;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use plonky2_maybe_rayon::rayon::iter::IntoParallelIterator;
    use plonky2_maybe_rayon::rayon::iter::IntoParallelRefIterator;
    use plonky2_maybe_rayon::ParallelIterator;
    use std::time::Instant;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type S = FibonacciStark<F, D>;

    pub fn fibonacci<F: Field>(n: usize, x0: F, x1: F) -> F {
        (0..n).fold((x0, x1), |x, _| (x.1, x.0 + x.1)).1
    }

    fn fibo_snark(num_rows: usize, repetition: usize) -> (CircuitBuilder<F, D>, PartialWitness<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // The arithmetic circuit.
        let initial_a = builder.add_virtual_target();
        let initial_b = builder.add_virtual_target();
        builder.register_public_input(initial_a);
        builder.register_public_input(initial_b);

        let mut prev_target = initial_a;
        let mut cur_target = initial_b;
        for _ in 0..num_rows - 1 {
            let temp = builder.add(prev_target, cur_target);
            prev_target = cur_target;
            cur_target = temp;
        }

        for _ in 0..(repetition - 1) {
            let mut prev_target = builder.add_virtual_target();
            let mut cur_target = builder.add_virtual_target();
            for _ in 0..num_rows - 1 {
                let temp = builder.add(prev_target, cur_target);
                prev_target = cur_target;
                cur_target = temp;
            }
        }

        builder.register_public_input(cur_target);

        let mut pw = PartialWitness::new();
        pw.set_target(initial_a, F::ZERO);
        pw.set_target(initial_b, F::ONE);

        (builder, pw)
    }

    #[test]
    fn test_recursive_stark_verifier_fibonacci() -> Result<()> {
        let repetition = 1 << 0;
        let num_rows = 1 << 18;
        let config = StarkConfig::standard_fast_config();

        let public_inputs = [
            F::ZERO,
            F::ONE,
            fibonacci(num_rows * repetition - 1, F::ZERO, F::ONE),
        ];

        // Pure STARK
        let stark = S::new(num_rows * repetition);
        let start_time = Instant::now();
        let proof = prove::<F, C, S, D>(
            stark,
            &config,
            stark.generate_trace(public_inputs[0], public_inputs[1]),
            &public_inputs,
            &mut TimingTree::default(),
        )?;
        println!(
            "STARK proving time (including witness generation): {:?}",
            start_time.elapsed()
        );

        let start_time = Instant::now();
        verify_stark_proof(stark, proof.clone(), &config)?;
        println!("STARK verification time: {:?}", start_time.elapsed());

        println!();
        println!("------------------------------");
        println!();

        // Pure SNARK
        let start_time = Instant::now();
        let (builder, pw) = fibo_snark(num_rows, repetition);
        let data = builder.build::<C>();
        println!(
            "pure_snark witness generation time: {:?}",
            start_time.elapsed()
        );
        let start_time = Instant::now();
        match data.prove(pw) {
            Ok(proof) => {
                println!("pure_snark proving time: {:?}", start_time.elapsed());

                let start_time = Instant::now();
                match data.verify(proof) {
                    Ok(_) => println!("pure_snark verifying time: {:?}", start_time.elapsed()),
                    Err(e) => println!("Verification failed: {:?}", e),
                }
            }
            Err(e) => println!("Proving failed: {:?}", e),
        }

        println!();
        println!("------------------------------");
        println!();

        // Recursive with STARK
        let stark = S::new(num_rows);
        // Parallelize the creation of proofs
        let public_inputs = [F::ZERO, F::ONE, fibonacci(num_rows - 1, F::ZERO, F::ONE)];
        let start_time = Instant::now();
        let inner_proofs: Vec<_> = (0..repetition)
            .into_par_iter()
            .map(|_| {
                prove::<F, C, S, D>(
                    stark,
                    &config,
                    stark.generate_trace(public_inputs[0], public_inputs[1]),
                    &public_inputs,
                    &mut TimingTree::default(),
                )
                .expect("Failed to prove")
            })
            .collect();
        println!(
            "stark_in_snark inner STARK proving time (sequential here but is parallelizable): {:?}",
            start_time.elapsed()
        );

        // Initialize the mother SNARK circuit
        let circuit_config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);

        // Verify STARKs in SNARK
        let start_time = Instant::now();
        let mut pw = PartialWitness::new();
        inner_proofs.iter().for_each(|inner_proof| {
            let stark_proof_with_pis_target = add_virtual_stark_proof_with_pis(
                &mut builder,
                &stark,
                &config,
                inner_proof.proof.recover_degree_bits(&config),
                0,
                0,
            );

            set_stark_proof_with_pis_target(
                &mut pw,
                &stark_proof_with_pis_target,
                &inner_proof,
                builder.zero(),
            );

            verify_stark_proof_circuit::<F, C, S, D>(
                &mut builder,
                stark,
                stark_proof_with_pis_target,
                &config,
            );
        });
        let data = builder.build::<C>();
        let time_spent_verifying_inner_starks = start_time.elapsed();
        println!(
            "stark_in_snark mother SNARK witness generation time (verifying inner STARK): {:?}",
            time_spent_verifying_inner_starks
        );

        let start_time = Instant::now();
        let proof = data.prove(pw)?;
        let time_spent_proving = start_time.elapsed();
        println!(
            "stark_in_snark mother SNARK proving time (verifying inner STARK): {:?}",
            time_spent_proving
        );

        let start_time = Instant::now();
        data.verify(proof);
        println!(
            "stark_in_snark mother SNARK verification time (verifying inner STARK): {:?}",
            start_time.elapsed()
        );
        Ok(())
    }

    fn recursive_proof<
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
    {
        let circuit_config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(circuit_config);
        let mut pw = PartialWitness::new();
        let degree_bits = inner_proof.proof.recover_degree_bits(inner_config);
        let pt =
            add_virtual_stark_proof_with_pis(&mut builder, &stark, inner_config, degree_bits, 0, 0);
        set_stark_proof_with_pis_target(&mut pw, &pt, &inner_proof, builder.zero());

        verify_stark_proof_circuit::<F, InnerC, S, D>(&mut builder, stark, pt, inner_config);

        if print_gate_counts {
            builder.print_gate_counts(0);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }
}
