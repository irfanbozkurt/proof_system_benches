use ethereum_types::U256;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use starky::config::StarkConfig;
use starky::util::trace_rows_to_poly_values;

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::arithmetic::{BinaryOperator, Operation};
use crate::bench_stark::{BenchStark, BENCH_NUM_TABLES};
use crate::byte_packing::byte_packing_stark::BytePackingOp;
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::membus::NUM_CHANNELS;
use crate::keccak_sponge::keccak_sponge_stark::{self, KeccakSpongeOp};
use crate::logic::Op;
use crate::memory::segments::Segment;
use crate::witness::memory::{MemoryAddress, MemoryOp};
use crate::{arithmetic, keccak, keccak_sponge, logic};

use crate::arithmetic::*;
use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use starky::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

use core::marker::PhantomData;
use core::ops::Range;

use plonky2::field::packed::PackedField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::util::transpose;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::cross_table_lookup::TableWithColumns;
use starky::evaluation_frame::StarkEvaluationFrame;
use starky::lookup::{Column, Filter, Lookup};
use starky::stark::Stark;
use static_assertions::const_assert;

use crate::all_stark::{EvmStarkFrame, Table};
use crate::arithmetic::columns::{NUM_SHARED_COLS, RANGE_COUNTER, RC_FREQUENCIES, SHARED_COLS};

fn set_trace_zeroes<T: Field>(trace: &mut [PolynomialValues<T>]) {
    for poly in trace.iter_mut() {
        for value in poly.values.iter_mut() {
            *value = T::ZERO;
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TraceCheckpoint {
    pub(self) arithmetic_len: usize,
    pub(self) byte_packing_len: usize,
    pub(self) cpu_len: usize,
    pub(self) keccak_len: usize,
    pub(self) keccak_sponge_len: usize,
    pub(self) logic_len: usize,
    pub(self) memory_len: usize,
}

#[derive(Debug)]
pub(crate) struct Traces<T: Copy> {
    pub(crate) arithmetic_ops: Vec<arithmetic::Operation>,
    pub(crate) byte_packing_ops: Vec<BytePackingOp>,
    pub(crate) cpu: Vec<CpuColumnsView<T>>,
    pub(crate) logic_ops: Vec<logic::Operation>,
    pub(crate) memory_ops: Vec<MemoryOp>,
    pub(crate) keccak_inputs: Vec<([u64; keccak::keccak_stark::NUM_INPUTS], usize)>,
    pub(crate) keccak_sponge_ops: Vec<KeccakSpongeOp>,
}

impl<T: Copy> Traces<T> {
    pub(crate) fn new() -> Self {
        Traces {
            arithmetic_ops: vec![],
            byte_packing_ops: vec![],
            cpu: vec![],
            logic_ops: vec![],
            memory_ops: vec![],
            keccak_inputs: vec![],
            keccak_sponge_ops: vec![],
        }
    }

    /// Returns the actual trace lengths for each STARK module.
    //  Uses a `TraceCheckPoint` as return object for convenience.
    pub(crate) fn get_lengths(&self) -> TraceCheckpoint {
        TraceCheckpoint {
            arithmetic_len: self
                .arithmetic_ops
                .iter()
                .map(|op| match op {
                    Operation::TernaryOperation { .. } => 2,
                    Operation::BinaryOperation { operator, .. } => match operator {
                        BinaryOperator::Div | BinaryOperator::Mod => 2,
                        _ => 1,
                    },
                    Operation::RangeCheckOperation { .. } => 1,
                })
                .sum(),
            byte_packing_len: self
                .byte_packing_ops
                .iter()
                .map(|op| usize::from(!op.bytes.is_empty()))
                .sum(),
            cpu_len: self.cpu.len(),
            keccak_len: self.keccak_inputs.len() * keccak::keccak_stark::NUM_ROUNDS,
            keccak_sponge_len: self
                .keccak_sponge_ops
                .iter()
                .map(|op| op.input.len() / keccak_sponge::columns::KECCAK_RATE_BYTES + 1)
                .sum(),
            logic_len: self.logic_ops.len(),
            // This is technically a lower-bound, as we may fill gaps,
            // but this gives a relatively good estimate.
            memory_len: self.memory_ops.len(),
        }
    }

    /// Returns the number of operations for each STARK module.
    pub(crate) fn checkpoint(&self) -> TraceCheckpoint {
        TraceCheckpoint {
            arithmetic_len: self.arithmetic_ops.len(),
            byte_packing_len: self.byte_packing_ops.len(),
            cpu_len: self.cpu.len(),
            keccak_len: self.keccak_inputs.len(),
            keccak_sponge_len: self.keccak_sponge_ops.len(),
            logic_len: self.logic_ops.len(),
            memory_len: self.memory_ops.len(),
        }
    }

    pub(crate) fn rollback(&mut self, checkpoint: TraceCheckpoint) {
        self.arithmetic_ops.truncate(checkpoint.arithmetic_len);
        self.byte_packing_ops.truncate(checkpoint.byte_packing_len);
        self.cpu.truncate(checkpoint.cpu_len);
        self.keccak_inputs.truncate(checkpoint.keccak_len);
        self.keccak_sponge_ops
            .truncate(checkpoint.keccak_sponge_len);
        self.logic_ops.truncate(checkpoint.logic_len);
        self.memory_ops.truncate(checkpoint.memory_len);
    }

    pub(crate) fn mem_ops_since(&self, checkpoint: TraceCheckpoint) -> &[MemoryOp] {
        &self.memory_ops[checkpoint.memory_len..]
    }

    pub(crate) fn clock(&self) -> usize {
        self.cpu.len()
    }

    pub(crate) fn into_tables<const D: usize>(
        self,
        all_stark: &AllStark<T, D>,
        config: &StarkConfig,
        timing: &mut TimingTree,
    ) -> [Vec<PolynomialValues<T>>; NUM_TABLES]
    where
        T: RichField + Extendable<D>,
    {
        let cap_elements = config.fri_config.num_cap_elements();
        let Traces {
            mut arithmetic_ops,
            byte_packing_ops,
            cpu,
            logic_ops,
            memory_ops,
            keccak_inputs,
            keccak_sponge_ops,
        } = self;

        // // change last 250 operations
        // arithmetic_ops
        //     .iter_mut()
        //     .rev()
        //     .take(250)
        //     .map(|_| {
        //         arithmetic::Operation::binary(
        //             BinaryOperator::Mul,
        //             U256::from(3), //rng.gen::<[u8; 32]>()),
        //             U256::from(4), //rng.gen::<[u8; 32]>()),
        //         )
        //     })
        //     .collect::<Vec<_>>();

        // arithmetic_ops = (0..256)
        //     .map(|_| {
        //         arithmetic::Operation::binary(
        //             BinaryOperator::Mul,
        //             U256::from(3), //rng.gen::<[u8; 32]>()),
        //             U256::from(4), //rng.gen::<[u8; 32]>()),
        //         )
        //     })
        //     .collect::<Vec<_>>();

        let mut arithmetic_trace = timed!(
            timing,
            "generate arithmetic trace",
            all_stark.arithmetic_stark.generate_trace(arithmetic_ops)
        );

        // set_trace_zeroes(&mut arithmetic_trace);

        let mut byte_packing_trace = timed!(
            timing,
            "generate byte packing trace",
            all_stark
                .byte_packing_stark
                .generate_trace(byte_packing_ops, cap_elements, timing)
        );

        // set_trace_zeroes(&mut byte_packing_trace);

        // byte_packing_trace = byte_packing_trace
        //     .iter()
        //     .map(|poly: &PolynomialValues<T>| {
        //         let values_len = poly.values.len();
        //         let mut values = vec![];
        //         values.resize(values_len, T::ZERO);
        //         PolynomialValues { values }
        //     })
        //     .collect();

        let cpu_rows = cpu.into_iter().map(|x| x.into()).collect();
        let mut cpu_trace = trace_rows_to_poly_values(cpu_rows);
        // set_trace_zeroes(&mut cpu_trace);
        let mut keccak_trace = timed!(
            timing,
            "generate Keccak trace",
            all_stark
                .keccak_stark
                .generate_trace(keccak_inputs, cap_elements, timing)
        );
        // set_trace_zeroes(&mut keccak_trace);
        let mut keccak_sponge_trace = timed!(
            timing,
            "generate Keccak sponge trace",
            all_stark
                .keccak_sponge_stark
                .generate_trace(keccak_sponge_ops, cap_elements, timing)
        );
        // set_trace_zeroes(&mut keccak_sponge_trace);
        let mut logic_trace = timed!(
            timing,
            "generate logic trace",
            all_stark
                .logic_stark
                .generate_trace(logic_ops, cap_elements, timing)
        );
        // set_trace_zeroes(&mut logic_trace);
        let mut memory_trace = timed!(
            timing,
            "generate memory trace",
            all_stark.memory_stark.generate_trace(memory_ops, timing)
        );
        // set_trace_zeroes(&mut memory_trace);

        [
            arithmetic_trace,
            byte_packing_trace,
            cpu_trace,
            keccak_trace,
            keccak_sponge_trace,
            logic_trace,
            memory_trace,
        ]
    }

    pub(crate) fn bench_into_tables<const D: usize>(
        self,
        bench_stark: &BenchStark<T, D>,
        config: &StarkConfig,
        timing: &mut TimingTree,
    ) -> [Vec<PolynomialValues<T>>; BENCH_NUM_TABLES]
    where
        T: RichField + Extendable<D>,
    {
        let cap_elements = config.fri_config.num_cap_elements();

        let mut rng = ChaCha8Rng::seed_from_u64(0x6feb51b7ec230f25);

        [
            timed!(
                timing,
                "generate arithmetic trace",
                bench_stark.arithmetic_stark.generate_trace(
                    (0..256)
                        .map(|_| {
                            arithmetic::Operation::binary(
                                BinaryOperator::Mul,
                                U256::from(3), //rng.gen::<[u8; 32]>()),
                                U256::from(4), //rng.gen::<[u8; 32]>()),
                            )
                        })
                        .collect::<Vec<_>>()
                )
            ),
            timed!(
                timing,
                "generate Keccak trace",
                bench_stark.keccak_stark.generate_trace(
                    (0..256)
                        .map(|_| {
                            (
                                [rng.gen(); keccak::keccak_stark::NUM_INPUTS],
                                rng.gen_range(0..keccak::keccak_stark::NUM_ROUNDS),
                            )
                        })
                        .collect::<Vec<_>>(),
                    cap_elements,
                    timing
                )
            ),
            timed!(
                timing,
                "generate Keccak sponge trace",
                bench_stark.keccak_sponge_stark.generate_trace(
                    (0..256)
                        .map(|_| keccak_sponge_stark::KeccakSpongeOp {
                            base_address: MemoryAddress::new(2, Segment::ContextMetadata, 3),
                            timestamp: 16,
                            input: vec![5; 16],
                        })
                        .collect::<Vec<_>>(),
                    cap_elements,
                    timing
                )
            ),
            timed!(
                timing,
                "generate logic trace",
                bench_stark.logic_stark.generate_trace(
                    (0..16)
                        .map(|_| {
                            logic::Operation::new(
                                Op::And,
                                U256::from(3), //rng.gen::<[u8; 32]>()),
                                U256::from(4), //rng.gen::<[u8; 32]>()),
                            )
                        })
                        .collect::<Vec<_>>(),
                    cap_elements,
                    timing
                )
            ),
        ]
    }
}

impl<T: Copy> Default for Traces<T> {
    fn default() -> Self {
        Self::new()
    }
}
