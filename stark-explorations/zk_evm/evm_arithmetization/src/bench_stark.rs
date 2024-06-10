use core::ops::Deref;
use std::time::Duration;

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::FriConfig;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::KeccakGoldilocksConfig;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use starky::config::StarkConfig;
use starky::cross_table_lookup::{CrossTableLookup, TableIdx, TableWithColumns};
use starky::evaluation_frame::StarkFrame;
use starky::stark::Stark;

use crate::arithmetic::arithmetic_stark;
use crate::arithmetic::arithmetic_stark::ArithmeticStark;
use crate::byte_packing::byte_packing_stark::{self, BytePackingStark};
use crate::cpu::cpu_stark;
use crate::cpu::cpu_stark::CpuStark;
use crate::cpu::membus::NUM_GP_CHANNELS;
use crate::keccak::keccak_stark;
use crate::keccak::keccak_stark::KeccakStark;
use crate::keccak_sponge::columns::KECCAK_RATE_BYTES;
use crate::keccak_sponge::keccak_sponge_stark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::logic;
use crate::logic::LogicStark;
use crate::memory::memory_stark;
use crate::memory::memory_stark::MemoryStark;
use crate::prover::prove_bench;
use crate::verifier::verify_bench_proof;
use crate::witness::traces::Traces;

//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

/// Structure containing all STARKs and the cross-table lookups.
#[derive(Clone)]
pub struct BenchStark<F: RichField + Extendable<D>, const D: usize> {
    pub(crate) arithmetic_stark: ArithmeticStark<F, D>,
    pub(crate) keccak_stark: KeccakStark<F, D>,
    pub(crate) keccak_sponge_stark: KeccakSpongeStark<F, D>,
    pub(crate) logic_stark: LogicStark<F, D>,
    pub(crate) cross_table_lookups: Vec<CrossTableLookup<F>>,
}

impl<F: RichField + Extendable<D>, const D: usize> Default for BenchStark<F, D> {
    /// Returns an `BenchStark` containing all the STARKs initialized with default
    /// values.
    fn default() -> Self {
        Self {
            arithmetic_stark: ArithmeticStark::default(),
            keccak_stark: KeccakStark::default(),
            keccak_sponge_stark: KeccakSpongeStark::default(),
            logic_stark: LogicStark::default(),
            cross_table_lookups: all_cross_table_lookups(),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> BenchStark<F, D> {
    pub(crate) fn num_lookups_helper_columns(
        &self,
        config: &StarkConfig,
    ) -> [usize; BENCH_NUM_TABLES] {
        [
            self.arithmetic_stark.num_lookup_helper_columns(config),
            self.keccak_stark.num_lookup_helper_columns(config),
            self.keccak_sponge_stark.num_lookup_helper_columns(config),
            self.logic_stark.num_lookup_helper_columns(config),
        ]
    }
}

pub type EvmStarkFrame<T, U, const N: usize> = StarkFrame<T, U, N, 0>;

/// Associates STARK tables with a unique index.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum BenchTable {
    Arithmetic = 0,
    Keccak = 1,
    KeccakSponge = 2,
    Logic = 3,
}

impl Deref for BenchTable {
    type Target = TableIdx;

    fn deref(&self) -> &Self::Target {
        // Hacky way to implement `Deref` for `Table` so that we don't have to
        // call `Table::Foo as usize`, but perhaps too ugly to be worth it.
        [&0, &1, &2, &3][*self as TableIdx]
    }
}

/// Number of STARK tables.
pub(crate) const BENCH_NUM_TABLES: usize = BenchTable::Logic as usize + 1;

impl BenchTable {
    /// Returns all STARK table indices.
    pub(crate) const fn all() -> [Self; BENCH_NUM_TABLES] {
        [
            Self::Arithmetic,
            Self::Keccak,
            Self::KeccakSponge,
            Self::Logic,
        ]
    }
}

/// Returns all the `CrossTableLookups` used for proving the EVM.
pub(crate) fn all_cross_table_lookups<F: Field>() -> Vec<CrossTableLookup<F>> {
    vec![
        ctl_arithmetic(),
        ctl_keccak_inputs(),
        ctl_keccak_outputs(),
        ctl_logic(),
    ]
}

/// `CrossTableLookup` for `ArithmeticStark`, to connect it with the `Cpu`
/// module.
fn ctl_arithmetic<F: Field>() -> CrossTableLookup<F> {
    CrossTableLookup::new(
        vec![cpu_stark::ctl_arithmetic_base_rows()],
        arithmetic_stark::ctl_arithmetic_rows(),
    )
}

/// `CrossTableLookup` for `KeccakStark` inputs, to connect it with the
/// `KeccakSponge` module. `KeccakStarkSponge` looks into `KeccakStark` to give
/// the inputs of the sponge. Its consistency with the 'output' CTL is ensured
/// through a timestamp column on the `KeccakStark` side.
fn ctl_keccak_inputs<F: Field>() -> CrossTableLookup<F> {
    let keccak_sponge_looking = TableWithColumns::new(
        *BenchTable::KeccakSponge,
        keccak_sponge_stark::ctl_looking_keccak_inputs(),
        keccak_sponge_stark::ctl_looking_keccak_filter(),
    );
    let keccak_looked = TableWithColumns::new(
        *BenchTable::Keccak,
        keccak_stark::ctl_data_inputs(),
        keccak_stark::ctl_filter_inputs(),
    );
    CrossTableLookup::new(vec![keccak_sponge_looking], keccak_looked)
}

/// `CrossTableLookup` for `KeccakStark` outputs, to connect it with the
/// `KeccakSponge` module. `KeccakStarkSponge` looks into `KeccakStark` to give
/// the outputs of the sponge.
fn ctl_keccak_outputs<F: Field>() -> CrossTableLookup<F> {
    let keccak_sponge_looking = TableWithColumns::new(
        *BenchTable::KeccakSponge,
        keccak_sponge_stark::ctl_looking_keccak_outputs(),
        keccak_sponge_stark::ctl_looking_keccak_filter(),
    );
    let keccak_looked = TableWithColumns::new(
        *BenchTable::Keccak,
        keccak_stark::ctl_data_outputs(),
        keccak_stark::ctl_filter_outputs(),
    );
    CrossTableLookup::new(vec![keccak_sponge_looking], keccak_looked)
}

/// `CrossTableLookup` for `LogicStark` to connect it with the `Cpu` and
/// `KeccakSponge` modules.
fn ctl_logic<F: Field>() -> CrossTableLookup<F> {
    let mut all_lookers = vec![];
    for i in 0..keccak_sponge_stark::num_logic_ctls() {
        let keccak_sponge_looking = TableWithColumns::new(
            *BenchTable::KeccakSponge,
            keccak_sponge_stark::ctl_looking_logic(i),
            keccak_sponge_stark::ctl_looking_logic_filter(),
        );
        all_lookers.push(keccak_sponge_looking);
    }
    let logic_looked =
        TableWithColumns::new(*BenchTable::Logic, logic::ctl_data(), logic::ctl_filter());
    CrossTableLookup::new(all_lookers, logic_looked)
}

//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

pub(crate) struct BenchState<F: Field> {
    pub(crate) traces: Traces<F>,
    pub(crate) bignum_modmul_result_limbs: Vec<F>,
}

impl<F: Field> BenchState<F> {
    pub(crate) fn new() -> Self {
        Self {
            traces: Traces::default(),
            bignum_modmul_result_limbs: vec![],
        }
    }
}

pub fn generate_bench_traces<F: RichField + Extendable<D>, const D: usize>(
    bench_stark: &BenchStark<F, D>,
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> anyhow::Result<([Vec<PolynomialValues<F>>; BENCH_NUM_TABLES])> {
    let mut state = BenchState::<F>::new();

    log::info!(
        "Trace lengths (before padding): {:?}",
        state.traces.get_lengths()
    );

    let tables = timed!(
        timing,
        "convert trace data to tables",
        state.traces.bench_into_tables(bench_stark, config, timing)
    );

    Ok(tables)
}

//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

type F = GoldilocksField;
const D: usize = 2;
type C = KeccakGoldilocksConfig;

#[test]
fn test_bench_stark() -> anyhow::Result<()> {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));

    let bench = BenchStark::<F, D>::default();
    let config = StarkConfig {
        security_bits: 100,
        num_challenges: 2,
        fri_config: FriConfig {
            rate_bits: 1,
            cap_height: 4,
            proof_of_work_bits: 16,
            reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
            num_query_rounds: 84,
        },
    };

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let proof = prove_bench::<F, C, D>(&bench, &config, &mut timing, None)?;
    timing.filter(Duration::from_millis(100)).print();

    verify_bench_proof(&bench, proof, &config)
}
