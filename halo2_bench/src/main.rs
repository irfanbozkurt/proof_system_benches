#[cfg(feature = "unstable")]
use halo2_gadgets::sha256::{BlockWord, Sha256, Table16Chip, Table16Config, BLOCK_SIZE};
use halo2_gadgets::{sinsemilla, utilities::lookup_range_check::LookupRangeCheckConfig};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::*,
    pasta::{group::ff::PrimeFieldBits, pallas},
    plonk::*,
    poly::Rotation,
};

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
/// Verify Block
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

// The top-level config that provides all necessary columns and permutations
// for the other configs.
#[derive(Clone, Debug)]
struct FiboConfig {
    // Columns through which we communicate with other parts of the circuit.
    pub advice: [Column<Advice>; 10],
    // pub selector: Selector,
    // Use a 10-bit lookup table
    pub lookup_config: LookupRangeCheckConfig<pallas::Base, 10>,

    #[cfg(feature = "unstable")]
    pub sha_config: Table16Config,
}

// Not implementing the 'Circuit' trait here as we won't be passing the chip
// to the prover.
struct FiboChip<F: PrimeFieldBits + FieldExt> {
    config: FiboConfig,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeFieldBits + FieldExt> FiboChip<F> {
    // Constructs this chip from given config.
    fn construct(config: FiboConfig) -> Self {
        Self {
            config,
            _marker: std::marker::PhantomData,
        }
    }

    // Compose your circuit as a custom gate / chip here.
    fn configure(meta: &mut ConstraintSystem<F>) -> FiboConfig {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Selector column, if you will
        // let selector = meta.selector();

        // We'll have a gate to enforce a + b = c, but that's not enough. We'll also have
        // to enforce some permutation checks between the rows. For that, we'll need to
        // enable equality checks for the columns.
        //
        // If you forget this, you won't be able to use permutation arguments for this column.
        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_equality(advice[2]);

        // Define your custom gate.
        // This gate will only constrain one row, but a gate can also have multiple rows.
        // You can query columns at different rows with Rotation::next(), or Rotation(i32)
        // But keep in mind it has to be relative to the current row.
        meta.create_gate("add", |meta| {
            // An "expression" is a cell within a custom gate.

            // col[0]  |  col[0]  |  col[0]  |  selector
            //   a     |    b     |    c     |    s
            //         |          |          |
            // let s: Expression<F> = meta.query_selector(selector);
            let a: Expression<F> = meta.query_advice(advice[0], Rotation::cur());
            let b: Expression<F> = meta.query_advice(advice[1], Rotation::cur());
            let c: Expression<F> = meta.query_advice(advice[2], Rotation::cur());

            // Return the constraint"s" for the custom gate
            // when s = 1, this gate will be enabled.
            vec![(a + b - c)]
        });

        let lookup = [
            meta.lookup_table_column(),
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        ];

        // Fixed columns for the Sinsemilla generator lookup table
        //////////////////////////////////////////////////////////////////////////

        FiboConfig {
            advice,
            // selector,
            #[cfg(feature = "unstable")]
            sha_config: Table16Chip::configure(meta),
            lookup_config: LookupRangeCheckConfig::<F, 10>::configure(meta, advice[9], lookup),
        }
    }
}

// Derife the Default macro so that you can call the default() method in "without_witnesses"
#[derive(Default)]
struct FiboCircuit<F> {
    pub a: Option<F>,
    pub b: Option<F>,
}

impl<F: PrimeFieldBits + FieldExt> Circuit<F> for FiboCircuit<F> {
    type Config = FiboConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        FiboChip::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        todo!()
    }
}

fn main() {
    println!("Hello, world!");
}
