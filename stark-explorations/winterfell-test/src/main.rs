use winterfell::{
    crypto::{hashers::Rp64_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement as Felt, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, ByteWriter, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, ProofOptions,
    Prover, Serializable, StarkDomain, Trace, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

//////////////////////////////// Constants

// Calculating .exp(ALPHA) is doable when creating the trace, but a constraint of
// that degree will be too large for the verifier to be practical.
const DEGREE: usize = 3;
const ALPHA: u64 = 12297829379609722881;
const INV_ALPHA: u64 = 3;
const FORTY_TWO: Felt = Felt::new(42);

//////////////////////////////// Calculating function

fn vdf(seed: Felt, n: usize) -> Felt {
    let mut state = seed; // A state of just a field element
    for _ in 0..(n - 1) {
        state = (state - FORTY_TWO).exp(ALPHA);
    }
    state
}

//////////////////////////////// Public inputs

#[derive(Clone, Copy)]
struct VdfInputs {
    seed: Felt,
    result: Felt,
}

impl ToElements<Felt> for VdfInputs {
    fn to_elements(&self) -> Vec<Felt> {
        vec![self.seed, self.result]
    }
}

impl Serializable for VdfInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.seed);
        target.write(self.result);
    }
}

//////////////////////////////// AIR

struct VdfAir {
    context: AirContext<Felt>,
    pub_inputs: VdfInputs,
}

impl Air for VdfAir {
    type BaseField = Felt;
    type PublicInputs = VdfInputs;

    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Degrees of ALL constraints. Length must be equal to the number of constraints.
        let degrees: Vec<TransitionConstraintDegree> =
            vec![TransitionConstraintDegree::new(DEGREE)];
        Self {
            context: AirContext::new(trace_info, degrees, 2, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    // Evaluate the constraints in the extension field
    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _: &[E], // Periodic values
        result: &mut [E],
    ) {
        result[0] = frame.current()[0] - (frame.next()[0].exp(INV_ALPHA.into()) + FORTY_TWO.into());
        // What if we evaluated based on current_state ??
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.pub_inputs.seed),
            Assertion::single(0, last_step, self.pub_inputs.result),
        ]
    }
}

//////////////////////////////// Prover

struct VdfProver {
    options: ProofOptions,
}

impl VdfProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }

    pub fn build_trace(seed: Felt, n: usize) -> TraceTable<Felt> {
        let mut column_0 = vec![Felt::ZERO; n];

        column_0[0] = seed;
        for i in 1..n {
            column_0[i] = (column_0[i - 1] - FORTY_TWO).exp(ALPHA);
        }

        // We could have more than one columns.
        TraceTable::init(vec![column_0])
    }
}

impl Prover for VdfProver {
    type BaseField = Felt;
    type Air = VdfAir;
    // This is the default trace table provided by Winterfell, and is most of the time enough.
    // You can always extend it beyond.
    type Trace = TraceTable<Felt>;
    type HashFn = Rp64_256; // Rescue prime
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E> = DefaultTraceLde<E, Self::HashFn> where E: FieldElement<BaseField = Self::BaseField>;
    type ConstraintEvaluator<'a, E> = DefaultConstraintEvaluator<'a, Self::Air, E> where E: FieldElement<BaseField = Self::BaseField>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> <<Self as Prover>::Air as Air>::PublicInputs {
        let last_step = trace.length() - 1;
        VdfInputs {
            seed: trace.get(0, 0),
            result: trace.get(0, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>)
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Self::TraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        Self::ConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

//////////////////////////////// Prover

fn main() {
    let n = 1024 * 1024;
    let seed = Felt::new(5);

    // Calculate the result
    let result = vdf(seed, n);
    println!("Result: {}", result);

    // Initialize STARK
    let stark_params = ProofOptions::new(40, 4, 21, FieldExtension::Quadratic, 8, 63);

    // Initialize Prover
    let prover = VdfProver::new(stark_params);

    // build the trace
    let trace = VdfProver::build_trace(seed, n);

    assert_eq!(result, trace.get(0, n - 1));

    // Generate the proof
    let proof = prover.prove(trace).unwrap();

    // Verify
    let public_inputs = VdfInputs { seed, result };
    match winterfell::verify::<
        <VdfProver as Prover>::Air,
        <VdfProver as Prover>::HashFn,
        <VdfProver as Prover>::RandomCoin,
    >(
        proof,
        public_inputs,
        &winterfell::AcceptableOptions::MinConjecturedSecurity(96),
    ) {
        Ok(_) => println!("Proof is valid"),
        Err(e) => println!("Proof is invalid: {}", e),
    }
}
