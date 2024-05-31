use ff::PrimeField;
use halo2_gadgets::sha256::{BlockWord, Sha256, Table16Chip, Table16Config, BLOCK_SIZE};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::{pallas, EqAffine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;
use std::{
    fs::{create_dir_all, File},
    io::{prelude::*, BufReader},
    path::Path,
};

fn main() {
    let k = 10;

    #[derive(Default)]
    struct MyCircuit {}

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = Table16Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        // Will be run at keygen stage a-proving
        // Considers fixed assignments, ignores witness assignments
        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            Table16Chip::configure(meta)
        }

        // Will be run BOTH at keygen stage AND proving stage
        // Considers witness assignments, ignores fixed assignments
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let upper_value =
                pallas::Scalar::from_str_vartime("91343852333181432387730302044767688728495783935")
                    .unwrap();
            let upper = Value::<pallas::Scalar>::known(upper_value);

            let x_value =
                pallas::Scalar::from_str_vartime("91343852333181432387730302044767688728495783934")
                    .unwrap();
            let x = Value::<pallas::Scalar>::known(x_value);

            let y_value = pallas::Scalar::from_str_vartime("1152921504606846975").unwrap();
            let y = Value::<pallas::Scalar>::known(y_value);

            /////////////

            Table16Chip::load(config.clone(), &mut layouter)?;
            let table16_chip = Table16Chip::construct(config);
            let test_input = [
                BlockWord(Value::known(0b01100001011000100110001110000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000000000)),
                BlockWord(Value::known(0b00000000000000000000000000011000)),
            ];
            let mut input = Vec::with_capacity(31 * BLOCK_SIZE);
            for _ in 0..31 {
                input.extend_from_slice(&test_input);
            }
            Sha256::digest(table16_chip, layouter.namespace(|| "'abc' * 2"), &input)?;

            Ok(())
        }
    }

    // Create parent directory for assets
    create_dir_all("./benches/sha256_assets").expect("Failed to create sha256_assets directory");

    // Initialize the polynomial commitment parameters
    let params_path = Path::new("./benches/sha256_assets/sha256_params");
    if File::open(params_path).is_err() {
        let params: Params<EqAffine> = Params::new(k);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");
        let mut file = File::create(params_path).expect("Failed to create sha256_params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }

    let params_fs = File::open(params_path).expect("couldn't load sha256_params");
    let params: Params<EqAffine> =
        Params::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    let empty_circuit: MyCircuit = MyCircuit {};

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let circuit: MyCircuit = MyCircuit {};

    // Create a proof
    let proof_path = Path::new("./benches/sha256_assets/sha256_proof");
    if File::open(proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
            .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        let mut file = File::create(proof_path).expect("Failed to create sha256_proof");
        file.write_all(&proof[..]).expect("Failed to write proof");
    }

    let mut proof_fs = File::open(proof_path).expect("couldn't load sha256_proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Couldn't read proof");

    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript).is_ok());
}

// #[allow(dead_code)]
// fn criterion_benchmark(c: &mut Criterion) {
//     bench("sha256", 17);
// }
