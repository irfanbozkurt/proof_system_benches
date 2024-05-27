use anyhow::Result;
use plonky2::{
    hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitData},
        config::Hasher,
        proof::ProofWithPublicInputs,
    },
};

use super::signal::{Digest, Signal, C, F};

pub struct AccessSet(pub MerkleTree<F, PoseidonHash>);

impl AccessSet {
    pub fn make_signal(
        &self,
        private_key: Digest,   // Your priv key
        topic: Digest,         // What topic you want to vote to
        public_key_idx: usize, // Within merkle tree
    ) -> Result<(Signal, VerifierCircuitData<F, C, 2>)> {
        // We use the standard recursion config with zero-knowledge.
        // This is a bit more inefficient,
        // but we want to hide the private key and the nullifier.
        let config = CircuitConfig::standard_recursion_zk_config();

        // Main API where each gadget / chip is implemented over.
        let mut builder = CircuitBuilder::new(config);

        // Create and fill a witness.
        // We'll fill a "partial" witness because Plonky2 API will
        // fill the rest of the cells depending on our circuit.
        let mut partial_witness = PartialWitness::new();
        self.fill_targets(
            &mut partial_witness,
            private_key,
            topic,
            public_key_idx,
            self.circuit(&mut builder),
        );

        // Export
        let data = builder.build();

        Ok((
            Signal {
                // Nullifier is just a hash of private key and topic
                nullifier: PoseidonHash::hash_no_pad(&[private_key, topic].concat()).elements,
                proof: data.prove(partial_witness)?.proof,
            },
            data.verifier_data(),
        ))
    }

    pub fn verify_signal(
        &self,
        topic: Digest,
        signal: Signal,
        // We need a verifier key because we use PLONK and it commits to
        // a set of columnar polynomials. In STARKs, we wouldn't need it.
        verifier_data: &VerifierCircuitData<F, C, 2>,
    ) -> Result<()> {
        // Verifier calculates public inputs.
        let public_inputs: Vec<F> = self
            .0
            .cap
            .0
            .iter()
            .flat_map(|h| h.elements) // Merkle root
            .chain(signal.nullifier) // nullifier is public, too
            .chain(topic) // topic is public, too
            .collect();

        verifier_data.verify(ProofWithPublicInputs {
            public_inputs,
            proof: signal.proof,
        })
    }
}
