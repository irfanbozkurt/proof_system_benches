use plonky2::{
    field::goldilocks_field::GoldilocksField,
    plonk::{config::PoseidonGoldilocksConfig, proof::Proof},
};

pub type F = GoldilocksField;
// Output of Poseidon will be 4 field elements
pub type Digest = [F; 4];
// Main config for recursion
pub type C = PoseidonGoldilocksConfig;
// At some point in recursion, for security reasons, we'll need to
// use an extension field, and "2" specifies the degree of extension
// You get 100 bits of security with this config.
pub type PlonkyProof = Proof<F, C, 2>;

#[derive(Debug, Clone)]
pub struct Signal {
    pub nullifier: Digest,
    pub proof: PlonkyProof,
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::{
        field::types::{Field, Sample},
        hash::{merkle_tree::MerkleTree, poseidon::PoseidonHash},
        plonk::config::Hasher,
    };

    use crate::semaphore::access_set::AccessSet;

    use super::{Digest, F};

    #[test]
    fn semaphore() -> Result<()> {
        let n = 1 << 20;

        let private_keys: Vec<Digest> = (0..n).map(|_| F::rand_array()).collect();

        let public_keys: Vec<Vec<F>> = private_keys
            .iter()
            .map(|&sk| {
                PoseidonHash::hash_no_pad(&[sk, [F::ZERO; 4]].concat())
                    .elements
                    .to_vec()
            })
            .collect();

        let access_set = AccessSet(MerkleTree::new(public_keys, 0));

        let i = 12;

        let topic = F::rand_array();

        let (signal, verifier_data) = access_set.make_signal(private_keys[i], topic, i)?;

        access_set.verify_signal(topic, signal, &verifier_data)
    }
}
