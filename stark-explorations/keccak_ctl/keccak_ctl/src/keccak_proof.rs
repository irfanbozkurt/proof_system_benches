use anyhow::Result;
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use plonky2::util::timing::TimingTree;

use starky_ctl::config::StarkConfig;

use starky_ctl::stark::Stark;

use crate::keccak_ctl_stark::KeccakCtl;
use crate::keccak_permutation::keccak_permutation_stark::KeccakPermutationStark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::keccak_sponge::keccak_util::u8_to_u32_reverse;
use crate::keccak_xor::xor_stark::KeccakXORStark;
use crate::proof_ctl::KeccakCtlProof;
use crate::prover_ctl::*;

pub fn keccak256proof_stark<F, C, const D: usize>(
    msg: &[u8],
    hash: &[u8],
) -> Result<(KeccakCtl<F, D>, KeccakCtlProof<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let config = StarkConfig::standard_fast_config();
    let keccakstark = KeccakCtl::default();

    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
    let mut timing = TimingTree::new("prove", log::Level::Debug);

    let trace_poly_values = generate_traces::<F, C, D>(&keccakstark, msg, &mut timing);

    let expected_hash: [F; 8] = u8_to_u32_reverse(hash)
        .iter()
        .map(|x| F::from_canonical_u32(*x))
        .collect_vec()
        .try_into()
        .expect("to field error");

    let proof = prove_with_traces(
        &keccakstark,
        &config,
        trace_poly_values,
        Some(expected_hash),
        &mut timing,
    )?;

    timing.print();

    Ok((keccakstark, proof))
}
