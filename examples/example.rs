use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::PrimeField;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{ops::Mul, UniformRand};
use blake2::Blake2s;

use ark_crypto_primitives::crh::{TwoToOneCRH, TwoToOneCRHGadget, CRH};
use ark_fc::common::{LeafHash, TwoToOneHash};
use ark_fc::constraints::MerkleTreeVerification;
use ark_fc::{Root, SimpleMerkleTree};

fn generate_merkle_tree_circuit(num_leaves: usize) -> MerkleTreeVerification {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    let mut a = Vec::new();
    for i in 1..num_leaves + 1 {
        a.push(i as u8);
    }
    let tree = crate::SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &a, // the i-th entry is the i-th leaf.
    )
    .unwrap();

    let proof = tree.generate_proof(0).unwrap();

    // First, let's get the root we want to verify against:
    let root = tree.root();

    MerkleTreeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf: 1u8,

        // witness
        authentication_path: Some(proof),
    }
}

fn main() {
    let num_leaves = 1 << 3;

    let rng = &mut ark_std::test_rng();
    let c = generate_merkle_tree_circuit(num_leaves);
    let vsize = 1 << 15;

    let srs =
        Marlin::<BlsFr, MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>, Blake2s>::universal_setup(
            vsize, vsize, vsize, rng,
        )
        .unwrap();

    let (pk, vk) = Marlin::<BlsFr, MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>, Blake2s>::index(
        &srs,
        c.clone(),
    )
    .unwrap();
    let proof = Marlin::<BlsFr, MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>, Blake2s>::prove(
        &pk,
        c.clone(),
        rng,
    )
    .unwrap();

    let start = ark_std::time::Instant::now();

    let v = c.clone().root;

    let _ = Marlin::<BlsFr, MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>, Blake2s>::verify(
        &vk,
        &vec![v],
        &proof,
        rng,
    )
    .unwrap();

    println!(
        "Verifying time for {} with {} leaves: {} ns",
        stringify!(Bls12_381),
        num_leaves,
        start.elapsed().as_nanos() as u128
    );
}
