use ark_crypto_primitives::crh::{TwoToOneCRH, TwoToOneCRHGadget, CRH};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_relations::r1cs::ConstraintSynthesizer;

use crate::common::*;
use crate::constraints::*;
use crate::SimpleMerkleTree;

// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn test_merkle_tree() {
    use ark_crypto_primitives::crh::CRH;
    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
    )
    .unwrap();

    // Now, let's try to generate a membership proof for the 5th item.
    let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();
    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &[9u8], // The claimed leaf
        )
        .unwrap();
    assert!(result);
}

#[test]
fn merkle_tree_constraints_correctness_and_prove() {
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use tracing_subscriber::layer::SubscriberExt;

    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = crate::SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
    )
    .unwrap();

    // Now, let's try to generate a membership proof for the 5th item, i.e. 9.
    let proof = tree.generate_proof(0).unwrap(); // we're 0-indexing!
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();

    let circuit = MerkleTreeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf: 1u8,

        // witness
        authentication_path: Some(proof),
    };
    // First, some boilerplat that helps with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let cs = ConstraintSystem::new_ref();
    let test_circuit = circuit.clone();
    test_circuit.generate_constraints(cs.clone()).unwrap();
    // Let's check whether the constraint system is satisfied
    let is_satisfied = cs.is_satisfied().unwrap();
    assert!(is_satisfied);

    use ark_bls12_381::{Bls12_381, Fr};
    use blake2::Blake2s;

    type MultiPC = MarlinKZG10<Bls12_381, DensePolynomial<Fr>>;
    type MarlinInst = ark_marlin::Marlin<Fr, MultiPC, Blake2s>;

    let rng = &mut ark_std::test_rng();

    let universal_srs = MarlinInst::universal_setup(20000, 20000, 40000, rng).unwrap();
    let (index_pk, index_vk) = MarlinInst::index(&universal_srs, circuit.clone()).unwrap();
    println!("Called index");

    let proof = MarlinInst::prove(&index_pk, circuit.clone(), rng).unwrap();
    println!("Called prover");

    let public_input = [circuit.root];
    println!(
        "{:?}",
        MarlinInst::verify(&index_vk, &public_input, &proof, rng)
    );
    assert!(MarlinInst::verify(&index_vk, &public_input, &proof, rng).unwrap());
    println!("Called verifier");
}
