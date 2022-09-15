// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

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

const NUM_PROVE_REPEATITIONS: usize = 10;
const NUM_VERIFY_REPEATITIONS: usize = 50;

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

macro_rules! marlin_prove_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::test_rng();

        let srs = Marlin::<
            $bench_field,
            MarlinKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
            Blake2s,
        >::universal_setup(65536, 65536, 65536, rng)
        .unwrap();

        for n in 1..4 {
            let c = generate_merkle_tree_circuit(1 << n);
            let (pk, _) = Marlin::<
                $bench_field,
                MarlinKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                Blake2s,
            >::index(&srs, c.clone())
            .unwrap();

            let start = ark_std::time::Instant::now();

            for _ in 0..NUM_PROVE_REPEATITIONS {
                let _ = Marlin::<
                    $bench_field,
                    MarlinKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                    Blake2s,
                >::prove(&pk, c.clone(), rng)
                .unwrap();
            }

            println!(
                "Proving time for {} with {} leaves: {} ns",
                stringify!($bench_pairing_engine),
                1 << n,
                start.elapsed().as_nanos() / NUM_PROVE_REPEATITIONS as u128
            );
        }
    };
}

macro_rules! marlin_verify_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::test_rng();

        let srs = Marlin::<
            $bench_field,
            MarlinKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
            Blake2s,
        >::universal_setup(65536, 65536, 65536, rng)
        .unwrap();

        for n in 1..4 {
            let c = generate_merkle_tree_circuit(1 << n);
            let (pk, vk) = Marlin::<
                $bench_field,
                MarlinKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                Blake2s,
            >::index(&srs, c.clone())
            .unwrap();
            let proof = Marlin::<
                $bench_field,
                MarlinKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                Blake2s,
            >::prove(&pk, c.clone(), rng)
            .unwrap();

            let v = c.clone().root;

            let start = ark_std::time::Instant::now();

            for _ in 0..NUM_VERIFY_REPEATITIONS {
                let _ = Marlin::<
                    $bench_field,
                    MarlinKZG10<$bench_pairing_engine, DensePolynomial<$bench_field>>,
                    Blake2s,
                >::verify(&vk, &vec![v], &proof, rng)
                .unwrap();
            }

            println!(
                "Verifying time for {} with {} leaves: {} ns",
                stringify!($bench_pairing_engine),
                1 << n,
                start.elapsed().as_nanos() / NUM_VERIFY_REPEATITIONS as u128
            );
        }
    };
}

fn bench_prove() {
    marlin_prove_bench!(bls, BlsFr, Bls12_381);
}

fn bench_verify() {
    marlin_verify_bench!(bls, BlsFr, Bls12_381);
}

fn main() {
    bench_prove();
    bench_verify();
}
