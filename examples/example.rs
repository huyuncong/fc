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
    println!("生成Merkle Tree...");
    let tree = crate::SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &a, // the i-th entry is the i-th leaf.
    )
    .unwrap();
    println!("已完成");

    use std::io;
    println!("请选择需要证明的结点（隐私输入）: ");
    let mut input = String::new();
    let node = io::stdin()
        .read_line(&mut input)
        .ok()
        .expect("Failed to read line");
    //    println!("{}", node);
    let node: usize = input.trim().parse().expect("Please type a number!");
    //    let node = 0;
    /*
    println!("{}号结点Hash值为{:?}",
        node,
        tree.leaf_nodes[node]
    );
    */

    println!("计算{}号结点验证路径...", node);
    let proof = tree.generate_proof(node - 1).unwrap();
    println!("已完成");

    // First, let's get the root we want to verify against:
    let root = tree.root();
    println!("根结点Hash值（公共输入）为{:?}", root.into_repr());
    println!("验证路径（自顶向下顺序）上的结点Hash值（隐私输入）为");
    for bro_node in &proof.auth_path {
        println!("{:?}", bro_node);
        //    println!("{:?}", proof.auth_path);
    }
    println!("{:?}", proof.leaf_sibling_hash);

    println!("生成验证电路...");
    MerkleTreeVerification {
        // constants
        leaf_crh_params,
        two_to_one_crh_params,

        // public inputs
        root,
        leaf: (node) as u8,

        // witness
        authentication_path: Some(proof),
    }
}

fn main() {
    print!("\x1b[2J");
    print!("\x1b[H");
    let num_leaves = 1 << 3;

    let rng = &mut ark_std::test_rng();
    let c = generate_merkle_tree_circuit(num_leaves);
    println!("已完成");
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

    println!("生成证明...");
    let start = ark_std::time::Instant::now();
    let proof = Marlin::<BlsFr, MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>, Blake2s>::prove(
        &pk,
        c.clone(),
        rng,
    )
    .unwrap();
    println!(
        "已完成，单线程执行下耗时{}ms",
        start.elapsed().as_millis() as u128
    );

    let v = c.clone().root;

    println!("验证证明...");
    let start2 = ark_std::time::Instant::now();
    let _ = Marlin::<BlsFr, MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>, Blake2s>::verify(
        &vk,
        &vec![v],
        &proof,
        rng,
    )
    .unwrap();

    println!(
        "已完成，单线程验证{}个叶子结点的Merkle Tree耗时{}ms",
        num_leaves,
        start2.elapsed().as_millis() as u128
    );
    println!("注：因测试环境与线程使用情况不同，可能与benchmark结果有差异。");
}
