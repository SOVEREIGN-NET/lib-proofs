//! Zero-Knowledge Proof System Benchmarks
//! 
//! Performance benchmarks for ZHTP ZK proof system including:
//! - Transaction proof generation and verification
//! - Range proof performance
//! - Bulletproof aggregation
//! - Merkle tree operations
//! - Identity proof benchmarks

use criterion::{criterion_group, criterion_main, Criterion};
use zhtp_zk::*;

/// Benchmark transaction proof generation
fn bench_transaction_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_proof_generation");
    
    group.bench_function("generate_single_proof", |b| {
        let mut prover = ZkTransactionProver::new().unwrap();
        
        b.iter(|| {
            prover.prove_transaction(
                1000, // sender_balance
                500,  // receiver_balance
                100,  // amount
                10,   // fee
                [1u8; 32], // sender_blinding
                [2u8; 32], // receiver_blinding
                [3u8; 32], // nullifier
            ).unwrap()
        });
    });
    
    group.bench_function("generate_batch_proofs", |b| {
        let mut prover = ZkTransactionProver::new().unwrap();
        let transactions = vec![
            (1000, 500, 100, 10, [1u8; 32], [2u8; 32], [3u8; 32]),
            (2000, 600, 200, 15, [4u8; 32], [5u8; 32], [6u8; 32]),
            (1500, 700, 150, 12, [7u8; 32], [8u8; 32], [9u8; 32]),
        ];
        
        b.iter(|| {
            prover.prove_transaction_batch(transactions.clone()).unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark transaction proof verification
fn bench_transaction_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_proof_verification");
    
    let mut prover = ZkTransactionProver::new().unwrap();
    let proof = prover.prove_transaction(
        1000, 500, 100, 10,
        [1u8; 32], [2u8; 32], [3u8; 32]
    ).unwrap();
    
    group.bench_function("verify_single_proof", |b| {
        let mut verifier = transaction::verifier::TransactionVerifier::new().unwrap();
        
        b.iter(|| {
            verifier.verify(&proof).unwrap()
        });
    });
    
    let proofs = vec![proof.clone(); 10];
    group.bench_function("verify_batch_proofs", |b| {
        let mut verifier = transaction::verifier::TransactionVerifier::new().unwrap();
        
        b.iter(|| {
            verifier.verify_batch(&proofs).unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark range proof operations
fn bench_range_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_proofs");
    
    group.bench_function("generate_8bit_proof", |b| {
        b.iter(|| {
            range::bulletproofs::BulletproofRangeProof::generate_8bit(
                255, [1u8; 32]
            ).unwrap()
        });
    });
    
    group.bench_function("generate_32bit_proof", |b| {
        b.iter(|| {
            range::bulletproofs::BulletproofRangeProof::generate_32bit(
                1000000, [1u8; 32]
            ).unwrap()
        });
    });
    
    let proof = range::bulletproofs::BulletproofRangeProof::generate_32bit(
        1000000, [1u8; 32]
    ).unwrap();
    
    group.bench_function("verify_range_proof", |b| {
        b.iter(|| {
            proof.verify().unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark Bulletproof aggregation
fn bench_bulletproof_aggregation(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulletproof_aggregation");
    
    let proofs = (0..10).map(|i| {
        range::bulletproofs::BulletproofRangeProof::generate_8bit(
            (i * 10) as u8, [i as u8; 32]
        ).unwrap()
    }).collect::<Vec<_>>();
    
    group.bench_function("aggregate_10_proofs", |b| {
        b.iter(|| {
            range::bulletproofs::AggregatedBulletproof::aggregate(proofs.clone()).unwrap()
        });
    });
    
    let aggregated = range::bulletproofs::AggregatedBulletproof::aggregate(proofs).unwrap();
    
    group.bench_function("verify_aggregated_proof", |b| {
        b.iter(|| {
            aggregated.verify().unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark Merkle tree operations
fn bench_merkle_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_operations");
    
    let leaves = (0..1024u32).map(|i| i.to_le_bytes().to_vec()).collect::<Vec<_>>();
    
    group.bench_function("build_merkle_tree_1024", |b| {
        b.iter(|| {
            merkle::tree::ZkMerkleTree::from_leaves(&leaves).unwrap()
        });
    });
    
    let tree = merkle::tree::ZkMerkleTree::from_leaves(&leaves).unwrap();
    
    group.bench_function("generate_merkle_proof", |b| {
        b.iter(|| {
            tree.generate_proof(512).unwrap()
        });
    });
    
    let proof = tree.generate_proof(512).unwrap();
    
    group.bench_function("verify_merkle_proof", |b| {
        b.iter(|| {
            proof.verify().unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark identity proof operations
fn bench_identity_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("identity_operations");
    
    let attributes = vec![
        ("name".to_string(), "Alice".to_string()),
        ("age".to_string(), "30".to_string()),
        ("country".to_string(), "USA".to_string()),
    ];
    
    group.bench_function("generate_identity_proof", |b| {
        let mut prover = identity::prover::ZkIdentityProver::new().unwrap();
        
        b.iter(|| {
            prover.prove_identity(
                &attributes,
                &["name".to_string()], // revealed_attributes
                [1u8; 32], // identity_secret
            ).unwrap()
        });
    });
    
    let mut prover = identity::prover::ZkIdentityProver::new().unwrap();
    let proof = prover.prove_identity(
        &attributes,
        &["name".to_string()],
        [1u8; 32],
    ).unwrap();
    
    group.bench_function("verify_identity_proof", |b| {
        let mut verifier = identity::verifier::IdentityVerifier::new().unwrap();
        
        b.iter(|| {
            verifier.verify(&proof).unwrap()
        });
    });
    
    group.finish();
}

/// Benchmark Plonky2 system operations
fn bench_plonky2_system(c: &mut Criterion) {
    let mut group = c.benchmark_group("plonky2_system");
    
    group.bench_function("initialize_zk_system", |b| {
        b.iter(|| {
            initialize_zk_system().unwrap()
        });
    });
    
    let zk_system = initialize_zk_system().unwrap();
    
    group.bench_function("prove_transaction_plonky2", |b| {
        b.iter(|| {
            zk_system.prove_transaction(
                1000, 500, 100, 10,
                [1u8; 32], [2u8; 32], [3u8; 32]
            ).unwrap()
        });
    });
    
    let proof = zk_system.prove_transaction(
        1000, 500, 100, 10,
        [1u8; 32], [2u8; 32], [3u8; 32]
    ).unwrap();
    
    group.bench_function("verify_transaction_plonky2", |b| {
        b.iter(|| {
            zk_system.verify_transaction(&proof).unwrap()
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_transaction_proof_generation,
    bench_transaction_proof_verification,
    bench_range_proofs,
    bench_bulletproof_aggregation,
    bench_merkle_operations,
    bench_identity_operations,
    bench_plonky2_system
);

criterion_main!(benches);
