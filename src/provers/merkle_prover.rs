// Merkle prover implementation
use crate::types::MerkleProof;
use crate::merkle::ZkMerkleTree;
use anyhow::Result;

/// Merkle prover for generating merkle inclusion proofs
pub struct MerkleProver {
    pub tree: ZkMerkleTree,
}

impl MerkleProver {
    pub fn new(tree: ZkMerkleTree) -> Self {
        Self { tree }
    }

    pub fn prove_inclusion(&self, leaf: [u8; 32], index: usize) -> Result<MerkleProof> {
        self.tree.generate_proof(index)
    }
}
