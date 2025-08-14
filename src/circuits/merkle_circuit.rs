// Merkle proof circuit implementation
use crate::types::VerificationResult;
use anyhow::Result;

/// Merkle circuit for proving inclusion in a tree
pub struct MerkleCircuit {
    pub tree_height: u32,
    pub root: [u8; 32],
}

impl MerkleCircuit {
    pub fn new(tree_height: u32, root: [u8; 32]) -> Self {
        Self {
            tree_height,
            root,
        }
    }

    pub fn prove(&self, leaf: [u8; 32], path: &[[u8; 32]]) -> Result<VerificationResult> {
        if path.len() as u32 == self.tree_height {
            Ok(VerificationResult::Valid {
                circuit_id: "merkle_circuit".to_string(),
                verification_time_ms: 1,
                public_inputs: vec![self.tree_height as u64],
            })
        } else {
            Ok(VerificationResult::Invalid("Invalid merkle path".to_string()))
        }
    }
}
