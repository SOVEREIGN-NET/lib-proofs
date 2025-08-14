//! Zero-knowledge transaction proof structures
//! 
//! Defines the ZkTransactionProof structure that contains all necessary
//! proofs for validating a transaction while preserving privacy.

use serde::{Serialize, Deserialize};
use crate::types::ZkProof;

/// Zero-knowledge transaction proof (production-ready)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkTransactionProof {
    /// Amount proof using Plonky2
    pub amount_proof: ZkProof,
    /// Balance proof using Plonky2  
    pub balance_proof: ZkProof,
    /// Nullifier proof using Plonky2
    pub nullifier_proof: ZkProof,
}

impl ZkTransactionProof {
    /// Create a new transaction proof
    pub fn new(
        amount_proof: ZkProof,
        balance_proof: ZkProof,
        nullifier_proof: ZkProof,
    ) -> Self {
        Self {
            amount_proof,
            balance_proof,
            nullifier_proof,
        }
    }

    /// Check if all proofs use Plonky2
    pub fn is_plonky2(&self) -> bool {
        self.amount_proof.is_plonky2() && 
        self.balance_proof.is_plonky2() && 
        self.nullifier_proof.is_plonky2()
    }

    /// Get the total size of all proofs in bytes
    pub fn total_size(&self) -> usize {
        self.amount_proof.size() + 
        self.balance_proof.size() + 
        self.nullifier_proof.size()
    }

    /// Check if any proof is empty/uninitialized
    pub fn has_empty_proofs(&self) -> bool {
        self.amount_proof.is_empty() || 
        self.balance_proof.is_empty() || 
        self.nullifier_proof.is_empty()
    }

    /// Get proof system types used
    pub fn proof_systems(&self) -> (String, String, String) {
        (
            self.amount_proof.proof_system.clone(),
            self.balance_proof.proof_system.clone(),
            self.nullifier_proof.proof_system.clone(),
        )
    }
}

impl Default for ZkTransactionProof {
    fn default() -> Self {
        let default_proof = ZkProof::default();

        ZkTransactionProof {
            amount_proof: default_proof.clone(),
            balance_proof: default_proof.clone(),
            nullifier_proof: default_proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_proof_creation() {
        let amount_proof = ZkProof::new(
            "Plonky2".to_string(),
            vec![1, 2, 3],
            vec![4, 5],
            vec![6, 7],
            Some(crate::plonky2::Plonky2Proof {
                circuit_id: "amount".to_string(),
                proof: vec![1, 2, 3],
                public_inputs: vec![4, 5],
                verification_key_hash: [6u8; 32],
                proof_system: "Plonky2".to_string(),
                generated_at: 1000,
                private_input_commitment: [7u8; 32],
            }),
        );
        let balance_proof = ZkProof::new(
            "Plonky2".to_string(),
            vec![8, 9, 10],
            vec![11, 12],
            vec![13, 14],
            Some(crate::plonky2::Plonky2Proof {
                circuit_id: "balance".to_string(),
                proof: vec![8, 9, 10],
                public_inputs: vec![11, 12],
                verification_key_hash: [13u8; 32],
                proof_system: "Plonky2".to_string(),
                generated_at: 2000,
                private_input_commitment: [14u8; 32],
            }),
        );
        let nullifier_proof = ZkProof::new(
            "Plonky2".to_string(),
            vec![15, 16, 17],
            vec![18, 19],
            vec![20, 21],
            Some(crate::plonky2::Plonky2Proof {
                circuit_id: "nullifier".to_string(),
                proof: vec![15, 16, 17],
                public_inputs: vec![18, 19],
                verification_key_hash: [20u8; 32],
                proof_system: "Plonky2".to_string(),
                generated_at: 3000,
                private_input_commitment: [21u8; 32],
            }),
        );

        let tx_proof = ZkTransactionProof::new(amount_proof, balance_proof, nullifier_proof);
        
        assert!(tx_proof.is_plonky2());
        assert!(tx_proof.total_size() > 0);
        assert!(!tx_proof.has_empty_proofs());
    }

    #[test]
    fn test_default_transaction_proof() {
        let tx_proof = ZkTransactionProof::default();
        
        assert!(tx_proof.is_plonky2());
        assert!(tx_proof.has_empty_proofs());
        
        let (amt_sys, bal_sys, null_sys) = tx_proof.proof_systems();
        assert_eq!(amt_sys, "Plonky2");
        assert_eq!(bal_sys, "Plonky2");
        assert_eq!(null_sys, "Plonky2");
    }
}
