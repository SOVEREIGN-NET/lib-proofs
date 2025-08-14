//! Zero-knowledge proof structure and types
//! 
//! Defines the core ZkProof structure that supports both modern Plonky2 
//! proofs and legacy formats for backward compatibility.

use serde::{Serialize, Deserialize};
use crate::plonky2::Plonky2Proof;

/// Zero-knowledge proof (now uses real Plonky2 implementation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Proof system identifier
    pub proof_system: String,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<u8>,
    /// Verification key 
    pub verification_key: Vec<u8>,
    /// Real Plonky2 proof data for enhanced verification
    pub plonky2_proof: Option<Plonky2Proof>,
    /// Legacy proof format for compatibility
    pub proof: Vec<u8>,
}

impl ZkProof {
    /// Create a new ZK proof with Plonky2 backend
    pub fn new(
        proof_system: String,
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
        verification_key: Vec<u8>,
        plonky2_proof: Option<Plonky2Proof>,
    ) -> Self {
        Self {
            proof_system,
            proof_data: proof_data.clone(),
            public_inputs,
            verification_key,
            plonky2_proof,
            proof: proof_data, // Legacy compatibility
        }
    }

    /// Create a default/empty proof
    pub fn empty() -> Self {
        Self {
            proof_system: "Plonky2".to_string(),
            proof_data: vec![],
            public_inputs: vec![],
            verification_key: vec![],
            plonky2_proof: None,
            proof: vec![],
        }
    }

    /// Check if this proof uses Plonky2
    pub fn is_plonky2(&self) -> bool {
        self.proof_system == "Plonky2" || self.plonky2_proof.is_some()
    }

    /// Get the proof size in bytes
    pub fn size(&self) -> usize {
        self.proof_data.len() + self.public_inputs.len() + self.verification_key.len()
    }

    /// Check if the proof is empty/uninitialized
    pub fn is_empty(&self) -> bool {
        // If this is a Plonky2 proof, check if the plonky2_proof is Some
        if self.is_plonky2() {
            return self.plonky2_proof.is_none();
        }
        
        // For legacy proofs, check if all fields are empty
        self.proof_data.is_empty() && self.public_inputs.is_empty() && self.verification_key.is_empty()
    }
}

impl Default for ZkProof {
    fn default() -> Self {
        Self::empty()
    }
}

/// Type alias for backward compatibility with other modules
pub type ZeroKnowledgeProof = ZkProof;

/// Zero-knowledge proof type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkProofType {
    /// Transaction proof (amount, balance, nullifier)
    Transaction,
    /// Identity proof with selective disclosure
    Identity,
    /// Range proof for values within bounds
    Range,
    /// Merkle inclusion proof
    Merkle,
    /// Storage access proof
    Storage,
    /// Routing privacy proof
    Routing,
    /// Data integrity proof
    DataIntegrity,
    /// Custom proof type
    Custom(String),
}

impl ZkProofType {
    /// Get the string representation of the proof type
    pub fn as_str(&self) -> &str {
        match self {
            ZkProofType::Transaction => "transaction",
            ZkProofType::Identity => "identity", 
            ZkProofType::Range => "range",
            ZkProofType::Merkle => "merkle",
            ZkProofType::Storage => "storage",
            ZkProofType::Routing => "routing",
            ZkProofType::DataIntegrity => "data_integrity",
            ZkProofType::Custom(name) => name,
        }
    }

    /// Parse proof type from string
    pub fn from_str(s: &str) -> Self {
        match s {
            "transaction" => ZkProofType::Transaction,
            "identity" => ZkProofType::Identity,
            "range" => ZkProofType::Range,
            "merkle" => ZkProofType::Merkle,
            "storage" => ZkProofType::Storage,
            "routing" => ZkProofType::Routing,
            "data_integrity" => ZkProofType::DataIntegrity,
            custom => ZkProofType::Custom(custom.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_proof_creation() {
        use crate::plonky2::Plonky2Proof;
        
        // Create a valid Plonky2Proof
        let plonky2 = Plonky2Proof {
            proof: vec![1, 2, 3],
            public_inputs: vec![4, 5, 6],
            verification_key_hash: [7; 32],
            proof_system: "Plonky2".to_string(),
            generated_at: 1234567890,
            circuit_id: "test_circuit".to_string(),
            private_input_commitment: [8; 32],
        };
        
        let proof = ZkProof::new(
            "Plonky2".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            Some(plonky2),
        );

        assert_eq!(proof.proof_system, "Plonky2");
        assert!(proof.is_plonky2());
        assert_eq!(proof.size(), 9);
        assert!(!proof.is_empty());
    }

    #[test]
    fn test_zk_proof_type() {
        let tx_type = ZkProofType::Transaction;
        assert_eq!(tx_type.as_str(), "transaction");

        let parsed = ZkProofType::from_str("identity");
        assert_eq!(parsed, ZkProofType::Identity);

        let custom = ZkProofType::Custom("my_proof".to_string());
        assert_eq!(custom.as_str(), "my_proof");
    }

    #[test]
    fn test_default_proof() {
        let proof = ZkProof::default();
        assert!(proof.is_empty());
        assert!(proof.is_plonky2());
    }
}
