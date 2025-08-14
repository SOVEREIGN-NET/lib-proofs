//! # ZHTP Zero-Knowledge Proof System
//! 
//! Production-ready zero-knowledge proof system for ZHTP blockchain:
//! - Plonky2 for fast recursive SNARKs
//! - Bulletproofs for range proofs  
//! - Merkle trees with ZK inclusion proofs
//! - Identity proofs with selective disclosure
//! - Transaction privacy and validation
//! 
//! ## Features
//! 
//! - **Transaction Proofs**: Privacy-preserving transaction validation
//! - **Identity Proofs**: Selective disclosure of identity attributes
//! - **Range Proofs**: Prove values are within ranges without revealing them
//! - **Merkle Proofs**: Zero-knowledge inclusion proofs for data structures
//! - **Plonky2 Integration**: Production-grade recursive SNARKs
//! 
//! ## Example
//! 
//! ```rust
//! use zhtp_zk::{ZkProofSystem, ZkTransactionProver};
//! 
//! # #[tokio::main]
//! # async fn main() -> anyhow::Result<()> {
//! // Initialize ZK proof system
//! let zk_system = ZkProofSystem::new()?;
//! 
//! // Generate transaction proof
//! let proof = ZkTransactionProver::prove_transaction(
//!     1000, // sender_balance
//!     500,  // receiver_balance  
//!     100,  // amount
//!     10,   // fee
//!     [1u8; 32], // sender_blinding
//!     [2u8; 32], // receiver_blinding
//!     [3u8; 32], // nullifier
//! )?;
//! 
//! // Verify the proof
//! let is_valid = ZkTransactionProver::verify_transaction(&proof)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

use anyhow::Result;

// Re-export core types for convenience
pub use types::*;
pub use transaction::*;
pub use merkle::*;
pub use range::*;
pub use identity::*;
pub use plonky2::*;

// Re-export prover and verifier modules
pub use provers::*;
pub use verifiers::*;

// Module declarations
pub mod types;
pub mod transaction;
pub mod merkle;
pub mod range;
pub mod identity;
pub mod plonky2;
pub mod circuits;
pub mod provers;
pub mod verifiers;

// Type aliases for backward compatibility
pub use types::zk_proof::ZkProof as ZeroKnowledgeProof;
pub use transaction::transaction_proof::ZkTransactionProof;
pub use transaction::prover::ZkTransactionProver;
pub use merkle::tree::ZkMerkleTree;
pub use types::MerkleProof;
pub use range::range_proof::ZkRangeProof;
pub use identity::identity_proof::ZkIdentityProof;
pub use plonky2::{ZkProofSystem, Plonky2Proof};

/// Initialize the ZK proof system with all circuits
pub fn initialize_zk_system() -> Result<ZkProofSystem> {
    ZkProofSystem::new()
}

/// Create a default proof for development/testing
pub fn create_default_proof(circuit_id: &str) -> Plonky2Proof {
    ZkProofSystem::create_default_proof(circuit_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_system_initialization() {
        let zk_system = initialize_zk_system();
        assert!(zk_system.is_ok());
    }

    #[test]
    fn test_default_proof_creation() {
        let proof = create_default_proof("test");
        assert_eq!(proof.circuit_id, "test");
    }
}
