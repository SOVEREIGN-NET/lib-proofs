//! Proof verification modules
//! 
//! Provides specialized verifiers for different types of zero-knowledge proofs
//! with optimized verification performance and batch processing.

pub mod transaction_verifier;
pub mod identity_verifier;
pub mod range_verifier;
pub mod merkle_verifier;

// Re-export main types
pub use transaction_verifier::TransactionVerifier;
pub use identity_verifier::IdentityVerifier;
pub use range_verifier::RangeVerifier;

// Re-export merkle verification functions
pub use merkle_verifier::{
    verify_merkle_proof, 
    verify_merkle_proof_detailed,
    batch_verify_merkle_proofs,
    verify_with_tree,
    verify_with_tree_detailed
};
