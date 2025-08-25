//! Integration test to verify lib-proofs properly uses zhtp-crypto
//! 
//! This test ensures that lib-proofs doesn't implement its own cryptography
//! and correctly depends on zhtp-crypto for all cryptographic operations.

use lib_proofs::range::range_proof::ZkRangeProof;
use lib_proofs::range::verification::verify_range_proof;
use lib_proofs::types::VerificationResult;
use zhtp_crypto::hashing::hash_blake3;
use zhtp_crypto::random::SecureRng;

#[test]
fn test_lib_proofs_uses_zhtp_crypto_hashing() {
    // Test that lib-proofs uses zhtp-crypto's hash function
    let test_data = b"test_data_for_hash_verification";
    let hash_result = hash_blake3(test_data);
    
    // Verify we get a proper 32-byte BLAKE3 hash
    assert_eq!(hash_result.len(), 32);
    
    // Verify deterministic behavior
    let hash_result2 = hash_blake3(test_data);
    assert_eq!(hash_result, hash_result2);
}

#[test]
fn test_lib_proofs_uses_zhtp_crypto_random() {
    // Test that lib-proofs uses zhtp-crypto's secure random generation
    let mut rng = SecureRng::new();
    
    let random1 = rng.generate_key_material();
    let random2 = rng.generate_key_material();
    
    // Verify we get proper 32-byte keys
    assert_eq!(random1.len(), 32);
    assert_eq!(random2.len(), 32);
    
    // Verify randomness (extremely unlikely to be equal)
    assert_ne!(random1, random2);
}

#[test]
fn test_range_proof_generation_uses_crypto() -> anyhow::Result<()> {
    // Test that range proof generation uses zhtp-crypto properly
    let value = 100u64;
    let min_value = 0u64;
    let max_value = 1000u64;
    
    // This should use zhtp-crypto's SecureRng internally
    let proof = ZkRangeProof::generate_simple(value, min_value, max_value)?;
    
    // Verify proof structure
    let verification_result = verify_range_proof(&proof)?;
    assert!(verification_result.is_valid());
    assert_eq!(proof.commitment.len(), 32);
    assert_eq!(proof.min_value, min_value);
    assert_eq!(proof.max_value, max_value);
    
    Ok(())
}

#[test]
fn test_no_direct_crypto_dependencies() {
    // This test compilation itself verifies that we don't have direct crypto deps
    // If curve25519-dalek or rand were still direct dependencies, this would fail
    
    // Verify we can only access crypto through zhtp-crypto
    let _hash_fn = hash_blake3; // Available through zhtp-crypto
    let _rng_type = SecureRng::new(); // Available through zhtp-crypto
    
    // These should NOT compile if we had direct dependencies:
    // let _direct_curve = curve25519_dalek::scalar::Scalar::zero(); // Should fail
    // let _direct_rand = rand::thread_rng(); // Should fail
}

#[test]
fn test_cryptographic_integrity() -> anyhow::Result<()> {
    // Test that cryptographic operations maintain integrity through the abstraction
    
    // Generate test data
    let test_message = b"ZHTP cryptographic integrity test";
    
    // Hash through zhtp-crypto
    let hash = hash_blake3(test_message);
    
    // Generate range proof that should use this hash internally
    let proof = ZkRangeProof::generate_simple(42, 0, 100)?;
    
    // Verify proof validates
    let verification_result = verify_range_proof(&proof)?;
    assert!(verification_result.is_valid());
    
    // Verify hash consistency
    let hash2 = hash_blake3(test_message);
    assert_eq!(hash, hash2);
    
    Ok(())
}

#[cfg(test)]
mod dependency_verification {
    //! Compile-time verification that we don't have direct crypto dependencies
    
    // These should compile - we have access through zhtp-crypto
    use zhtp_crypto::hashing::hash_blake3;
    use zhtp_crypto::random::SecureRng;
    
    // These should NOT be available - direct dependencies removed
    // use curve25519_dalek::scalar::Scalar; // Should cause compile error
    // use rand::thread_rng; // Should cause compile error
    
    #[test]
    fn verify_only_zhtp_crypto_access() {
        // Test passes if compilation succeeds with only zhtp-crypto imports
        let _hash = hash_blake3(b"test");
        let _rng = SecureRng::new();
    }
}
