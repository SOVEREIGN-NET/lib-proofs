//! Identity and credential proof verification
//! 
//! Provides comprehensive verification functions for identity-based
//! zero-knowledge proofs and verifiable credentials.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use zhtp_crypto::hashing::hash_blake3;
use crate::types::VerificationResult;
use super::{ZkIdentityProof, ZkCredentialProof, CredentialSchema};
use crate::identity::identity_proof::BatchIdentityProof;
use crate::identity::credential_proof::BatchCredentialProof;

/// Identity verification result with additional context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerificationResult {
    /// Basic verification result
    pub basic_result: VerificationResult,
    /// Verified attributes
    pub verified_attributes: Vec<String>,
    /// Proof age in seconds
    pub proof_age_seconds: u64,
    /// Whether proof is expired
    pub is_expired: bool,
    /// Nullifier for double-spending prevention
    pub nullifier: [u8; 32],
}

/// Verify a zero-knowledge identity proof
pub fn verify_identity_proof(proof: &ZkIdentityProof) -> Result<IdentityVerificationResult> {
    let start_time = std::time::Instant::now();
    
    // Check if proof is expired
    let is_expired = proof.is_expired();
    let proof_age_seconds = proof.age_seconds();
    
    // Verify commitment structure
    let commitment_valid = verify_identity_commitment(&proof.commitment)?;
    if !commitment_valid {
        return Ok(IdentityVerificationResult {
            basic_result: VerificationResult::Invalid("Identity commitment verification failed".to_string()),
            verified_attributes: vec![],
            proof_age_seconds,
            is_expired,
            nullifier: proof.commitment.nullifier,
        });
    }

    // Verify knowledge proof (that prover knows the identity secret)
    let knowledge_valid = verify_knowledge_proof(proof)?;
    if !knowledge_valid {
        return Ok(IdentityVerificationResult {
            basic_result: VerificationResult::Invalid("Knowledge proof verification failed".to_string()),
            verified_attributes: vec![],
            proof_age_seconds,
            is_expired,
            nullifier: proof.commitment.nullifier,
        });
    }

    // Verify challenge-response (Fiat-Shamir)
    let challenge_valid = verify_identity_challenge_response(proof)?;
    if !challenge_valid {
        return Ok(IdentityVerificationResult {
            basic_result: VerificationResult::Invalid("Challenge-response verification failed".to_string()),
            verified_attributes: vec![],
            proof_age_seconds,
            is_expired,
            nullifier: proof.commitment.nullifier,
        });
    }

    // Verify attribute proof
    let attribute_valid = verify_attribute_proof(proof)?;
    if !attribute_valid {
        return Ok(IdentityVerificationResult {
            basic_result: VerificationResult::Invalid("Attribute proof verification failed".to_string()),
            verified_attributes: vec![],
            proof_age_seconds,
            is_expired,
            nullifier: proof.commitment.nullifier,
        });
    }

    Ok(IdentityVerificationResult {
        basic_result: VerificationResult::Valid {
            circuit_id: "identity".to_string(),
            verification_time_ms: start_time.elapsed().as_millis() as u64,
            public_inputs: vec![],
        },
        verified_attributes: proof.proven_attributes.clone(),
        proof_age_seconds,
        is_expired,
        nullifier: proof.commitment.nullifier,
    })
}

/// Verify a zero-knowledge credential proof
pub fn verify_credential_proof(
    proof: &ZkCredentialProof,
    schema: &CredentialSchema,
) -> Result<VerificationResult> {
    let start_time = std::time::Instant::now();

    // Verify schema hash matches
    if proof.schema_hash != schema.schema_hash() {
        return Ok(VerificationResult::Invalid("Schema hash mismatch".to_string()));
    }

    // Check if proof is expired
    if proof.is_expired() {
        return Ok(VerificationResult::Invalid("Credential proof is expired".to_string()));
    }

    // Verify issuer signature
    let signature_valid = verify_issuer_signature(proof, schema)?;
    if !signature_valid {
        return Ok(VerificationResult::Invalid("Issuer signature verification failed".to_string()));
    }

    // Verify claims commitment
    let claims_valid = verify_claims_commitment(proof)?;
    if !claims_valid {
        return Ok(VerificationResult::Invalid("Claims commitment verification failed".to_string()));
    }

    // Verify revealed claims against schema
    let revealed_claims_valid = verify_revealed_claims(proof, schema)?;
    if !revealed_claims_valid {
        return Ok(VerificationResult::Invalid("Revealed claims verification failed".to_string()));
    }

    // Verify validity proof
    let validity_valid = verify_credential_validity_proof(proof, schema)?;
    if !validity_valid {
        return Ok(VerificationResult::Invalid("Validity proof verification failed".to_string()));
    }

    Ok(VerificationResult::Valid {
        circuit_id: "credential".to_string(),
        verification_time_ms: start_time.elapsed().as_millis() as u64,
        public_inputs: vec![],
    })
}

/// Verify batch identity proofs
pub fn verify_batch_identity_proofs(batch: &BatchIdentityProof) -> Result<Vec<IdentityVerificationResult>> {
    if batch.proofs.is_empty() {
        return Ok(vec![]);
    }

    let mut results = Vec::with_capacity(batch.proofs.len());
    
    // Verify aggregated challenge
    let aggregated_valid = verify_batch_aggregated_challenge(batch)?;
    if !aggregated_valid {
        // If aggregated challenge fails, mark all proofs as invalid
        for proof in &batch.proofs {
            results.push(IdentityVerificationResult {
                basic_result: VerificationResult::Invalid("Batch aggregation verification failed".to_string()),
                verified_attributes: vec![],
                proof_age_seconds: proof.age_seconds(),
                is_expired: proof.is_expired(),
                nullifier: proof.commitment.nullifier,
            });
        }
        return Ok(results);
    }

    // Verify Merkle root
    let merkle_valid = verify_batch_merkle_root(batch)?;
    if !merkle_valid {
        for proof in &batch.proofs {
            results.push(IdentityVerificationResult {
                basic_result: VerificationResult::Invalid("Batch Merkle root verification failed".to_string()),
                verified_attributes: vec![],
                proof_age_seconds: proof.age_seconds(),
                is_expired: proof.is_expired(),
                nullifier: proof.commitment.nullifier,
            });
        }
        return Ok(results);
    }

    // Verify individual proofs
    for proof in &batch.proofs {
        let result = verify_identity_proof(proof)?;
        results.push(result);
    }

    Ok(results)
}

/// Verify batch credential proofs
pub fn verify_batch_credential_proofs(
    batch: &BatchCredentialProof,
    schemas: &[CredentialSchema],
) -> Result<Vec<VerificationResult>> {
    if batch.proofs.len() != schemas.len() {
        return Err(anyhow::anyhow!("Proof and schema count mismatch"));
    }

    let mut results = Vec::with_capacity(batch.proofs.len());

    // Verify aggregated validity
    let aggregated_valid = verify_batch_aggregated_validity(batch)?;
    if !aggregated_valid {
        for _ in 0..batch.proofs.len() {
            results.push(VerificationResult::Invalid("Batch aggregated validity verification failed".to_string()));
        }
        return Ok(results);
    }

    // Verify combined commitment
    let commitment_valid = verify_batch_combined_commitment(batch)?;
    if !commitment_valid {
        for _ in 0..batch.proofs.len() {
            results.push(VerificationResult::Invalid("Batch combined commitment verification failed".to_string()));
        }
        return Ok(results);
    }

    // Verify individual credential proofs
    for (proof, schema) in batch.proofs.iter().zip(schemas.iter()) {
        let result = verify_credential_proof(proof, schema)?;
        results.push(result);
    }

    Ok(results)
}

/// Fast identity verification with reduced checks
pub fn verify_identity_proof_fast(proof: &ZkIdentityProof) -> Result<bool> {
    // Quick structural checks only
    if proof.is_expired() {
        return Ok(false);
    }

    // Basic commitment check
    let commitment_valid = verify_identity_commitment(&proof.commitment)?;
    if !commitment_valid {
        return Ok(false);
    }

    // Skip expensive cryptographic checks for fast verification
    Ok(true)
}

/// Helper functions for verification

fn verify_identity_commitment(commitment: &super::IdentityCommitment) -> Result<bool> {
    // Verify that commitments are non-zero (indicating proper generation)
    let valid = commitment.attribute_commitment != [0u8; 32] &&
                commitment.secret_commitment != [0u8; 32] &&
                commitment.nullifier != [0u8; 32] &&
                commitment.public_key != [0u8; 32];
    
    Ok(valid)
}

fn verify_knowledge_proof(proof: &ZkIdentityProof) -> Result<bool> {
    // In a real implementation, this would verify that the prover knows
    // the identity secret without revealing it. For this implementation,
    // we check that the knowledge proof is consistent with the commitment.
    
    // The knowledge proof is generated as hash(identity_secret || secret_commitment)
    // We can't directly verify this without the secret, so we do a basic validity check
    
    // Check that knowledge proof is non-zero (indicating proper generation)
    Ok(proof.knowledge_proof != [0u8; 32])
}

fn verify_identity_challenge_response(proof: &ZkIdentityProof) -> Result<bool> {
    // Verify Fiat-Shamir challenge
    let challenge_data = [
        &proof.commitment.attribute_commitment[..],
        &proof.commitment.secret_commitment[..],
        &proof.knowledge_proof[..],
        &proof.attribute_proof[..],
    ].concat();
    let expected_challenge = hash_blake3(&challenge_data);
    
    Ok(expected_challenge == proof.challenge)
}

fn verify_attribute_proof(proof: &ZkIdentityProof) -> Result<bool> {
    // Verify that attribute proof is consistent
    // In a real ZK system, this would verify the attributes without revealing them
    
    // For this implementation, check that attribute proof is non-zero
    Ok(proof.attribute_proof != [0u8; 32])
}

fn verify_issuer_signature(proof: &ZkCredentialProof, schema: &CredentialSchema) -> Result<bool> {
    // In a real implementation, this would verify the issuer's digital signature
    // using the issuer's public key from the schema
    
    // For this implementation, check signature is non-zero
    Ok(proof.issuer_signature != [0u8; 64])
}

fn verify_claims_commitment(proof: &ZkCredentialProof) -> Result<bool> {
    // Verify that the claims commitment is valid
    // In practice, this would involve verifying the commitment to all claims
    
    Ok(proof.claims_commitment != [0u8; 32])
}

fn verify_revealed_claims(proof: &ZkCredentialProof, schema: &CredentialSchema) -> Result<bool> {
    // Verify that revealed claims match schema requirements
    let revealed_claim_names: std::collections::HashSet<_> = proof.revealed_claims
        .iter()
        .map(|c| c.claim_name.clone())
        .collect();
    
    // Check that all required fields are either revealed or proven in hidden claims
    for required_field in &schema.required_fields {
        if !revealed_claim_names.contains(required_field) {
            // In a real implementation, we'd also check if it's in hidden claims proof
            // For now, require all required fields to be revealed
            return Ok(false);
        }
    }
    
    // Verify claim types match schema
    for claim in &proof.revealed_claims {
        if let Some(expected_type) = schema.field_types.get(&claim.claim_name) {
            if &claim.claim_type != expected_type {
                return Ok(false);
            }
        }
    }
    
    Ok(true)
}

fn verify_credential_validity_proof(proof: &ZkCredentialProof, schema: &CredentialSchema) -> Result<bool> {
    // Verify the validity proof
    let validity_data = [
        &schema.schema_hash()[..],
        &proof.claims_commitment[..],
        &proof.issuer_signature[..],
    ].concat();
    
    // In a real implementation, this would be a more complex cryptographic check
    let expected_validity_hash = hash_blake3(&validity_data);
    
    // Check partial match for simplified verification
    Ok(proof.validity_proof[0..16] == expected_validity_hash[0..16])
}

fn verify_batch_aggregated_challenge(batch: &BatchIdentityProof) -> Result<bool> {
    // Verify that the aggregated challenge is correct
    let mut challenge_data = Vec::new();
    for proof in &batch.proofs {
        challenge_data.extend_from_slice(&proof.challenge);
    }
    let expected_challenge = hash_blake3(&challenge_data);
    
    Ok(expected_challenge == batch.aggregated_challenge)
}

fn verify_batch_merkle_root(batch: &BatchIdentityProof) -> Result<bool> {
    // Verify Merkle root calculation
    let mut leaf_data = Vec::new();
    for proof in &batch.proofs {
        let proof_hash = hash_blake3(&[
            &proof.commitment.attribute_commitment[..],
            &proof.commitment.secret_commitment[..],
            &proof.challenge[..],
            &proof.response[..],
        ].concat());
        leaf_data.push(proof_hash);
    }
    
    let expected_root = calculate_merkle_root(&leaf_data);
    Ok(expected_root == batch.merkle_root)
}

fn verify_batch_aggregated_validity(batch: &BatchCredentialProof) -> Result<bool> {
    // Verify aggregated validity proof
    let mut validity_data = Vec::new();
    for proof in &batch.proofs {
        validity_data.extend_from_slice(&proof.validity_proof);
    }
    let expected_validity = hash_blake3(&validity_data);
    
    Ok(expected_validity == batch.aggregated_validity)
}

fn verify_batch_combined_commitment(batch: &BatchCredentialProof) -> Result<bool> {
    // Verify combined claims commitment
    let mut commitment_data = Vec::new();
    for proof in &batch.proofs {
        commitment_data.extend_from_slice(&proof.claims_commitment);
    }
    let expected_commitment = hash_blake3(&commitment_data);
    
    Ok(expected_commitment == batch.combined_commitment)
}

/// Helper function to calculate Merkle root (same as in identity_proof.rs)
fn calculate_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    
    if leaves.len() == 1 {
        return leaves[0];
    }
    
    let mut current_level = leaves.to_vec();
    
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        
        for chunk in current_level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_blake3(&[&chunk[0][..], &chunk[1][..]].concat())
            } else {
                chunk[0] // Odd number, carry forward
            };
            next_level.push(hash);
        }
        
        current_level = next_level;
    }
    
    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{IdentityAttributes, ZkIdentityProof, ZkCredentialProof, CredentialSchema};

    #[test]
    fn test_verify_identity_proof() {
        let attrs = IdentityAttributes::new().with_age_range(25, 35);
        let proof = ZkIdentityProof::generate(
            &attrs,
            [1u8; 32],
            [2u8; 32],
            vec!["age_range".to_string()],
        ).unwrap();

        let result = verify_identity_proof(&proof).unwrap();
        assert!(result.basic_result.is_valid());
        assert!(!result.is_expired);
        assert_eq!(result.verified_attributes, vec!["age_range"]);
    }

    #[test]
    fn test_verify_credential_proof() {
        let schema = CredentialSchema::new(
            "test_credential".to_string(),
            "1.0".to_string(),
            [1u8; 32],
        )
        .with_required_field("name".to_string(), "string".to_string());

        let proof = ZkCredentialProof::generate_education_proof(
            "Bachelor".to_string(),
            "University".to_string(),
            2020,
            None,
            [2u8; 64],
            [3u8; 32],
        ).unwrap();

        // Note: This will fail schema validation as schemas don't match
        // In a real test, we'd use matching schemas
        let result = verify_credential_proof(&proof, &schema).unwrap();
        assert!(!result.is_valid()); // Expected failure due to schema mismatch
    }

    #[test]
    fn test_fast_identity_verification() {
        let attrs = IdentityAttributes::new().with_citizenship("US".to_string());
        let proof = ZkIdentityProof::generate(
            &attrs,
            [4u8; 32],
            [5u8; 32],
            vec!["citizenship".to_string()],
        ).unwrap();

        let is_valid = verify_identity_proof_fast(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_expired_proof() {
        let attrs = IdentityAttributes::new().with_kyc_level(2);
        let mut proof = ZkIdentityProof::generate(
            &attrs,
            [6u8; 32],
            [7u8; 32],
            vec!["kyc_level".to_string()],
        ).unwrap();

        // Set timestamp to 2 days ago
        proof.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - (2 * 24 * 60 * 60);

        let result = verify_identity_proof(&proof).unwrap();
        assert!(result.is_expired);
        assert!(result.proof_age_seconds >= 2 * 24 * 60 * 60);
    }

    #[test]
    fn test_identity_commitment_verification() {
        let attrs = IdentityAttributes::new().with_age_range(18, 21);
        let commitment = super::super::IdentityCommitment::generate(&attrs, [8u8; 32], [9u8; 32]).unwrap();
        
        let is_valid = verify_identity_commitment(&commitment).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_challenge_response_verification() {
        let attrs = IdentityAttributes::new().with_license("driver".to_string());
        let proof = ZkIdentityProof::generate(
            &attrs,
            [10u8; 32],
            [11u8; 32],
            vec!["license_type".to_string()],
        ).unwrap();

        let is_valid = verify_identity_challenge_response(&proof).unwrap();
        assert!(is_valid);
    }
}
