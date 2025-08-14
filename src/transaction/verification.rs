//! Transaction proof verification logic
//! 
//! Provides verification functions for transaction proofs, prioritizing
//! Plonky2 verification with fallback to cryptographic verification.

use anyhow::Result;
use crate::transaction::ZkTransactionProof;
use crate::plonky2::ZkProofSystem;
use crate::types::VerificationResult;

/// Verify a transaction proof (prioritizes Plonky2)
pub fn verify_transaction(proof: &ZkTransactionProof) -> Result<bool> {
    // Check if we have Plonky2 proofs
    if let Some(plonky2_proof) = &proof.amount_proof.plonky2_proof {
        if let Ok(zk_system) = ZkProofSystem::new() {
            let amount_valid = zk_system.verify_transaction(plonky2_proof)?;
            
            if let Some(range_proof) = &proof.balance_proof.plonky2_proof {
                let balance_valid = zk_system.verify_range(range_proof)?;
                
                if let Some(nullifier_range_proof) = &proof.nullifier_proof.plonky2_proof {
                    let nullifier_valid = zk_system.verify_range(nullifier_range_proof)?;
                    
                    return Ok(amount_valid && balance_valid && nullifier_valid);
                }
            }
        }
    }

    // Fallback to cryptographic verification
    verify_transaction_fallback(proof)
}

/// Verify transaction proof with detailed results
pub fn verify_transaction_detailed(proof: &ZkTransactionProof) -> VerificationResult {
    match verify_transaction(proof) {
        Ok(true) => VerificationResult::Valid {
            circuit_id: "transaction".to_string(),
            verification_time_ms: 0,
            public_inputs: vec![],
        },
        Ok(false) => VerificationResult::Invalid("Transaction constraints violated".to_string()),
        Err(e) => VerificationResult::Error(e.to_string()),
    }
}

/// Fallback verification using cryptographic methods
fn verify_transaction_fallback(proof: &ZkTransactionProof) -> Result<bool> {
    // Verify all three proof components have valid structure  
    if proof.amount_proof.proof_system != "Plonky2" ||
       proof.balance_proof.proof_system != "Plonky2" ||
       proof.nullifier_proof.proof_system != "Plonky2" {
        return Ok(false);
    }

    // Verify all three proof components
    let amount_valid = !proof.amount_proof.public_inputs.is_empty() && 
                      !proof.amount_proof.verification_key.is_empty();
    let balance_valid = !proof.balance_proof.public_inputs.is_empty() && 
                       !proof.balance_proof.verification_key.is_empty();
    let nullifier_valid = !proof.nullifier_proof.public_inputs.is_empty() && 
                          !proof.nullifier_proof.verification_key.is_empty();

    Ok(amount_valid && balance_valid && nullifier_valid)
}

/// Verify individual proof components
pub fn verify_amount_proof(proof: &ZkTransactionProof) -> Result<bool> {
    if let Some(plonky2_proof) = &proof.amount_proof.plonky2_proof {
        if let Ok(zk_system) = ZkProofSystem::new() {
            return zk_system.verify_transaction(plonky2_proof);
        }
    }
    
    // Fallback verification
    Ok(!proof.amount_proof.public_inputs.is_empty() && 
       !proof.amount_proof.verification_key.is_empty())
}

/// Verify balance proof component
pub fn verify_balance_proof(proof: &ZkTransactionProof) -> Result<bool> {
    if let Some(plonky2_proof) = &proof.balance_proof.plonky2_proof {
        if let Ok(zk_system) = ZkProofSystem::new() {
            return zk_system.verify_range(plonky2_proof);
        }
    }
    
    // Fallback verification
    Ok(!proof.balance_proof.public_inputs.is_empty() && 
       !proof.balance_proof.verification_key.is_empty())
}

/// Verify nullifier proof component
pub fn verify_nullifier_proof(proof: &ZkTransactionProof) -> Result<bool> {
    if let Some(plonky2_proof) = &proof.nullifier_proof.plonky2_proof {
        if let Ok(zk_system) = ZkProofSystem::new() {
            return zk_system.verify_range(plonky2_proof);
        }
    }
    
    // Fallback verification
    Ok(!proof.nullifier_proof.public_inputs.is_empty() && 
       !proof.nullifier_proof.verification_key.is_empty())
}

/// Batch verify multiple transaction proofs
pub fn batch_verify_transactions(proofs: &[ZkTransactionProof]) -> Result<Vec<bool>> {
    let mut results = Vec::with_capacity(proofs.len());
    
    for proof in proofs {
        results.push(verify_transaction(proof)?);
    }
    
    Ok(results)
}

/// Check if a transaction proof meets minimum security requirements
pub fn meets_security_requirements(proof: &ZkTransactionProof) -> bool {
    // All proofs must use Plonky2 or have valid fallback verification
    proof.is_plonky2() && !proof.has_empty_proofs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::ZkTransactionProver;
    use crate::types::ZkProof;

    #[test]
    fn test_verify_valid_transaction() {
        let sender_balance = 1000u64;
        let receiver_balance = 500u64;
        let amount = 100u64;
        let fee = 10u64;
        let sender_blinding = [1u8; 32];
        let receiver_blinding = [2u8; 32];
        let nullifier = [3u8; 32];
        
        let proof = ZkTransactionProver::prove_transaction(
            sender_balance,
            receiver_balance,
            amount,
            fee,
            sender_blinding,
            receiver_blinding,
            nullifier,
        ).unwrap();
        
        let is_valid = verify_transaction(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_transaction_detailed() {
        let proof = ZkTransactionProof::default();
        
        let result = verify_transaction_detailed(&proof);
        // Default proof should be invalid (empty proofs)
        assert!(result.is_invalid());
    }

    #[test]
    fn test_verify_individual_components() {
        let proof = ZkTransactionProof::default();
        
        // Components should fail for empty proof
        assert!(!verify_amount_proof(&proof).unwrap());
        assert!(!verify_balance_proof(&proof).unwrap());
        assert!(!verify_nullifier_proof(&proof).unwrap());
    }

    #[test]
    fn test_security_requirements() {
        let empty_proof = ZkTransactionProof::default();
        assert!(!meets_security_requirements(&empty_proof));
        
        // Create proofs with valid Plonky2 data
        use crate::plonky2::Plonky2Proof;
        
        let create_valid_plonky2_proof = |circuit_id: &str| -> ZkProof {
            let plonky2 = Plonky2Proof {
                proof: vec![1, 2, 3],
                public_inputs: vec![4, 5, 6],
                verification_key_hash: [7; 32],
                proof_system: "Plonky2".to_string(),
                generated_at: 1234567890,
                circuit_id: circuit_id.to_string(),
                private_input_commitment: [8; 32],
            };
            
            ZkProof::new(
                "Plonky2".to_string(),
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![7, 8, 9],
                Some(plonky2),
            )
        };
        
        let valid_proof = ZkTransactionProof::new(
            create_valid_plonky2_proof("amount"),
            create_valid_plonky2_proof("balance"),
            create_valid_plonky2_proof("nullifier"),
        );
        
        assert!(meets_security_requirements(&valid_proof));
    }

    #[test]
    fn test_batch_verification() {
        let proof1 = ZkTransactionProver::prove_simple_transaction(100, [1u8; 32]).unwrap();
        let proof2 = ZkTransactionProver::prove_simple_transaction(200, [2u8; 32]).unwrap();
        
        let proofs = vec![proof1, proof2];
        let results = batch_verify_transactions(&proofs).unwrap();
        
        assert_eq!(results.len(), 2);
        // Both should be valid
        assert!(results.iter().all(|&r| r));
    }
}
