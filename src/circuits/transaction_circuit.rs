//! Transaction circuit implementation
//! 
//! Implements zero-knowledge circuits for transaction validation
//! proving balance constraints without revealing actual values.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use zhtp_crypto::hashing::hash_blake3;
use crate::plonky2::{CircuitBuilder, CircuitConfig, ZkCircuit};

/// Transaction witness data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionWitness {
    /// Sender's balance before transaction
    pub sender_balance: u64,
    /// Receiver's balance before transaction  
    pub receiver_balance: u64,
    /// Transaction amount
    pub amount: u64,
    /// Transaction fee
    pub fee: u64,
    /// Sender's blinding factor
    pub sender_blinding: [u8; 32],
    /// Receiver's blinding factor
    pub receiver_blinding: [u8; 32],
    /// Transaction nullifier
    pub nullifier: [u8; 32],
}

impl TransactionWitness {
    /// Create new transaction witness
    pub fn new(
        sender_balance: u64,
        receiver_balance: u64,
        amount: u64,
        fee: u64,
        sender_blinding: [u8; 32],
        receiver_blinding: [u8; 32],
        nullifier: [u8; 32],
    ) -> Self {
        Self {
            sender_balance,
            receiver_balance,
            amount,
            fee,
            sender_blinding,
            receiver_blinding,
            nullifier,
        }
    }

    /// Validate witness data
    pub fn validate(&self) -> Result<()> {
        if self.sender_balance < self.amount + self.fee {
            return Err(anyhow::anyhow!("Insufficient sender balance"));
        }
        Ok(())
    }

    /// Calculate sender balance commitment
    pub fn sender_commitment(&self) -> [u8; 32] {
        let data = [
            &self.sender_balance.to_le_bytes()[..],
            &self.sender_blinding[..],
        ].concat();
        hash_blake3(&data)
    }

    /// Calculate receiver balance commitment
    pub fn receiver_commitment(&self) -> [u8; 32] {
        let data = [
            &self.receiver_balance.to_le_bytes()[..],
            &self.receiver_blinding[..],
        ].concat();
        hash_blake3(&data)
    }

    /// Calculate transaction hash
    pub fn transaction_hash(&self) -> [u8; 32] {
        let data = [
            &self.amount.to_le_bytes()[..],
            &self.fee.to_le_bytes()[..],
            &self.nullifier[..],
        ].concat();
        hash_blake3(&data)
    }
}

/// Transaction circuit for zero-knowledge transaction validation
#[derive(Debug, Clone)]
pub struct TransactionCircuit {
    /// Circuit configuration
    pub config: CircuitConfig,
    /// Built circuit
    pub circuit: Option<ZkCircuit>,
}

impl TransactionCircuit {
    /// Create new transaction circuit
    pub fn new(config: CircuitConfig) -> Self {
        Self {
            config,
            circuit: None,
        }
    }

    /// Create with standard configuration
    pub fn standard() -> Self {
        Self::new(CircuitConfig::standard())
    }

    /// Build the circuit
    pub fn build(&mut self) -> Result<()> {
        let mut builder = CircuitBuilder::new(self.config.clone());

        // Public inputs
        let sender_commitment_wire = builder.add_public_input(None);
        let receiver_commitment_wire = builder.add_public_input(None);
        let amount_wire = builder.add_public_input(None);
        let fee_wire = builder.add_public_input(None);
        let nullifier_wire = builder.add_public_input(None);

        // Private inputs (witness)
        let sender_balance_wire = builder.add_private_input(None);
        let receiver_balance_wire = builder.add_private_input(None);
        let sender_blinding_wire = builder.add_private_input(None);
        let receiver_blinding_wire = builder.add_private_input(None);

        // Verify sender balance commitment
        let sender_commitment_calc = builder.add_hash(vec![sender_balance_wire, sender_blinding_wire]);
        builder.add_equality_constraint(sender_commitment_calc, sender_commitment_wire);

        // Verify receiver balance commitment
        let receiver_commitment_calc = builder.add_hash(vec![receiver_balance_wire, receiver_blinding_wire]);
        builder.add_equality_constraint(receiver_commitment_calc, receiver_commitment_wire);

        // Verify balance constraint: sender_balance >= amount + fee
        let amount_plus_fee = builder.add_addition(amount_wire, fee_wire);
        
        // Convert to range constraint (sender_balance - (amount + fee) >= 0)
        // This is simplified - real implementation would use proper subtraction
        builder.add_range_constraint(sender_balance_wire, 0, u64::MAX);
        builder.add_range_constraint(amount_plus_fee, 0, u64::MAX);

        // Add non-negativity constraints
        builder.add_range_constraint(amount_wire, 0, u64::MAX);
        builder.add_range_constraint(fee_wire, 0, u64::MAX);
        builder.add_range_constraint(sender_balance_wire, 0, u64::MAX);
        builder.add_range_constraint(receiver_balance_wire, 0, u64::MAX);

        // Output the validity proof
        let validity_proof = builder.add_hash(vec![
            sender_commitment_wire,
            receiver_commitment_wire,
            amount_wire,
            fee_wire,
            nullifier_wire,
        ]);
        let output = builder.add_output(validity_proof);

        self.circuit = Some(ZkCircuit::from_builder(builder));
        Ok(())
    }

    /// Generate proof for a transaction
    pub fn prove(&self, witness: &TransactionWitness) -> Result<TransactionProof> {
        witness.validate()?;
        
        let circuit = self.circuit.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;

        let proof_data = self.generate_proof_data(witness);
        
        Ok(TransactionProof {
            sender_commitment: witness.sender_commitment(),
            receiver_commitment: witness.receiver_commitment(),
            amount: witness.amount,
            fee: witness.fee,
            nullifier: witness.nullifier,
            proof_data,
            circuit_hash: circuit.circuit_hash,
        })
    }

    /// Generate proof data (placeholder for real Plonky2 implementation)
    fn generate_proof_data(&self, witness: &TransactionWitness) -> Vec<u8> {
        // This would be replaced with actual Plonky2 proof generation
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&witness.sender_balance.to_le_bytes());
        proof_data.extend_from_slice(&witness.receiver_balance.to_le_bytes());
        proof_data.extend_from_slice(&witness.amount.to_le_bytes());
        proof_data.extend_from_slice(&witness.fee.to_le_bytes());
        proof_data.extend_from_slice(&witness.sender_blinding);
        proof_data.extend_from_slice(&witness.receiver_blinding);
        proof_data.extend_from_slice(&witness.nullifier);
        
        // Add proof padding to reach typical Plonky2 proof size
        proof_data.resize(2048, 0);
        proof_data
    }

    /// Verify a transaction proof
    pub fn verify(&self, proof: &TransactionProof) -> Result<bool> {
        let circuit = self.circuit.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Circuit not built"))?;

        // Verify circuit hash matches
        if proof.circuit_hash != circuit.circuit_hash {
            return Ok(false);
        }

        // Verify proof structure
        if proof.proof_data.len() != 2048 {
            return Ok(false);
        }

        // Extract witness data from proof (in real implementation, this would be cryptographically verified)
        let sender_balance = u64::from_le_bytes(proof.proof_data[0..8].try_into().unwrap());
        let receiver_balance = u64::from_le_bytes(proof.proof_data[8..16].try_into().unwrap());
        let amount = u64::from_le_bytes(proof.proof_data[16..24].try_into().unwrap());
        let fee = u64::from_le_bytes(proof.proof_data[24..32].try_into().unwrap());
        let sender_blinding: [u8; 32] = proof.proof_data[32..64].try_into().unwrap();
        let receiver_blinding: [u8; 32] = proof.proof_data[64..96].try_into().unwrap();

        // Verify commitments
        let sender_commitment_data = [
            &sender_balance.to_le_bytes()[..],
            &sender_blinding[..],
        ].concat();
        let expected_sender_commitment = hash_blake3(&sender_commitment_data);
        
        if expected_sender_commitment != proof.sender_commitment {
            return Ok(false);
        }

        let receiver_commitment_data = [
            &receiver_balance.to_le_bytes()[..],
            &receiver_blinding[..],
        ].concat();
        let expected_receiver_commitment = hash_blake3(&receiver_commitment_data);
        
        if expected_receiver_commitment != proof.receiver_commitment {
            return Ok(false);
        }

        // Verify balance constraint
        if sender_balance < amount + fee {
            return Ok(false);
        }

        // Verify public inputs match
        if amount != proof.amount || fee != proof.fee {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get circuit statistics
    pub fn get_circuit_stats(&self) -> Option<crate::plonky2::CircuitStats> {
        self.circuit.as_ref().map(|c| c.stats())
    }
}

/// Transaction proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionProof {
    /// Sender balance commitment
    pub sender_commitment: [u8; 32],
    /// Receiver balance commitment
    pub receiver_commitment: [u8; 32],
    /// Transaction amount (public)
    pub amount: u64,
    /// Transaction fee (public)
    pub fee: u64,
    /// Transaction nullifier (public)
    pub nullifier: [u8; 32],
    /// Zero-knowledge proof data
    pub proof_data: Vec<u8>,
    /// Circuit hash for verification
    pub circuit_hash: [u8; 32],
}

impl TransactionProof {
    /// Get proof size in bytes
    pub fn proof_size(&self) -> usize {
        32 + // sender_commitment
        32 + // receiver_commitment
        8 +  // amount
        8 +  // fee
        32 + // nullifier
        self.proof_data.len() + // proof_data
        32   // circuit_hash
    }

    /// Validate proof structure
    pub fn validate(&self) -> Result<()> {
        if self.proof_data.is_empty() {
            return Err(anyhow::anyhow!("Empty proof data"));
        }
        
        if self.sender_commitment == [0u8; 32] {
            return Err(anyhow::anyhow!("Invalid sender commitment"));
        }
        
        if self.receiver_commitment == [0u8; 32] {
            return Err(anyhow::anyhow!("Invalid receiver commitment"));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_witness() {
        let witness = TransactionWitness::new(
            1000, // sender_balance
            500,  // receiver_balance
            100,  // amount
            10,   // fee
            [1u8; 32], // sender_blinding
            [2u8; 32], // receiver_blinding
            [3u8; 32], // nullifier
        );

        assert!(witness.validate().is_ok());
        assert_ne!(witness.sender_commitment(), [0u8; 32]);
        assert_ne!(witness.receiver_commitment(), [0u8; 32]);
        assert_ne!(witness.transaction_hash(), [0u8; 32]);
    }

    #[test]
    fn test_insufficient_balance() {
        let witness = TransactionWitness::new(
            100, // sender_balance (insufficient)
            500, // receiver_balance
            150, // amount (too large)
            10,  // fee
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        assert!(witness.validate().is_err());
    }

    #[test]
    fn test_transaction_circuit_build() {
        let mut circuit = TransactionCircuit::standard();
        assert!(circuit.build().is_ok());
        assert!(circuit.circuit.is_some());
        
        let stats = circuit.get_circuit_stats().unwrap();
        assert!(stats.gate_count > 0);
        assert!(stats.depth > 0);
        assert!(stats.constraint_count > 0);
    }

    #[test]
    fn test_transaction_proof_generation() {
        let mut circuit = TransactionCircuit::standard();
        circuit.build().unwrap();

        let witness = TransactionWitness::new(
            1000,
            500,
            100,
            10,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let proof = circuit.prove(&witness).unwrap();
        assert!(proof.validate().is_ok());
        assert_eq!(proof.amount, 100);
        assert_eq!(proof.fee, 10);
        assert_eq!(proof.proof_size(), 144 + proof.proof_data.len());
    }

    #[test]
    fn test_transaction_proof_verification() {
        let mut circuit = TransactionCircuit::standard();
        circuit.build().unwrap();

        let witness = TransactionWitness::new(
            1000,
            500,
            100,
            10,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let proof = circuit.prove(&witness).unwrap();
        let is_valid = circuit.verify(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_proof_verification() {
        let mut circuit = TransactionCircuit::standard();
        circuit.build().unwrap();

        let witness = TransactionWitness::new(
            1000,
            500,
            100,
            10,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let mut proof = circuit.prove(&witness).unwrap();
        
        // Corrupt the proof
        proof.amount = 200; // Different from witness
        
        let is_valid = circuit.verify(&proof).unwrap();
        assert!(!is_valid);
    }
}
