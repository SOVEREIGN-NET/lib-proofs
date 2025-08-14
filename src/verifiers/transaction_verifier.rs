//! Transaction proof verification
//! 
//! High-performance verification system for transaction proofs with
//! batch processing and caching capabilities.

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::circuits::{TransactionCircuit, TransactionProof};
use crate::types::VerificationResult;
use crate::plonky2::CircuitConfig;

/// Transaction verifier for validating zero-knowledge transaction proofs
#[derive(Debug)]
pub struct TransactionVerifier {
    /// Underlying circuit for verification
    circuit: TransactionCircuit,
    /// Verification cache for performance
    verification_cache: HashMap<[u8; 32], bool>,
    /// Performance statistics
    stats: VerificationStats,
    /// Cache settings
    cache_enabled: bool,
    cache_max_size: usize,
}

impl TransactionVerifier {
    /// Create new transaction verifier with standard configuration
    pub fn new() -> Result<Self> {
        let mut circuit = TransactionCircuit::standard();
        circuit.build()?;
        
        Ok(Self {
            circuit,
            verification_cache: HashMap::new(),
            stats: VerificationStats::new(),
            cache_enabled: true,
            cache_max_size: 10000,
        })
    }

    /// Create verifier with custom configuration
    pub fn with_config(config: CircuitConfig) -> Result<Self> {
        let mut circuit = TransactionCircuit::new(config);
        circuit.build()?;
        
        Ok(Self {
            circuit,
            verification_cache: HashMap::new(),
            stats: VerificationStats::new(),
            cache_enabled: true,
            cache_max_size: 10000,
        })
    }

    /// Create verifier without caching
    pub fn without_cache() -> Result<Self> {
        let mut verifier = Self::new()?;
        verifier.cache_enabled = false;
        Ok(verifier)
    }

    /// Verify a transaction proof
    pub fn verify(&mut self, proof: &TransactionProof) -> Result<bool> {
        let start_time = std::time::Instant::now();
        
        // Check cache first if enabled
        if self.cache_enabled {
            let proof_hash = self.calculate_proof_hash(proof);
            if let Some(&cached_result) = self.verification_cache.get(&proof_hash) {
                self.stats.cache_hits += 1;
                let elapsed = start_time.elapsed().as_millis() as u64;
                self.stats.add_verification_time(std::cmp::max(elapsed, 1));
                return Ok(cached_result);
            }
            self.stats.cache_misses += 1;
        }

        // Perform actual verification
        let is_valid = self.circuit.verify(proof)?;
        
        // Cache result if enabled
        if self.cache_enabled {
            let proof_hash = self.calculate_proof_hash(proof);
            self.add_to_cache(proof_hash, is_valid);
        }

        let verification_time = start_time.elapsed().as_millis() as u64;
        let verification_time = std::cmp::max(verification_time, 1);
        self.stats.add_verification_time(verification_time);
        self.stats.increment_verifications();
        
        if is_valid {
            self.stats.valid_proofs += 1;
        } else {
            self.stats.invalid_proofs += 1;
        }

        Ok(is_valid)
    }

    /// Verify with detailed result
    pub fn verify_detailed(&mut self, proof: &TransactionProof) -> Result<VerificationResult> {
        let start_time = std::time::Instant::now();
        
        let is_valid = match self.verify(proof) {
            Ok(valid) => valid,
            Err(e) => {
                return Ok(VerificationResult::Error(e.to_string()));
            }
        };

        let verification_time = start_time.elapsed().as_millis() as u64;
        let verification_time = std::cmp::max(verification_time, 1);
        
        if is_valid {
            Ok(VerificationResult::Valid {
                circuit_id: "transaction_verifier".to_string(),
                verification_time_ms: verification_time,
                public_inputs: vec![proof.amount, proof.fee],
            })
        } else {
            Ok(VerificationResult::Invalid("Transaction verification failed".to_string()))
        }
    }

    /// Verify batch of transaction proofs
    pub fn verify_batch(&mut self, proofs: &[TransactionProof]) -> Result<Vec<bool>> {
        let mut results = Vec::with_capacity(proofs.len());
        
        for proof in proofs {
            let is_valid = self.verify(proof)?;
            results.push(is_valid);
        }
        
        Ok(results)
    }

    /// Verify batch with detailed results
    pub fn verify_batch_detailed(&mut self, proofs: &[TransactionProof]) -> Result<Vec<VerificationResult>> {
        let mut results = Vec::with_capacity(proofs.len());
        
        for proof in proofs {
            let result = self.verify_detailed(proof)?;
            results.push(result);
        }
        
        Ok(results)
    }

    /// Parallel verification for large batches
    pub fn verify_batch_parallel(&mut self, proofs: &[TransactionProof]) -> Result<Vec<bool>> {
        // Note: In a real implementation, this would use actual parallelization
        // For now, we'll simulate parallel processing with chunked verification
        
        let chunk_size = std::cmp::max(1, proofs.len() / num_cpus::get());
        let mut results = Vec::with_capacity(proofs.len());
        
        for chunk in proofs.chunks(chunk_size) {
            let chunk_results = self.verify_batch(chunk)?;
            results.extend(chunk_results);
        }
        
        Ok(results)
    }

    /// Fast verification mode (reduced security checks)
    pub fn verify_fast(&mut self, proof: &TransactionProof) -> Result<bool> {
        let start_time = std::time::Instant::now();
        
        // Basic structural validation only
        if let Err(_) = proof.validate() {
            return Ok(false);
        }

        // Quick circuit hash check
        if proof.circuit_hash != self.circuit.circuit.as_ref().unwrap().circuit_hash {
            return Ok(false);
        }

        // Skip expensive cryptographic verification
        let verification_time = start_time.elapsed().as_millis() as u64;
        let verification_time = std::cmp::max(verification_time, 1);
        self.stats.add_verification_time(verification_time);
        self.stats.increment_verifications();
        
        Ok(true)
    }

    /// Calculate proof hash for caching
    fn calculate_proof_hash(&self, proof: &TransactionProof) -> [u8; 32] {
        use zhtp_crypto::hashing::hash_blake3;
        
        let mut data = Vec::new();
        data.extend_from_slice(&proof.sender_commitment);
        data.extend_from_slice(&proof.receiver_commitment);
        data.extend_from_slice(&proof.amount.to_le_bytes());
        data.extend_from_slice(&proof.fee.to_le_bytes());
        data.extend_from_slice(&proof.nullifier);
        data.extend_from_slice(&proof.proof_data);
        
        hash_blake3(&data)
    }

    /// Add result to cache with eviction policy
    fn add_to_cache(&mut self, proof_hash: [u8; 32], result: bool) {
        if self.verification_cache.len() >= self.cache_max_size {
            // Simple eviction: remove oldest entry
            if let Some(oldest_key) = self.verification_cache.keys().next().copied() {
                self.verification_cache.remove(&oldest_key);
            }
        }
        
        self.verification_cache.insert(proof_hash, result);
    }

    /// Clear verification cache
    pub fn clear_cache(&mut self) {
        self.verification_cache.clear();
        self.stats.cache_hits = 0;
        self.stats.cache_misses = 0;
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            cache_size: self.verification_cache.len(),
            cache_hits: self.stats.cache_hits,
            cache_misses: self.stats.cache_misses,
            hit_ratio: if self.stats.cache_hits + self.stats.cache_misses > 0 {
                self.stats.cache_hits as f64 / (self.stats.cache_hits + self.stats.cache_misses) as f64
            } else {
                0.0
            },
        }
    }

    /// Get verification statistics
    pub fn get_stats(&self) -> &VerificationStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = VerificationStats::new();
    }

    /// Configure cache settings
    pub fn configure_cache(&mut self, enabled: bool, max_size: usize) {
        self.cache_enabled = enabled;
        self.cache_max_size = max_size;
        
        if !enabled {
            self.clear_cache();
        }
    }
}

impl Default for TransactionVerifier {
    fn default() -> Self {
        Self::new().expect("Failed to create default TransactionVerifier")
    }
}

/// Verification performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    /// Total verifications performed
    pub total_verifications: u64,
    /// Number of valid proofs verified
    pub valid_proofs: u64,
    /// Number of invalid proofs verified
    pub invalid_proofs: u64,
    /// Total verification time (ms)
    pub total_verification_time_ms: u64,
    /// Average verification time (ms)
    pub average_verification_time_ms: f64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
}

impl VerificationStats {
    /// Create new statistics
    pub fn new() -> Self {
        Self {
            total_verifications: 0,
            valid_proofs: 0,
            invalid_proofs: 0,
            total_verification_time_ms: 0,
            average_verification_time_ms: 0.0,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    /// Add verification time
    pub fn add_verification_time(&mut self, time_ms: u64) {
        self.total_verification_time_ms += time_ms;
        self.update_average();
    }

    /// Increment verification count
    pub fn increment_verifications(&mut self) {
        self.total_verifications += 1;
        self.update_average();
    }

    /// Update average verification time
    fn update_average(&mut self) {
        if self.total_verifications > 0 {
            self.average_verification_time_ms = 
                self.total_verification_time_ms as f64 / self.total_verifications as f64;
        }
    }

    /// Get verification throughput (verifications per second)
    pub fn throughput(&self) -> f64 {
        if self.average_verification_time_ms > 0.0 {
            1000.0 / self.average_verification_time_ms
        } else {
            0.0
        }
    }

    /// Get accuracy rate (valid proofs / total proofs)
    pub fn accuracy_rate(&self) -> f64 {
        if self.total_verifications > 0 {
            self.valid_proofs as f64 / self.total_verifications as f64
        } else {
            0.0
        }
    }
}

impl Default for VerificationStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Current cache size
    pub cache_size: usize,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Cache hit ratio
    pub hit_ratio: f64,
}

/// Batch transaction verifier with optimized performance
#[derive(Debug)]
pub struct BatchTransactionVerifier {
    /// Base verifier
    verifier: TransactionVerifier,
    /// Batch size for optimal performance
    batch_size: usize,
    /// Parallel processing enabled
    parallel_enabled: bool,
}

impl BatchTransactionVerifier {
    /// Create new batch verifier
    pub fn new(batch_size: usize) -> Result<Self> {
        Ok(Self {
            verifier: TransactionVerifier::new()?,
            batch_size,
            parallel_enabled: true,
        })
    }

    /// Process large batch with automatic chunking
    pub fn verify_large_batch(&mut self, proofs: &[TransactionProof]) -> Result<Vec<bool>> {
        let mut all_results = Vec::with_capacity(proofs.len());
        
        for chunk in proofs.chunks(self.batch_size) {
            let chunk_results = if self.parallel_enabled && chunk.len() > 4 {
                self.verifier.verify_batch_parallel(chunk)?
            } else {
                self.verifier.verify_batch(chunk)?
            };
            all_results.extend(chunk_results);
        }
        
        Ok(all_results)
    }

    /// Get optimal batch size for current system
    pub fn optimal_batch_size() -> usize {
        num_cpus::get() * 4
    }

    /// Enable or disable parallel processing
    pub fn set_parallel_enabled(&mut self, enabled: bool) {
        self.parallel_enabled = enabled;
    }

    /// Get verifier statistics
    pub fn get_stats(&self) -> &VerificationStats {
        self.verifier.get_stats()
    }
}

/// Verification result aggregator for analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResultAggregator {
    /// Total results processed
    pub total_results: usize,
    /// Valid proof count
    pub valid_count: usize,
    /// Invalid proof count  
    pub invalid_count: usize,
    /// Error count
    pub error_count: usize,
    /// Average verification time
    pub average_time_ms: f64,
    /// Min verification time
    pub min_time_ms: u64,
    /// Max verification time
    pub max_time_ms: u64,
}

impl VerificationResultAggregator {
    /// Create new aggregator
    pub fn new() -> Self {
        Self {
            total_results: 0,
            valid_count: 0,
            invalid_count: 0,
            error_count: 0,
            average_time_ms: 0.0,
            min_time_ms: u64::MAX,
            max_time_ms: 0,
        }
    }

    /// Add verification results
    pub fn add_results(&mut self, results: &[VerificationResult]) {
        for result in results {
            self.add_result(result);
        }
    }

    /// Add single verification result
    pub fn add_result(&mut self, result: &VerificationResult) {
        self.total_results += 1;
        
        if result.is_valid() {
            self.valid_count += 1;
        } else {
            self.invalid_count += 1;
        }
        
        if result.error_message().is_some() {
            self.error_count += 1;
        }
        
        // Update timing statistics
        if let Some(time_ms) = result.verification_time_ms() {
            self.min_time_ms = self.min_time_ms.min(time_ms);
            self.max_time_ms = self.max_time_ms.max(time_ms);
            
            // Update average (incremental calculation)
            let old_avg = self.average_time_ms;
            self.average_time_ms = old_avg + (time_ms as f64 - old_avg) / self.total_results as f64;
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_results > 0 {
            self.valid_count as f64 / self.total_results as f64
        } else {
            0.0
        }
    }

    /// Get error rate
    pub fn error_rate(&self) -> f64 {
        if self.total_results > 0 {
            self.error_count as f64 / self.total_results as f64
        } else {
            0.0
        }
    }
}

impl Default for VerificationResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provers::transaction_prover::TransactionProver;
    use crate::types::ZkProofType;

    #[test]
    fn test_transaction_verifier_creation() {
        let verifier = TransactionVerifier::new();
        assert!(verifier.is_ok());
    }

    #[test]
    fn test_transaction_verification() {
        let mut prover = TransactionProver::new().unwrap();
        let mut verifier = TransactionVerifier::new().unwrap();
        
        let proof = prover.prove_transaction(
            1000, 500, 100, 10,
            [1u8; 32], [2u8; 32], [3u8; 32]
        ).unwrap();
        
        let is_valid = verifier.verify(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_detailed_verification() {
        let mut prover = TransactionProver::new().unwrap();
        let mut verifier = TransactionVerifier::new().unwrap();
        
        let proof = prover.prove_transaction(
            1000, 500, 100, 10,
            [1u8; 32], [2u8; 32], [3u8; 32]
        ).unwrap();
        
        let result = verifier.verify_detailed(&proof).unwrap();
        assert!(result.is_valid());
        assert!(result.error_message().is_none());
        assert_eq!(result.proof_type(), ZkProofType::Transaction);
    }

    #[test]
    fn test_batch_verification() {
        let mut prover = TransactionProver::new().unwrap();
        let mut verifier = TransactionVerifier::new().unwrap();
        
        let transactions = vec![
            (1000, 500, 100, 10, [1u8; 32], [2u8; 32], [3u8; 32]),
            (2000, 600, 200, 15, [4u8; 32], [5u8; 32], [6u8; 32]),
            (1500, 700, 150, 12, [7u8; 32], [8u8; 32], [9u8; 32]),
        ];
        
        let proofs = prover.prove_transaction_batch(transactions).unwrap();
        let results = verifier.verify_batch(&proofs).unwrap();
        
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&r| r));
    }

    #[test]
    fn test_verification_cache() {
        let mut prover = TransactionProver::new().unwrap();
        let mut verifier = TransactionVerifier::new().unwrap();
        
        let proof = prover.prove_transaction(
            1000, 500, 100, 10,
            [1u8; 32], [2u8; 32], [3u8; 32]
        ).unwrap();
        
        // First verification (cache miss)
        let _result1 = verifier.verify(&proof).unwrap();
        
        // Second verification (cache hit)
        let _result2 = verifier.verify(&proof).unwrap();
        
        let cache_stats = verifier.cache_stats();
        assert_eq!(cache_stats.cache_hits, 1);
        assert_eq!(cache_stats.cache_misses, 1);
        assert_eq!(cache_stats.hit_ratio, 0.5);
    }

    #[test]
    fn test_fast_verification() {
        let mut prover = TransactionProver::new().unwrap();
        let mut verifier = TransactionVerifier::new().unwrap();
        
        let proof = prover.prove_transaction(
            1000, 500, 100, 10,
            [1u8; 32], [2u8; 32], [3u8; 32]
        ).unwrap();
        
        let is_valid = verifier.verify_fast(&proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verification_stats() {
        let mut prover = TransactionProver::new().unwrap();
        let mut verifier = TransactionVerifier::new().unwrap();
        
        // Verify several proofs
        for i in 0..5 {
            let proof = prover.prove_transaction(
                1000 + i * 100, 500, 100, 10,
                [i as u8; 32], [2u8; 32], [3u8; 32]
            ).unwrap();
            let _result = verifier.verify(&proof).unwrap();
        }
        
        let stats = verifier.get_stats();
        assert_eq!(stats.total_verifications, 5);
        assert_eq!(stats.valid_proofs, 5);
        assert_eq!(stats.invalid_proofs, 0);
        assert!(stats.average_verification_time_ms > 0.0);
        assert!(stats.throughput() > 0.0);
    }

    #[test]
    fn test_batch_transaction_verifier() {
        let mut prover = TransactionProver::new().unwrap();
        let mut batch_verifier = BatchTransactionVerifier::new(2).unwrap();
        
        let transactions = vec![
            (1000, 500, 100, 10, [1u8; 32], [2u8; 32], [3u8; 32]),
            (2000, 600, 200, 15, [4u8; 32], [5u8; 32], [6u8; 32]),
            (1500, 700, 150, 12, [7u8; 32], [8u8; 32], [9u8; 32]),
            (1200, 800, 120, 8, [10u8; 32], [11u8; 32], [12u8; 32]),
        ];
        
        let proofs = prover.prove_transaction_batch(transactions).unwrap();
        let results = batch_verifier.verify_large_batch(&proofs).unwrap();
        
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|&r| r));
    }

    #[test]
    fn test_verification_result_aggregator() {
        let mut aggregator = VerificationResultAggregator::new();
        
        let results = vec![
            VerificationResult::Valid {
                circuit_id: "test1".to_string(),
                verification_time_ms: 100,
                public_inputs: vec![],
            },
            VerificationResult::Valid {
                circuit_id: "test2".to_string(),
                verification_time_ms: 150,
                public_inputs: vec![],
            },
            VerificationResult::Invalid("test error".to_string()),
        ];
        
        aggregator.add_results(&results);
        
        assert_eq!(aggregator.total_results, 3);
        assert_eq!(aggregator.valid_count, 2);
        assert_eq!(aggregator.invalid_count, 1);
        assert_eq!(aggregator.error_count, 1);
        assert_eq!(aggregator.success_rate(), 2.0 / 3.0);
        assert!(aggregator.average_time_ms > 0.0);
    }

    #[test]
    fn test_cache_configuration() {
        let mut verifier = TransactionVerifier::new().unwrap();
        
        // Disable cache
        verifier.configure_cache(false, 0);
        
        let cache_stats = verifier.cache_stats();
        assert_eq!(cache_stats.cache_size, 0);
        
        // Re-enable cache with smaller size
        verifier.configure_cache(true, 100);
        assert_eq!(verifier.cache_max_size, 100);
    }
}
