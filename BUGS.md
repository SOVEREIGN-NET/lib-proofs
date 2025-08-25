ZKproofs do not use real zkproofs, and instead use a sort of cryptographic verification


Searched text for zk|zero.knowledge|commit|blind|proof (**/packages/zhtp-crypto/src/post_quantum/**), no results

Read post_quantum

Read mod.rs

Read constants.rs

ZK Post-Quantum Primitives Currently in zhtp-crypto: None
Finding: zhtp-crypto currently has NO ZK-specific post-quantum primitives.

What EXISTS in zhtp-crypto:
1. Basic Post-Quantum Cryptography:

dilithium.rs - CRYSTALS-Dilithium signatures
kyber.rs - CRYSTALS-Kyber KEM
constants.rs - Key size constants
2. ZK Integration Interface (but no PQ-ZK implementation):

plonky2.rs - Just trait definitions
DefaultZkProofSystem - Returns helpful error messages only
3. Basic Cryptographic Primitives:

ring_signature.rs - Has commitment functions but uses classical Curve25519
src/hashing/ - BLAKE3/SHA-3 hashing
src/random/ - Secure random generation
What's MISSING for ZK Post-Quantum Integration:
Need to CREATE these files:

1. src/post_quantum/zk_primitives.rs - Missing entirely

2. Update mod.rs - Missing ZK exports

3. Update plonky2.rs - Missing hybrid proof types

Current Status:
✅ Has: Basic PQC (Dilithium/Kyber)
✅ Has: ZK trait interface
❌ Missing: ZK-specific PQ primitives
❌ Missing: Hybrid proof support
❌ Missing: PQ commitment schemes
❌ Missing: PQ blinding functions