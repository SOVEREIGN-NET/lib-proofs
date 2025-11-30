# V0 ProofEnvelope Quick Reference

## TL;DR

- **All proof serialization includes `version="v0"`** automatically
- **Use container structs** (ZkTransactionProof, ZkRangeProof, ZkIdentityProof) - they handle versioning
- **ProofEnvelope wraps ZkProof** at serialization boundaries only
- **Internal code uses ZkProof** - no changes needed
- **V1 migration later** - post-alpha, when we implement full governance

## Quick Examples

### Transaction Proof

```rust
use lib_proofs::*;

// Create and serialize
let tx_proof = transaction::transaction_proof::ZkTransactionProof::default();
let json = serde_json::to_string(&tx_proof)?;
// ✅ Automatically includes version="v0" in all proof fields

// Deserialize
let tx_proof: ZkTransactionProof = serde_json::from_str(&json)?;
// ✅ Automatically unwraps ProofEnvelope
```

### Range Proof

```rust
use lib_proofs::*;

// Create
let range_proof = range::range_proof::ZkRangeProof {
    proof: types::ZkProof::default(),
    commitment: [0u8; 32],
    min_value: 0,
    max_value: 100,
};

// Serialize
let json = serde_json::to_string(&range_proof)?;
// ✅ proof field has version="v0"
```

### Identity Proof

```rust
use lib_proofs::*;

// Create
let attributes = identity::identity_proof::IdentityAttributes::new();
let identity_proof = identity::identity_proof::ZkIdentityProof::generate(
    &attributes,
    [1u8; 32],
    [2u8; 32],
    vec!["age".to_string()],
)?;

// Serialize
let json = serde_json::to_string(&identity_proof)?;
// ✅ proof field has version="v0"
```

### Single Proof (Direct ProofEnvelope)

```rust
use lib_proofs::types::{ZkProof, ProofEnvelope};

// Wrap in envelope
let proof = ZkProof::default();
let envelope = ProofEnvelope::new_v0(proof);

// Serialize
let json = serde_json::to_string(&envelope)?;
// ✅ Has version="v0" field

// Access inner proof
let inner: ZkProof = envelope.into_inner();
```

## Common Mistakes

### ❌ Serializing ZkProof Directly

```rust
// DON'T DO THIS
let proof = ZkProof::default();
let json = serde_json::to_string(&proof)?;  // ❌ No version!
```

**Fix:** Wrap in ProofEnvelope first
```rust
let envelope = ProofEnvelope::new_v0(proof);
let json = serde_json::to_string(&envelope)?;  // ✅ Has version
```

### ❌ Creating Unversioned Containers

```rust
// DON'T DO THIS
#[derive(Serialize, Deserialize)]
struct MyProof {
    proof: ZkProof,  // ❌ Won't have version when serialized
}
```

**Fix:** Add custom serde like existing containers
```rust
#[derive(Debug, Clone)]
struct MyProof {
    proof: ZkProof,  // Internal: no version needed
}

// Add custom Serialize/Deserialize that wraps in ProofEnvelope
// See v0-proof-system.md for full pattern
```

## Checking It Works

Run the verification example:

```bash
cargo run --example verify_pr2_versioning
```

Expected output:
```
=== PR-2 Verification: Version Markers in Serialization ===

Test 1: ZkTransactionProof
✓ amount_proof has version=v0
✓ balance_proof has version=v0
✓ nullifier_proof has version=v0

Test 2: ZkRangeProof
✓ proof has version=v0

Test 3: ZkIdentityProof
✓ proof has version=v0

=== PR-2 VERIFICATION COMPLETE ===
```

## When Do I Need to Care About Versioning?

### You DON'T need to worry if:
- ✅ Using existing container structs (ZkTransactionProof, etc.)
- ✅ Working with internal ZkProof in application logic
- ✅ Calling proof generation/verification methods

### You DO need to care if:
- ⚠️ Creating new proof container structs
- ⚠️ Implementing custom serialization
- ⚠️ Storing/transmitting proofs across systems
- ⚠️ Building proof verification infrastructure

## File Structure

```
lib-proofs/
├── src/
│   ├── types/zk_proof.rs           # ProofEnvelope definition
│   ├── transaction/
│   │   └── transaction_proof.rs    # Example: custom serde
│   ├── range/range_proof.rs        # Example: custom serde
│   └── identity/identity_proof.rs  # Example: custom serde
├── examples/
│   └── verify_pr2_versioning.rs    # Verification example
└── docs/
    └── migration/
        ├── v0-proof-system.md      # Full documentation
        └── quick-reference.md      # This file
```

## Next Steps

1. **For new proof types:** Follow the custom serde pattern in `v0-proof-system.md`
2. **For V1 migration:** Wait for post-alpha - V1 design TBD
3. **For questions:** See full docs in `v0-proof-system.md`
