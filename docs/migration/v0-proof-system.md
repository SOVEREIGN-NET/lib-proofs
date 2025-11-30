# V0 ProofEnvelope System - Current Implementation

## Overview

The V0 ProofEnvelope system provides versioned serialization for all zero-knowledge proofs in the ZHTP blockchain. This system was implemented as part of the alpha release strategy to enable future proof system migrations without breaking existing deployments.

## What is ProofEnvelope?

`ProofEnvelope` is a versioned wrapper around the internal `ZkProof` structure that ensures all serialized proofs include a `version` field. This enables:

1. **Future migration tracking** - Know which proof version you're working with
2. **Backward compatibility** - Legacy proofs without versions default to "v0" with warnings
3. **Safe upgrades** - New proof systems (V1, V2) can coexist with V0 during migration
4. **Governance compliance** - Matches ADR-0003 proof architecture requirements

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Application Layer                   │
│  (Uses container structs: ZkTransactionProof, etc.) │
└──────────────────┬──────────────────────────────────┘
                   │
                   │ Internal representation: ZkProof
                   │
┌──────────────────▼──────────────────────────────────┐
│           Serialization Boundary                    │
│  Custom serde: ZkProof → ProofEnvelope (with v0)   │
└──────────────────┬──────────────────────────────────┘
                   │
                   │ Wire format: JSON/Binary with version
                   │
┌──────────────────▼──────────────────────────────────┐
│              Network / Storage                      │
│  {"version": "v0", "proof_system": "Plonky2", ...} │
└─────────────────────────────────────────────────────┘
```

## Current State (V0)

### What V0 Means

- **V0 = Placeholder/Development Proofs**
- Uses `ZkProof::default()` and simple proof structures
- No heavy Plonky2 compilation required
- Sufficient for alpha release features
- All proofs tagged with `version="v0"`

### Container Structs with Versioning

The following proof container structs automatically wrap their internal `ZkProof` fields in `ProofEnvelope` during serialization:

1. **ZkTransactionProof** - Transaction privacy proofs
2. **ZkRangeProof** - Value range proofs
3. **ZkIdentityProof** - Identity attribute proofs

### Internal vs External Types

```rust
// Internal (in-memory): ZkProof
pub struct ZkTransactionProof {
    pub amount_proof: ZkProof,      // Internal: no version
    pub balance_proof: ZkProof,      // Internal: no version
    pub nullifier_proof: ZkProof,    // Internal: no version
}

// External (serialized): ProofEnvelope
{
  "amount_proof": {
    "version": "v0",                 // Automatically added
    "proof_system": "Plonky2",
    "proof_data": [...],
    ...
  },
  "balance_proof": {
    "version": "v0",                 // Automatically added
    ...
  },
  "nullifier_proof": {
    "version": "v0",                 // Automatically added
    ...
  }
}
```

## Serialization Patterns

### Pattern 1: Custom Serialize Implementation

```rust
impl Serialize for ZkTransactionProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ZkTransactionProof", 3)?;

        // Wrap each ZkProof in ProofEnvelope at serialization boundary
        state.serialize_field("amount_proof",
            &ProofEnvelope::new_v0(self.amount_proof.clone()))?;
        state.serialize_field("balance_proof",
            &ProofEnvelope::new_v0(self.balance_proof.clone()))?;
        state.serialize_field("nullifier_proof",
            &ProofEnvelope::new_v0(self.nullifier_proof.clone()))?;

        state.end()
    }
}
```

### Pattern 2: Custom Deserialize Implementation

```rust
impl<'de> Deserialize<'de> for ZkTransactionProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            amount_proof: ProofEnvelope,
            balance_proof: ProofEnvelope,
            nullifier_proof: ProofEnvelope,
        }

        let helper = Helper::deserialize(deserializer)?;

        // Unwrap ProofEnvelope back to ZkProof
        Ok(ZkTransactionProof {
            amount_proof: helper.amount_proof.into_inner(),
            balance_proof: helper.balance_proof.into_inner(),
            nullifier_proof: helper.nullifier_proof.into_inner(),
        })
    }
}
```

## ProofEnvelope API

### Creating a Versioned Proof

```rust
use lib_proofs::types::{ZkProof, ProofEnvelope};

// Create internal proof
let proof = ZkProof::default();

// Wrap in versioned envelope (V0)
let envelope = ProofEnvelope::new_v0(proof);

// Or use the type alias
use lib_proofs::ZeroKnowledgeProof;  // = ProofEnvelope
let envelope: ZeroKnowledgeProof = proof.into();
```

### Accessing Proof Data

```rust
// ProofEnvelope implements Deref/DerefMut to ZkProof
let envelope = ProofEnvelope::new_v0(proof);

// Access inner proof fields transparently
let proof_system = &envelope.proof_system;  // Via Deref
let proof_data = &envelope.proof_data;      // Via Deref

// Or extract the inner proof
let inner_proof: ZkProof = envelope.into_inner();
```

### Serialization

```rust
use serde_json;

let envelope = ProofEnvelope::new_v0(ZkProof::default());

// Serialize to JSON
let json = serde_json::to_string_pretty(&envelope)?;
println!("{}", json);

// Output:
// {
//   "version": "v0",
//   "proof_system": "Plonky2",
//   "proof_data": [],
//   "public_inputs": [],
//   "verification_key": [],
//   "plonky2_proof": null,
//   "proof": []
// }
```

### Deserialization

```rust
// With version field (V0)
let json = r#"{
  "version": "v0",
  "proof_system": "Plonky2",
  "proof_data": []
}"#;

let envelope: ProofEnvelope = serde_json::from_str(json)?;
assert_eq!(envelope.version(), "v0");

// Without version field (legacy - defaults to V0 with warning)
let legacy_json = r#"{
  "proof_system": "Plonky2",
  "proof_data": []
}"#;

// Logs: WARN - Missing version field in proof; assuming v0
let envelope: ProofEnvelope = serde_json::from_str(legacy_json)?;
assert_eq!(envelope.version(), "v0");
```

## Do's and Don'ts

### ✅ DO

1. **Use container structs for serialization**
   ```rust
   let tx_proof = ZkTransactionProof::default();
   let json = serde_json::to_string(&tx_proof)?;  // ✅ Has version fields
   ```

2. **Use ProofEnvelope for single proofs**
   ```rust
   let proof = ZkProof::default();
   let envelope = ProofEnvelope::new_v0(proof);
   let json = serde_json::to_string(&envelope)?;  // ✅ Has version field
   ```

3. **Check version when deserializing**
   ```rust
   let envelope: ProofEnvelope = serde_json::from_str(json)?;
   if envelope.version() != "v0" {
       tracing::warn!("Unexpected proof version: {}", envelope.version());
   }
   ```

### ❌ DON'T

1. **Don't serialize ZkProof directly**
   ```rust
   let proof = ZkProof::default();
   let json = serde_json::to_string(&proof)?;  // ❌ No version field!
   ```

2. **Don't bypass ProofEnvelope**
   ```rust
   // ❌ Bad: Creates unversioned proof on wire
   #[derive(Serialize)]
   struct MyProof {
       proof: ZkProof,  // ❌ Should wrap in ProofEnvelope
   }
   ```

3. **Don't ignore version mismatches**
   ```rust
   let envelope: ProofEnvelope = serde_json::from_str(json)?;
   // ❌ Bad: Ignoring version
   let proof = envelope.into_inner();

   // ✅ Good: Check version first
   if envelope.version() != "v0" {
       return Err(anyhow::anyhow!("Unsupported version"));
   }
   let proof = envelope.into_inner();
   ```

## Common Patterns

### Pattern: Sending Proofs Over Network

```rust
use lib_proofs::*;

// Create proof
let tx_proof = transaction::transaction_proof::ZkTransactionProof::default();

// Serialize (automatically includes version fields)
let json = serde_json::to_string(&tx_proof)?;

// Send over network
send_to_peer(json)?;

// Receive and deserialize
let received_json = receive_from_peer()?;
let tx_proof: ZkTransactionProof = serde_json::from_str(&received_json)?;

// All proofs are automatically unwrapped from ProofEnvelope
assert!(tx_proof.amount_proof.is_empty());
```

### Pattern: Storing Proofs in Database

```rust
use lib_proofs::*;

// Create proof
let range_proof = range::range_proof::ZkRangeProof {
    proof: ZkProof::default(),
    commitment: [0u8; 32],
    min_value: 0,
    max_value: 100,
};

// Serialize with version
let bytes = bincode::serialize(&range_proof)?;

// Store in database
db.put("proof_key", &bytes)?;

// Later: Load from database
let bytes = db.get("proof_key")?;
let range_proof: ZkRangeProof = bincode::deserialize(&bytes)?;

// ProofEnvelope automatically handled during serde
```

### Pattern: Creating Custom Proof Containers

```rust
use lib_proofs::types::{ZkProof, ProofEnvelope};
use serde::{Serialize, Deserialize};

// New proof container
#[derive(Debug, Clone)]
pub struct MyCustomProof {
    pub proof: ZkProof,          // Internal: ZkProof
    pub metadata: String,
}

// Custom serialization: wrap ZkProof in ProofEnvelope
impl Serialize for MyCustomProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MyCustomProof", 2)?;

        // Wrap ZkProof in ProofEnvelope at boundary
        state.serialize_field("proof",
            &ProofEnvelope::new_v0(self.proof.clone()))?;
        state.serialize_field("metadata", &self.metadata)?;

        state.end()
    }
}

// Custom deserialization: unwrap ProofEnvelope
impl<'de> Deserialize<'de> for MyCustomProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            proof: ProofEnvelope,
            metadata: String,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(MyCustomProof {
            proof: helper.proof.into_inner(),
            metadata: helper.metadata,
        })
    }
}
```

## Version Checking

### Logging Version Mismatches

ProofEnvelope automatically logs warnings for:
- Missing version field (defaults to "v0")
- Version mismatch (expected "v0", got something else)

```rust
// Example log output:
// WARN - Missing version field in proof; assuming v0
// WARN - ProofEnvelope version mismatch: v1
```

### Explicit Version Validation

```rust
fn validate_proof_version(envelope: &ProofEnvelope) -> anyhow::Result<()> {
    const SUPPORTED_VERSIONS: &[&str] = &["v0"];

    if !SUPPORTED_VERSIONS.contains(&envelope.version()) {
        return Err(anyhow::anyhow!(
            "Unsupported proof version: {}. Supported: {:?}",
            envelope.version(),
            SUPPORTED_VERSIONS
        ));
    }

    Ok(())
}
```

## Future Migration to V1

### Timeline

- **V0 (Current - Alpha)**: Placeholder proofs, minimal versioning
- **V1 (Post-Alpha)**: Full proof governance system (PG-1 through PG-7)
  - Type-safe proof dispatch
  - Schema validation
  - Circuit-specific constraints
  - Performance optimization
  - Security hardening

### Migration Preparation

Code written against V0 today will migrate smoothly to V1 because:

1. **Version field is already in place** - V1 proofs will have `version="v1"`
2. **Serialization boundary pattern** - Same pattern will be used for V1
3. **Container structs remain** - ZkTransactionProof, etc. will support V1 internally
4. **Gradual migration** - V0 and V1 can coexist during transition

### What Will Change in V1

1. **Internal proof representation** - From placeholder ZkProof to typed proof system
2. **Proof generation** - Real Plonky2 circuits instead of defaults
3. **Validation** - Schema and constraint checking
4. **Performance** - Optimized proof generation and verification

### What Will NOT Change

1. **Container struct APIs** - ZkTransactionProof, ZkRangeProof, etc.
2. **Serialization pattern** - Still wrap at boundaries
3. **Version field location** - Still top-level in JSON
4. **ProofEnvelope concept** - V1 will use ProofEnvelope with version="v1"

## References

- [ADR-0003: ZHTP Proof Suite V1](../../lib-identity/docs/adr/0003-zhtp-proof-suite-v1.md) - Proof governance architecture
- [Alpha Strategy](../../../pm-docs/ZHTPPM/alpha-strategy-proof-governance-deferral.md) - Why V0 first, V1 later
- [ProofEnvelope Implementation](../../src/types/zk_proof.rs) - Source code
- [Verification Example](../../examples/verify_pr2_versioning.rs) - Working code example

## Support

For questions or issues with the V0 ProofEnvelope system:
1. Check existing code examples in `examples/`
2. Review test cases in `src/*/tests.rs`
3. Open an issue on GitHub with the `proof-system` label
