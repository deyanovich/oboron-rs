# Specialized Obfuscation Schemes (`z`-tier)

**IMPORTANT**: `z`-tier schemes provide deterministic obfuscation, not cryptographically secure encryption.
**DO NOT use `z`-tier for sensitive data or security-critical applications.**

If you're looking for IND-CPA standard encryption, refer to the
[main README](README.md) instead.

## Overview

`z`-tier schemes are specialized transformations designed for non-security use cases where deterministic output and high performance are prioritized over cryptographic security. These schemes are **not enabled by default** and must be explicitly enabled via feature flags.

## Available Scheme

### `ob:zrbcx` - Deterministic CBC Obfuscation

**Properties:**
- **Algorithm**: AES-CBC with constant IV
- **Deterministic**: ✅ (same input → same output)
- **Authenticated**: ❌ (no integrity protection)
- **Security tier**: z (obfuscation only)
- **Prefix structure**: `z` (tier) + `r` (referenceable) + `bc` (AES-CBC) + `x` (prefix restructuring)

**Performance Characteristics:**
- ~40% lower latency than SHA256 for short inputs on modern x86 CPUs
- ~2-4x faster than `a`-tier schemes
- Output: 28 characters in base32 encoding

## Security Considerations

### What `ob:zrbcx` Does NOT Provide:

❌ **Confidentiality for repeated plaintexts** - Uses constant IV, making repeated plaintexts detectable  
❌ **Integrity protection** - Ciphertexts can be modified without detection  
❌ **IND-CPA security** - Vulnerable to chosen-plaintext attacks  
❌ **Formal encryption guarantees** - Should be considered obfuscation, not encryption  

### Security Warnings

**DO NOT USE `ob:zrbcx` FOR:**
- Sensitive data requiring confidentiality
- Systems where data integrity matters
- Applications requiring cryptographic security guarantees
- Any scenario where attackers might observe multiple ciphertexts

**The `z` in `zrbcx` stands for "obfuscation tier"** - it's a deliberate marker that this scheme provides zero cryptographic security guarantees.

## Technical Details

### Algorithm Implementation

`ob:zrbcx` uses AES-CBC with these specific characteristics:

1. **Constant IV**: Uses the second 16 bytes of the master key as a fixed IV
2. **Custom padding**: Uses 0x01 byte padding optimized for UTF-8 strings
3. **Prefix restructuring**: XORs the first AES block with the final one to concentrate entropy in the output prefix
4. **Deterministic by design**: Same (key + plaintext) always produces same output

### Prefix Restructuring

For prefix entropy concentration, `zrbcx` applies this transformation:
```
ciphertext'[0..16] = ciphertext[0..16] XOR ciphertext[last_block]
```
This brings entropy from the entire message to the front, creating a prefix-localized avalanche effect ideal for short references.

### Key Usage

`ob:zrbcx` uses the master key partitioning:
- **Encryption key**: First 16 bytes (128 bits) of the master key
- **IV**: Second 16 bytes (128 bits) of the master key (constant)

## Appropriate Use Cases

### ✅ Acceptable Uses (Non-Security)

- **Development/testing environments** - Obfuscation for debugging/logging
- **Non-sensitive identifier generation** - Like Hashids but with better diffusion
- **Cache key generation** - Deterministic keys from structured data
- **URL slug generation** - Obfuscated but reversible identifiers
- **Hash-like applications** - Where reversibility is occasionally needed
- **Internal system IDs** - When IDs should be opaque externally but reversible internally

### Example: Database ID Obfuscation

```rust
use oboron::{ZrbcxC32, ObtextCodec};

// Enable keyless mode for development (or use env var for production-like)
let ob = ZrbcxC32::new_keyless(); // WARNING: Uses hardcoded key!

let user_id = 12345;
let obfuscated = ob.enc(&format!("user:{}", user_id))?;
// Result: "mdwsx9rdwkntyqcf806r9jhsp6gg" (28 chars)

// Can be reversed when needed
let original = ob.dec(&obfuscated)?; // "user:12345"
```

### Example: Git-like Short References

```rust
let ob = ZrbcxC32::new(&env::var("OBORON_KEY")?);
let full = ob.enc("commit:abc123")?;
let short_ref = &full[0..7]; // 7 chars = ~35 bits entropy

// Use short_ref for Git-like abbreviated references
```

## Making `z`-tier Applications More Secure

While `ob:zrbcx` alone doesn't provide cryptographic security, you can build more robust applications:

### 1. Include External Nonce in Plaintext

```rust
let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
let plaintext = format!("{}:{}", timestamp, sensitive_data);
let obtext = ob.enc(&plaintext)?;
```
Prevents repeated plaintext detection across time.

### 2. Add External Integrity Protection

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Obfuscate
let obtext = ob.enc(data)?;

// Add HMAC for integrity
let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)?;
mac.update(obtext.as_bytes());
let tag = mac.finalize().into_bytes();

// Store/transmit (obtext, tag)
```

### 3. Context-Specific Namespacing

```rust
// Prevent cross-context confusion
let plaintext = format!("{}:{}:{}", context, entity_type, id);
// e.g., "webapp:user:12345", "mobile:session:abc"
```

## Performance Comparison

| Scheme     | 8B Encode | Security Level        | Output Length (base32) |
|------------|----------|----------------------|------------------------|
| `ob:zrbcx` | 132 ns   | Obfuscation only     | 28 chars               |
| `ob:aasv`  | 334 ns   | Authenticated        | 34-47 chars            |
| SHA256     | 191 ns   | One-way hash         | 64 chars (hex)         |
| JWT        | 550 ns   | Authentication only  | 150+ chars             |

**Note:** `ob:zrbcx` shows ~40% lower latency than SHA256 for short inputs while providing reversibility.

## Enabling `z`-tier

### Cargo.toml Configuration

```toml
# Minimal: only zrbcx
oboron = { version = "1.0", features = ["zrbcx"] }

# zrbcx with keyless mode support
oboron = { version = "1.0", features = ["zrbcx", "keyless"] }

# All schemes including `z`-tier (not recommended for production)
oboron = { version = "1.0", features = ["full"] }
```

### Rust API Usage

```rust
use oboron::{ZrbcxC32, ObtextCodec};

// With environment key (recommended for consistency)
let ob = ZrbcxC32::new(&env::var("OBORON_KEY")?)?;

// Keyless mode (development/testing only - NO SECURITY)
let ob = ZrbcxC32::new_keyless()?; // Uses hardcoded public key

// Different encodings available
use oboron::{ZrbcxB32, ZrbcxB64, ZrbcxHex};
```

## Migration to Secure Alternatives

When security requirements evolve, migrate from `zrbcx` to:

1. **For deterministic + secure**: `ob:aasv` (AES-SIV, authenticated)
2. **For probabilistic + secure**: `ob:apsv` (AES-SIV, authenticated)
3. **For similar performance + security**: `ob:aags` (AES-GCM-SIV)

**Migration path:**
```rust
// Old: zrbcx for obfuscation
let old_ob = ZrbcxC32::new(&key)?;
let old_ot = old_ob.enc("data")?;

// New: aasv for security
let new_ob = AasvC32::new(&key)?;
let new_ot = new_ob.enc("data")?;

// Re-encrypt existing data during migration
let migrated = new_ob.enc(&old_ob.dec(&old_ot)?)?;
```

## Frequently Asked Questions

### Q: Why include an insecure scheme?

**A:** Oboron is a general-purpose library whose utility extends beyond encryption. For applications such as obfuscation, development tools, or hash alternatives, `z`-tier schemes provide sufficient transformation while significantly outperforming cryptographic alternatives.

### Q: Can I use `zrbcx` for password hashing?

**A:** NO! `zrbcx` is reversible and not designed for password hashing. Use Argon2, bcrypt, or scrypt for password hashing.

### Q: Is `zrbcx` safe for public-facing identifiers?

**A:** Only if the identifiers contain no sensitive information and you don't mind them being reversible by anyone with the key (or with keyless mode, by anyone at all).

### Q: How does `zrbcx` compare to Hashids?

**A:** `zrbcx` provides:
- Better diffusion (more random-looking output)
- Reversibility with key
- Consistent output length
- Better prefix entropy for short references
- But: Requires key management (unlike Hashids which uses a salt)

## Related Documentation

- [Main README](../README.md) - Overview and secure schemes
- [NON_SECURITY_USE_CASES.md](./NON_SECURITY_USE_CASES.md) - Detailed examples of appropriate `z`-tier usage
- [BENCHMARKS.md](./BENCHMARKS.md) - Performance comparisons
- [API Reference](https://docs.rs/oboron) - Complete Rust API documentation

---

**Remember:** `z`-tier = zero cryptographic guarantees. Use only when security is not a requirement.
