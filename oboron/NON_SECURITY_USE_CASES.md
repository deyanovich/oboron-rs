# Non-Security Use Cases for Oboron `z`-tier

This document outlines appropriate applications for Oboron's `z`-tier
schemes (`ob:zrbcx`), which provide deterministic obfuscation rather than
cryptographically secure encryption.

**Reminder:** `z`-tier schemes are **not suitable for sensitive data** or
security-critical applications. Use only when confidentiality and
integrity are not required.

For actual encryption, see the [main README](README.md) and use
`aasv`, `apsv`, `aags`, or `apgs` schemes.

## Primary Use Cases

### 1. Hash-like Identifier Generation

When you need deterministic, reversible identifiers with better
performance than cryptographic hashes:

```rust
use oboron::ztier::ZrbcxC32;
let ob = ZrbcxC32::new_keyless();

// Generate opaque ID from structured data
let user_id = ob.enc(&format!("user:{}:{}", tenant_id, user_num))?;
// "mdwsx9rdwkntyqcf806r9jhsp6gg" (28 chars)

// Short prefix for Git-like references
let short_id = &user_id[0..7]; // 7 chars = ~35 bits entropy
```

**Advantages over SHA256:**
- 27-37% faster for short strings
- More compact: 28 base32 chars vs 64 hex chars
- Reversible when needed (with key)
- Better prefix entropy for short references

**Collision resistance comparison:**
- 6 base32 chars (30 bits): Exceeds 7 hex chars (28 bits)
- 20 base32 chars (100 bits): Comparable to SHA1
- 28 base32 chars (136 bits): Stronger than SHA256's 128 bits
- Different inputs **never collide** with same key (injective)

More detailed examples in the [Appendix](#appendix).

### 2. Database ID Obfuscation

Hide sequential IDs while maintaining reversibility:

```rust
// Obfuscate database IDs for public APIs
let public_id = ob.enc(&format!("order:{}", order_id))?;
// Returns "b4g9lao2xd7fnbq5z53cb63ukc"

// Can reverse when needed (e.g., in private API endpoints)
let original = ob.dec(&public_id)?; // "order:12345"
```

**Benefits over alternatives:**
- More secure than Hashids (actual transformation, not just encoding)
- Can embed metadata (e.g., `"user:"`, `"order:"` prefixes)
- Referenceable short prefixes
- Consistent output length regardless of input size

### 3. URL-friendly State Tokens (Non-Sensitive)

For non-sensitive state that needs to be compact:

```rust
let state = serde_json::to_string(&view_state)?;
let token = ob.enc(&state)?; // ~28 characters
// "b4g9lao2xd7fnbq5z53cb63ukc"

// Much smaller than JWT (150+ chars)
```

**When appropriate:**
- UI state serialization
- Non-sensitive filter/sort parameters
- Pagination tokens (when page contents aren't secret)

### 4. Cache Key Generation

Create deterministic cache keys from structured data:

```rust
fn cache_key(user_id: &str, resource: &str, params: &HashMap<&str, &str>) -> String {
    let mut input = format!("{}:{}", user_id, resource);
    for (k, v) in params.iter().sorted() {
        input.push_str(&format!(":{}={}", k, v));
    }
    ob.enc(&input).unwrap_or_else(|_| input) // Fallback to plain input
}
```

**Advantages:**
- Consistent key length regardless of input complexity
- Opaque structure reveals no information about input
- Deterministic - same input always generates same cache key

### 5. Development & Testing Tools

For development environments where real encryption is unnecessary:

```rust
// Log obfuscation - hide PII in logs but keep reversibility for debugging
fn log_sensitive(ob: &ZrbcxC32, user_data: &str) {
    let obfuscated = ob.enc(user_data).unwrap();
    info!("User action: {}", obfuscated);
    
    // During debugging, can quickly reverse:
    // println!("Original: {}", ob.dec(&obfuscated).unwrap());
}

// Test data generation - create predictable test IDs
fn create_test_entities(ob: &ZrbcxC32, count: usize) -> Vec<String> {
    (0..count)
        .map(|i| ob.enc(&format!("test:entity:{}", i)).unwrap())
        .collect()
}
```

## Performance-Sensitive Applications

### 1. High-volume Logging

When logging non-sensitive data at high volume:

```rust
// ~40% faster than SHA256 + hex encoding
let log_token = ob.enc(&format!("{}:{}:{}", timestamp, event_type, event_data))?;
```

### 2. Real-time Analytics

Generating deterministic user/session identifiers for analytics:

```rust
// Consistent ID across sessions without storing mapping
let analytics_id = ob.enc(&format!("analytics:{}", user_fingerprint))?;
```

## Comparison with Alternatives

| Use Case            | Traditional Solution | Oboron `z`-tier                         | When to Choose Oboron                 |
|---------------------|----------------------|---------------------------------------|---------------------------------------|
| Short unique IDs    | UUIDv4 (36 chars)    | `ob:zrbcx.c32` (28 chars, reversible) | Need reversibility or better prefixes |
| Database ID masking | Hashids (insecure)   | `ob:zrbcx` (more secure than Hashids) | Want actual transformation, not encoding |
| Cache keys          | String concatenation | Consistent length, opaque structure   | Input structure shouldn't be visible  |
| Analytics IDs       | Cookie-based         | Deterministic from fingerprint        | Need consistency without server state |

## Patterns to Avoid

### ❌ Don't use for:

1. **Sensitive data** (personal information, secrets, tokens)
2. **Authentication/authorization tokens**
3. **Financial transactions**
4. **Medical/health data**
5. **Any regulated data (GDPR, HIPAA, etc.)**

### ✅ Do use for:

1. **Public identifiers** (like YouTube video IDs)
2. **URL slugs** for public content
3. **Internal system IDs** that aren't secret
4. **Development/test data**
5. **Non-sensitive configuration/toggle names**

## Security Considerations for These Use Cases

Even in non-security applications, consider these practices:

### 1. Add Context to Prevent Confusion

```rust
// Bad: Just the ID
let id = ob.enc("12345")?;

// Good: Include context
let id = ob.enc("public_user_id:12345")?;
let id = ob.enc("cache_key:v2:user:prefs:12345")?;
```

### 2. Consider Including a Version

```rust
// Allows future algorithm changes
let id = ob.enc("v1:user:12345")?;
```

### 3. Use Different Keys per Context

```rust
let user_ob = ZrbcxC32::new(&env::var("OBORON_KEY_USERS")?);
let order_ob = ZrbcxC32::new(&env::var("OBORON_KEY_ORDERS")?);
// Prevents ID conversion between contexts
```

## Integration Examples

### Web Application (Non-sensitive routes)

```rust
// Generate public-facing IDs for resources
async fn get_public_resource(Path(public_id): Path<String>) -> Result<Json<Resource>> {
    let ob = ZrbcxC32::from_secret(&env::var("OBORON_SECRET")?);
    let internal_id = ob.dec(&public_id)?; // "resource:12345"

    // Parse and fetch
    let parts: Vec<&str> = internal_id.split(':').collect();
    let db_id = parts[1];

    Ok(Json(fetch_resource(db_id).await?))
}

// Create new resource
async fn create_resource() -> Result<Json<CreatedResponse>> {
    let db_id = insert_resource().await?;
    let ob = ZrbcxC32::new(&env::var("OBORON_KEY_PUBLIC")?);
    let public_id = ob.enc(&format!("resource:{}", db_id))?;

    Ok(Json(CreatedResponse { id: public_id }))
}
```

### CLI Tool for Development

```rust
// Command to obfuscate test data
#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Obfuscate an ID for testing
    Obfuscate { input: String },

    /// De-obfuscate an ID (development only)
    Reveal { obtext: String },
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let ob = ZrbcxC32::new_keyless(); // Hardcoded dev key

    match opts.cmd {
        Command::Obfuscate { input } => {
            println!("{}", ob.enc(&input)?);
        }
        Command::Reveal { obtext } => {
            println!("{}", ob.dec(&obtext)?);
        }
    }
    Ok(())
}
```

## When to Upgrade to a-tier

Migrate from `z`-tier to a-tier (`ob:aasv` or `ob:aags`) when:

1. **Data becomes sensitive** - Any PII or confidential information
2. **System goes to production** - Better safe than sorry
3. **External audit required** - Need provable security
4. **Scale increases** - More attackers, more risk
5. **Regulatory requirements** - Legal/compliance needs

The migration is straightforward since both use the same API:

```rust
// Old: `z`-tier for development
let dev_ob = ZrbcxC32::new_keyless();

// New: a-tier for production
let prod_ob = AasvC32::new(&env::var("OBORON_KEY")?);

// Same API, just different constructor
let token = prod_ob.enc("user:12345")?;
```

**Remember:** `z`-tier is for convenience and performance in non-security
contexts. When in doubt, use a-tier.

## Appendix: Hash-like Applications

Oboron's `zrbcx` provides an efficient alternatives to UUIDs and SHA256
for generating unique, referenceable identifiers.

### Techniques: Reversible or Non-reversible

#### Approach 1: Full Oboron Output (Reversible)
```rust
let ob = ZrbcxC32::new_keyless();
let full_id = ob.enc("user:alice")?;
// "mdwsx9rdwkntyqcf806r9jhsp6gg" (28 base32 chars, reversible)
```

- Pros:
  - Reversible (decodes to "user:alice"),
  - Opaque structure: When decoded with base32, the obtext produces a
    binary blob, revealing no input patterns.
  - Oboron detects scheme, can decrypt with hardcoded key
- Cons:
  - Using hardcoded key: Given the context (keyless Oboron), anyone can
    decode
- Best for:
  - Internal systems where reversibility is useful
  - Strong obfuscation where attackers have no context of Oboron use

Possible security tightening if reversibility is needed:
- Use a shared secret with `ZrbcxC32::with_secret(&secret)`, where:
  `let secret = env::var("OBORON_SECRET")?` (Trade-off: shared secret
  management)
- Use `aags` or `aasv` for strong 256-bit tamper-proof encryption.
  (Trade-off: longer output: 44 chars; 2-3x slower than `zrbcx` but still
  comparable performance to SHA256)


#### Approach 2: Trimmed Prefix (Hash-like, Non-reversible)
```rust
let ob = ZrbcxC32::new_keyless();
let full = ob.enc("user:alice")?;
let short_id = &full[0..20];
```

- Pros:
  - Non-reversible even with hardcoded key
  - No key management
  - Adjustable length
- Cons:
  - Not reversible
- Best for:
  - Public-facing identifiers requiring opacity and referenceable short
    IDs.

### Oboron Hash-like Identifier Properties

SHA256 is the ubiquitous go-to solution for hash identifiers. However,
it is not optimized for short strings.  Hashing a 6-digit ID or an
10-character parameter is a very common use-case, however reaching for
SHA256 in this context may have drawbacks:
- the output is much longer than the input (always 64 hex characters)
- cutting the output down to a short prefix requires weighing odds of
  the birthday paradox problem
- performance is not optimal (optimized for large files)

**Performance considerations:**
- SHA256 + hex: ~190 ns, 64 hex characters (128-bit collision resistance)
- `ob:zrbcx` (one block): ~130 ns, 28 base32/34 hex chars (37% faster)
- `ob:zrbcx` (two blocks): ~147 ns, 53 base32/66 hex chars (27% faster,
  stronger than SHA256)
(Times from benchmarks run on an Intel i5 laptop.)

**Collision resistance comparison:**
- 6 base32 chars (30 bits): Exceeds 7 hex chars (28 bits) for short
  references
- 20 base32 chars (100 bits): Comparable to SHA1 collision resistance
- 28 base32 chars (136 bits): Slightly stronger than SHA256's 128 bits
- 53 base32 chars (264 bits): Substantially stronger than SHA256
Note that the consideration of Oboron's 28- and 53-bit outputs in the
context of collision resistance only makes sense in a global namespace;
when using a fixed key, the collision problem for full Oboron outputs
disappears altogether (see [the Deterministic Injectivity section in README.md](./README.md#deterministic-injectivity).

**Oboron advantages:**
1. *More compact encoding* - Base32 provides 5 bits per char vs hex's 4
   bits
2. *Referenceable prefixes* - High entropy from initial characters
3. *Tunable security* - Select prefix length for specific collision
   resistance requirements
4. *Deterministic guarantee* - Different inputs always produce
   different outputs
`ob:zrbcx` offers the additional:
5. *Better performance* - 27-37% faster than SHA256 for short strings

**When to choose which approach:**
- Oboron (28 chars): General-purpose quasi-hashing with deterministic
  non-collision guarantee, and improved performance over SHA256
- Oboron (53 chars): Stronger-than-SHA256 collision resistance (in a
  scenario without a fixed key)
- Shorter prefixes (6 chars): Git-like short references

**Note:** Oboron provides strong collision resistance for identifier
generation but is not a comprehensive replacement for cryptographic
hashing in all contexts (e.g., password hashing where slow hashes are
desirable).
