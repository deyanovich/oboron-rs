# Oboron

[![Crates.io](https://img.shields.io/crates/v/oboron.svg)](https://crates.io/crates/oboron)
[![Documentation](https://docs.rs/oboron/badge.svg)](https://docs.rs/oboron)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.77-blue.svg)](https://blog.rust-lang.org/2023/11/16/Rust-1.77.0.html)
[![oboron-cli](https://img.shields.io/crates/v/oboron-cli?label=oboron-cli)](https://crates.io/crates/oboron-cli)
[![oboron-py](https://img.shields.io/pypi/v/oboron?label=oboron-py)](https://pypi.org/project/oboron/)

Oboron is a general-purpose symmetric encryption library focused on
developer ergonomics:
- *String in, string out*: Encryption and encoding are bundled into
  one seamless process
- *Standardized interface*: Multiple encryption algorithms accessible
  through the same API
- *[Unified key management](#key-management)*: A single 512-bit key
  works across all schemes with internal extraction to algorithm-specific
  keys
- *[Prefix-focused entropy](#referenceable-prefixes)*: Maximizes
  entropy in initial characters for referenceable short prefixes (similar
  to Git commit hashes)

In essence, Oboron provides an accessible interface over established
cryptographic primitives—implementing AES-CBC, AES-GCM-SIV, and AES-SIV—
with a focus on developer ergonomics and output characteristics. Each
scheme follows a consistent naming pattern that encodes its security
properties, making it easier to choose the right tool without deep
cryptographic expertise: e.g., `aasv` = Authenticated + Avalanche
property + SiV algorithm (AES-SIV).

Key Advantages:
- *Referenceable prefixes*: High initial entropy enables Git-like short
  IDs
- *Simplified workflow*:
  - No manual encoding/decoding between encryption stages
  - No decoding encryption keys from env vars to bytes
- *Performance optimized*

## Contents

- [Quick Start](#quick-start)
- [Formats](#formats)
- [Algorithm](#algorithm)
- [Key Management](#key-management)
- [Properties](#properties)
- [Rust API Overview](#rust-api-overview)
- [Applications](#applications)
- [Compatibility](#compatibility)
- [Related Crates](#related-crates)
- [Getting Help](#getting-help)
- [License](#license)
- [Appendix: Obtext Lengths](#appendix-obtext-lengths)

## Quick Start

Add to your `Cargo.toml`:
```toml
[dependencies]
oboron = "1.0" # default features
# or with minimal features:
# oboron = { version = "1.0", features = ["aasv", "apsv"] }
```

Generate your 512-bit key (86 base64 characters) using the keygen script
(always included with the crate, not feature-gated):
```shell
cargo run --bin keygen
```
or in your code:
```rust
let key = oboron::generate_key();
```
then save the key as an environment variable.

Use AasvC32 (a secure scheme, 256-bit encrypted with AES-SIV, encoded
using Crockford's base32 variant) for enc/dec:
```rust
use oboron::AasvC32;

let key = env::var("OBORON_KEY")?; // get the key

let ob = AasvC32::new(&key)?; // create codec instance

let ot = ob.enc("hello, world")?; // encrypt+encode
let pt2 = ob.dec(&ot)?; // decode+decrypt

println!("obtext: {}", ot);
// "obtext: cbv74r1m7a7cf8n6gzdy6tf2vjddkhwdtwa5ssgv78v5c1g"

assert_eq!(pt2, "hello, world");
```

*Version 1.0*: This release marks API stability. Oboron follows semantic
versioning, so 1.x releases will maintain backward compatibility.

## Formats

An Oboron *format* represents the full transformation of the plaintext to
the encrypted text (obtext), including:

1. *Encryption*: Plaintext UTF-8 string encrypted to ciphertext bytes
   using a cryptographic algorithm
2. *Encoding*: The binary payload is encoded to a string representation

### Scheme + Encoding = Format

Formats combine a scheme (cryptographic algorithm) with an encoding
(string representation):
- *Scheme*: Cryptographic algorithm + mode + parameters (e.g., `aasv`)
- *Encoding*: String representation method (e.g., `c32`)
- *Format*: Scheme + encoding = complete transformation (e.g.,
  `aasv.c32`)


Given an encryption key, the format thus uniquely specifies the complete
transformation from a plaintext string to an encoded *obtext* string.

Formats are represented by identifiers:
- `ob:{scheme}.{encoding}`, (URI-like syntax, e.g., `ob:aasv.c32`),
- `{scheme}.{encoding}`, when the context is clear

**API Notes**:
- The `ob:` namespace prefix is not used in the `oboron` API.
  Formats like `aasv.c32` are used directly.
- The public interface uses `enc`/`dec` names for methods and functions.
  Thus the `enc` operation comprises the full process, including the
  encryption and encoding stages.

### Encodings

- `b32` - standard base32: Balanced compactness and readability,
  uppercase alphanumeric (RFC 4648 Section 6)
- `c32` - Crockford base32: Balanced compactness and readability,
  lowercase alphanumeric; designed to avoid accidental obscenity
- `b64` - standard URL-safe base64: Most compact, case-sensitive,
  includes `-` and `_` characters (RFC 4648 Section 5)
- `hex` - hexadecimal: Slightly faster performance (~2-3%), longest
  output

> **FAQ:** *Why use Crockford's base32 instead of the RFC standard one?*
>
> Crockford's base32 alphabet minimizes the probability of accidental
> obscenity words, which is important when using with short prefixes:
> Whereas accidental obscenity is not an issue when working with full
> encrypted outputs (as any such words would be buried as substrings of a
> 28+ character long obtext), it may become a concern when using short
> prefixes as references or quasi-hash identifiers.

### Schemes

Schemes define the encryption algorithm and its properties, classified
into *tiers*:

#### Scheme Tiers

- **`a` - Authenticated**
  - Provide both confidentiality and integrity protection
  - Examples: `ob:aasv`, `ob:aags`, `ob:apsv`, `ob:apgs`
  - *Always prefer `a`-tier schemes for security-critical applications*

- **`u` - Unauthenticated**
  - Provide confidentiality only (no integrity protection)
  - Example: `ob:upbc`
  - Suitable when integrity is verified externally or not required
  - *Warning*: Vulnerable to ciphertext tampering

- **`z` - Obfuscation tier**
  - *Not cryptographically secure* - for non-security use only
  - Example: `ob:zrbcx` - deterministic obfuscation with constant IV
  - Requires explicit `ztier` feature flag (not enabled by default)
  - See [Z_TIER.md](Z_TIER.md) for details and warnings

#### Scheme Properties

The second letter of the scheme ID further describe the properties of the
scheme:
- **`.a..` - avalanche, deterministic**
  - *deterministic* => same plaintext always produces same obtext
  - *avalanche* => entropy uniformly distributed; change in any byte of
    plaintext completely changes the entire obtext (hash-like property)
  - Examples: `ob:aasv`, `ob:aags`
- **`.p..` - probabilistic**
  - Different output each time
  - Examples: `ob:apsv`, `ob:apgs`, `ob:upbc`

#### Scheme Cryptographic Algorithms

The remaining two letters in scheme IDs indicate the algorithm:
- `gs` = AES-GCM-SIV
- `sv` = AES-SIV
- `bc` = AES-CBC

#### Summary Table

| Scheme     | Algorithm   | Deterministic? | Authenticated? | Notes                              |
| :--------- | :---------- | :------------- | :------------- | :--------------------------------- |
| `ob:aasv`  | AES-SIV     | Yes            | Yes            | General purpose, deterministic |
| `ob:aags`  | AES-GCM-SIV | Yes            | Yes            | Deterministic alternative |
| `ob:apsv`  | AES-SIV     | No             | Yes            | Maximum privacy protection |
| `ob:apgs`  | AES-GCM-SIV | No             | Yes            | Probabilistic alternative |
| `ob:upbc`  | AES-CBC     | No             | No             | Unauthenticated - use with caution |

Key Concepts:
* *Deterministic:* Same input (key + plaintext) always produces same
  output. Useful for idempotent operations, lookup keys, caching, or
  hash-like references.
* *Probabilistic:* Incorporates a random nonce, producing different
  ciphertexts for identical plaintexts.  Standard for most cryptographic
  use cases (non-cached, not used as hidden references).
* *Authenticated:* Ciphertext is tamper-proof.  Any modification (even a
  single bit flipped) results in decryption failure.

#### Choosing a Scheme

- `ob:aasv`: General-purpose secure encryption with deterministic output
  and compact size
- `ob:apsv`: Maximum privacy with probabilistic output (larger size due
  to nonce)
- `ob:upbc`: Only when integrity is handled externally

> *Note on encryption strength*: All `a`-tier and `u`-tier schemes use
  256-bit AES encryption. The `z`-tier uses 128-bit AES for performance
  in non-security contexts.


## Algorithm

Oboron combines encryption and encoding in a single operation, requiring
specific terminology:

- **enc**: Combines encryption and encoding stages
- **dec**: Combines decoding and decryption stages
- **obtext**: The output of the `enc` operation (encryption + encoding),
  distinct from cryptographic ciphertext

The cryptographic ciphertext (bytes, not string) is an internal
implementation detail, not exposed in the public API.

The high-level process flow is:
```
enc operation:
    [plaintext] (string) -> encryption -> [ciphertext] (bytes) -> encoding -> [obtext] (string)

dec operation:
    [obtext] (string) -> decoding -> [ciphertext] (bytes) -> decryption -> [plaintext] (string)
```

The above diagram is conceptual; actual implementation includes
scheme-specific steps like scheme byte appending and (for `z`-tier
schemes only) optional ciphertext prefix restructuring. With this
middle-step included, the diagram becomes:
```
enc operation:
    [plaintext] -> encryption -> [ciphertext] -> oboron pack -> [payload] -> encoding -> [obtext] 

dec operation:
    [obtext] -> decoding -> [payload] -> oboron unpack -> [ciphertext] -> decryption -> [plaintext]
```

In `a`-tier and `u`-tier schemes, the difference between the payload and
the ciphertext is in the 2-byte scheme marker that is appended to the
ciphertext, enabling scheme autodetection in decoding.

### Padding Design

Oboron's CBC schemes use a custom padding scheme optimized for UTF-8
strings:
- Uses 0x01 byte for padding (Unicode control character, never valid in
  UTF-8)
- No padding needed when plaintext ends at block boundary
- 5% performance improvement over PKCS#7
- Smaller output size compared to PKCS#7

**Rationale:** Oboron exclusively processes UTF-8 strings, not arbitrary
binary data.  The 0x01 padding byte can never appear in valid UTF-8
input, ensuring unambiguous decoding.  Therefore, under the UTF-8 input
constraint, this padding is functionally equivalent to PKCS#7 and does
not weaken security.  The UTF-8 input constraint is guaranteed by the
Rust type system - all `enc` functions and methods accept a `&str`,
therefore passing an input that is not valid UTF-8 would not be allowed
by the Rust compiler.  This UTF-8 guarantee is enforced at compile time,
eliminating padding ambiguity errors at runtime.


## Key Management

### Single Master Key Model

Oboron uses a single 512-bit master key partitioned into
algorithm-specific subkeys:

- `ob:aags`, `ob:apgs`: use the first 32 bytes (256 bits) for AES-GCM-SIV
  key
- `ob:aasv`, `ob:apsv`: use the full 64 bytes (512 bits) for AES-SIV key
- `ob:upbc` uses the last 32 bytes (256 bits) for AES-CBC key

**Design Rationale:** This approach prioritizes low latency for
short-string encryption.  No hash-based KDF (e.g., HKDF) is used, as this
would dominate runtime for intended workloads.

The master key never leaves your application. Algorithm-specific keys
are extracted on-the-fly and never cached or stored.

> **FAQ:** *Why use a single key across all schemes?*
>
> - Simplifies deployment: Store one key instead of multiple
> - Reduces errors: No risk of mismatching keys to algorithms

### Key Format

The default key input format is base64. This is consistent with Oboron's
strings-first API design. As any production use will typically read the
key from an environment variable, this allows the string format to be
directly fed into the constructor.

The base64 format was chosen for its compactness, as an 86-character
base64 key is easier to handle manually (in secrets or environment
variables management UI) than a 128-character hex key.

While any 512-bit key is accepted by Oboron, the keys generated with
`oboron::generate_key()` or `cargo run --bin keygen` do not include any
dashes or underscores, in order to ensure the keys are double-click
selectable, and to avoid any human visual parsing due to underscores.

#### Valid Base64 Keys

**Important technical detail:** Not every 86-character base64 string is a
valid 512-bit key.  Since 512 bits requires 85.3 bytes when
base64-encoded, the final character is constrained by padding
requirements. When generating keys, it is recommended to use one of the
following methods:
1. use Oboron's key generator (`oboron::generate_key()` or
  `cargo run --bin keygen`)
2. generate random 64 bytes, then encode as base64
3. generate random 128 hex characters, then convert hexadecimal to base64

#### Alternative Key Interfaces

For specialized use-cases:
- Enable `hex-keys` feature for hexadecimal key input
- Enable `bytes-keys` feature for raw byte key input
- Enable `keyless` feature for testing/development (uses hardcoded key -
  no security)

## Properties

### Referenceable Prefixes

If you've used Git, you're already familiar with prefix entropy: you can
reference commits with just the first 7 characters of their SHA1 hash
(like `git show a1b2c3d`). This works because cryptographic hashes
distribute entropy evenly across all characters.

Oboron schemes exhibit similar prefix quality.
Consider these comparisons:

**Short Reference Strength:**
- Git SHA1 (7 hex chars): 28 bits of entropy
- Oboron (6 base32 chars): 30 bits of entropy
- Oboron (7 base32 chars): 35 bits of entropy

**Collision Resistance:**
For a 1-in-a-million chance of two items sharing the same prefix:
- Git 7-char prefix (28 bits): After ~38 items
- Oboron 6-char prefix (30 bits): After ~52 items
- Oboron 7-char prefix (35 bits): After ~262 items

(These estimates assume uniform ciphertext distribution under a fixed
key.)

**Practical Implications:**
In a system with 1,000 unique items using 7-character Oboron prefixes:
- Collision probability: ~0.007% (1 in 14,000)
- In a system with 10,000 items: ~0.7% (1 in 140)

This enables Git-like workflows for moderate-scale systems: database IDs,
URL slugs, or commit references that are both human-friendly and
cryptographically robust for everyday use cases.

### Deterministic Injectivity

Comparing the prefix collision resistance in the previous section, Oboron
and standard hashing algorithms were compared against each other.  But
when we consider the full output, then they are not on the same plane:
while SHA1 and SHA256 collision probabilities are astronomically small,
they are never zero, and the birthday paradox risk can become a factor
in large systems even with the full hash.  Oboron, on the other hand, is
a symmetric encryption library, and as such it is collision free
(although applying this label to an encryption library is awkward):
for a fixed key and within the block-cipher domain limits, Oboron is
injective (one-to-one), i.e. two different inputs can never result in the
same output.

### Performance Comparison

Oboron is optimized for performance with short strings, often exceeding
both SHA256 and JWT performance while providing reversible encryption.

> **Note:** As a general-purpose encryption library, Oboron is not a
> replacement for either JWT or SHA256.  We use those two for baseline
> comparison, as they are both standard and highly optimized libraries.

| Scheme     | 8B Encode | 8B Decode | Security      | Use Case                        |
|------------|----------:|-----------|---------------|---------------------------------|
| `ob:aasv`  | 334 ns    | 364 ns    | Secure + Auth | Balanced performance + security |
| JWT        | 550 ns    | 846 ns    | Auth only`*`  | Signature without encryption    |
| SHA256     | 191 ns    | N/A       | One-way       | Hashing only                    |

`*` **Note**: JWT baseline (HMAC-SHA256) provides authentication without
encryption.  Despite comparing against our stronger **`a`-tier** (secure
+ authenticated), Oboron maintains performance advantages while providing
full confidentiality.

More detailed benchmark results are presented in a separate document:
- [BENCHMARKS.md](BENCHMARKS.md).
Data from JWT and SHA256 benchmarks performed on the same machine is
available here:
- [BASELINE_BENCHMARKS.md](BASELINE_BENCHMARKS.md)

**Performance advantages:**
- All Oboron authenticated schemes outperform JWT for both encoding and
  decoding

### Output Length Comparison

| Method        | Small string output length |
|---------------|----------------------------|
| `ob:aasv`     | 31-48 characters           |
| `ob:apsv`     | 56-74 characters           |
| SHA256        | 64 characters              |
| JWT           | 150+ characters            |

A more complete output length comparison is given in the
[Appendix](#appendix-obtext-lengths).

## Rust API Overview

Oboron provides multiple API styles supporting different use cases.  For
most production applications, *compile-time format selection* (option 1
below) offers the best combination of performance, type safety, and
clarity.

### 1. Compile-time Format Selection (Recommended for Production)

Use fixed-format types when formats are known at compile time for optimal
performance and type safety:
```rust
use oboron::ApgsB64;

let key = env::var("OBORON_KEY")?;
let apgs = ApgsB64::new(&key)?;

let ot = apgs.enc("hello")?;
let pt2 = apgs.dec(&ot)?;
assert_eq!(pt2, "hello");
```

Available types include all combinations of scheme variants (e.g.,
`Upbc`, `Aags`, `Apgs`, `Aasv`, `Apsv`) with encoding specifications
(`B64`, `Hex`, `B32`, or `C32`), and concatenates the two in struct
names, for example:
- `UpbcHex` - encoder for `ob:upbc.hex` format
- `AagsB64` - encoder for `ob:aags.b64` format
- `AasvC32` - encoder for `ob:aasv.c32` format.

### 2. Runtime Format Selection (`Ob`)

When format specification at runtime is required, use `Ob`:
```rust
use oboron::Ob;

let key = env::var("OBORON_KEY")?;
let ob = Ob::new("aasv.b64", &key)?;

let ot = ob.enc("hello")?;
let pt2 = ob.dec(&ot)?;
assert_eq!(pt2, "hello");
```
The format can also be changed with mutable instances:
```rust
let mut ob = Ob::new("aags.b64", &key)?;
let ot = ob.enc("hello")?; // aags.b64 obtext

// Format modification
ob.set_format("apsv.hex")?;
let ot_hex = ob.enc("world")?; // apsv.hex obtext
```

`Ob` offers another advantage over fixed-format types like `AasvC32`:
the `autodec()` method.
```rust
let ob = Ob::new("aasv.c32, &key);
let pt2 = ob.autodec(&some_ot)
```
This method will decode the obtext in any format, as long as it was
encrypted with the same key.

Note:
While `Omnib` (described below) also has an `autodec()` method, `Ob`'s
variant will try the current encoding first (`c32` in the example above),
before resorting to a heuristic logic combined with a trial and error
guessing the encoding that `Omnib` uses exclusively, and will therefore
have better performance than `Omnib::autodec()` if the encoding is known.

### 3. Multiple Format Support (`Omnib`)

`Omnib` differs in format management and provides comprehensive
`autodec()` functionality.

**Multi-Format Workflow:** Designed for simultaneous work with different
formats, requiring format specification in each operation:
```rust
use oboron::Omnib;

let omb = Omnib::new(&key)?;

// Format specification per operation
let ot = omb.enc("test", "apsv.b64");
let pt2 = omb.dec(&ot, "apsv.b64");
let pt_other = omb.dec(&other, "aasv.c32");

// Autodecode when format is unknown
let pt2 = omb.autodec(&ot);
```

Note performance implications: autodetection uses trial-and-error across
encodings, with worst-case performance ~3x slower than known-format dec
operations.

### Using Format Constants

For type safety and discoverability, use the provided format constants
instead of string literals:

```rust
use oboron::{Ob, Omnib, AASV_B64, AASV_HEX};

let key = oboron::generate_key();

// With Ob (runtime format selection)
let ob = Ob::new(AASV_B64, &key)?;

// With Omnib (multi-format operations)
let omb = Omnib::new(&key)?;
let ot_b64 = omb.enc("data", AASV_B64)?;
let ot_hex = omb.enc("data", AASV_HEX)?;
```

Available constants:
- `UPBC_C32`, `UPBC_B32`, `UPBC_B64`, `UPBC_HEX`
- `AAGS_C32`, `AAGS_B32`, `AAGS_B64`, `AAGS_HEX`
- `APGS_C32`, `APGS_B32`, `APGS_B64`, `APGS_HEX`
- `AASV_C32`, `AASV_B32`, `AASV_B64`, `AASV_HEX`
- `APSV_C32`, `APSV_B32`, `APSV_B64`, `APSV_HEX`
- Testing:  `MOCK1_C32`, `MOCK2_B32`, etc.
- Legacy: `LEGACY`

### Advanced: `Format` Objects

`Format` structs provide a more fine-grained type safety than format
string constants:
```rust
use oboron::{Ob, Format, Scheme, Encoding};

let format = Format::new(Scheme::Aasv, Encoding::B64);
let ob = Ob::new(format, &key)?;
```

### Typical Production Use

For compile-time known schemes and encodings, however, static types
provide optimal performance, concise syntax, and strongest type
guarantees:
```rust
use oboron::AasvB64;
let ob = AasvB64::new(&key)?;
let ot = ob.enc("secret")?;
```
The format is built into the struct, no format strings, constants, or
Format structs are needed.

### Feature Flags

Oboron exposes a small set of optional features so you can opt out of
schemes you don't need. This is mainly useful for WebAssembly builds
where bundle size matters.

**Default:** all five secure production-ready schemes (`aasv`, `apsv`,
`aags`, `apgs`, `upbc`) plus transitional `base64-keys` support (to be
removed at 1.0).

Available features:

- **`secure-schemes`** — bundles all five secure schemes (default).
- **`aasv`**, **`apsv`**, **`aags`**, **`apgs`**, **`upbc`** —
  individual secure schemes; enable only what you need to minimize
  binary size.
- **`zrbcx`** — insecure z-tier scheme for fast obfuscation only.
  Off by default.
- **`legacy`** — backward-compatibility for early-adopter encrypted
  data. Off by default.
- **`mock`** — mock1, mock2, zmock1 testing schemes (no encryption).
- **`keyless`** — hardcoded-key constructors for tests/obfuscation.
- **`unchecked-utf8`** — skip post-decrypt UTF-8 validation. Wrong-key
  decrypts return garbage instead of `InvalidUtf8`. Use only in
  trusted-source scenarios.
- **`base64-keys`** *(deprecated, default-on)* — base64 string keys
  and `HARDCODED_KEY_BASE64`. Will be removed before 1.0; migrate to
  hex.

Hex and raw-byte key input are always available — no feature flag
needed (`AasvC32::new(&hex_key)`, `AasvC32::from_bytes(&key_bytes)`).

Examples:

```toml
# Minimal: only aasv (deterministic AES-SIV).
oboron = { version = "1.0", default-features = false, features = ["aasv"] }

# Both SIV schemes.
oboron = { version = "1.0", default-features = false, features = ["aasv", "apsv"] }

# Default behavior but without the deprecated base64 keys.
oboron = { version = "1.0", default-features = false, features = ["secure-schemes"] }
```

At least one scheme feature must be enabled — building with no
features will fail with a compile error.

### The `ObtextCodec` Trait

All types except `Omnib` implement the `ObtextCodec` trait, providing a
consistent interface:

- `enc(plaintext: &str) -> Result<String, Error>` - Encode plaintext to
  obtext
- `dec(obtext: &str) -> Result<String, Error>` - Decode with automatic
  scheme detection
- `scheme() -> Scheme` - Current scheme
- `encoding() -> Encoding` - Current encoding
- `format() -> Format` - Current format (scheme + encoding)

### Working with Keys

```rust
// main interface: pass a 128-char hex key string.
let ob = AagsB64::new(&env::var("OBORON_KEY")?);       // hex key (or base64, deprecated)
// explicit hex constructor:
let ob = AagsB64::from_hex_key(&env::var("HEX_KEY")?); // hex key
// raw bytes:
let ob = AagsB64::from_bytes(&key_bytes)?;             // raw bytes key
// with "keyless" feature enabled:
let ob = AagsB64::new_keyless()?;              // insecure/testing only
```

**Warning**: `new_keyless()` uses the publicly available hardcoded key
providing no security. Use only for testing or obfuscation contexts where
encryption is not required.  The `keyless` feature must be enabled to use
the hardcoded key.


## Applications

While Oboron serves as a general-purpose encryption library with its
"string in, string out" API, its combination of properties—particularly
prefix entropy and compactness—enables specialized applications:

- *Git-like short IDs* - High-entropy prefixes for unique references
- *URL-friendly state tokens* - Encrypt web application state into
  compact URLs
- *No-lookup captcha systems* - Server issues encrypted challenge,
  verifies without database lookup
- *Database ID obfuscation* - Hide sequential IDs while maintaining
  reversibility
- *Compact authentication tokens* - Efficient alternative to JWT for
  simple use cases where JWT may be overkill
- *General-purpose symmetric encryption* - Straightforward string-based
  API

### Comparison with Alternatives

| Use Case            | Traditional Solution | Oboron Approach                         |
|---------------------|----------------------|-----------------------------------------|
| Short unique IDs    | UUIDv4 (36 chars)    | `ob:aasv.c32` (34-47 chars, reversible) |
| URL parameters      | JWT (150+ chars)     | `ob:aasv.b64` (4.5x smaller, 4x faster) |
| Database ID masking | Hashids (not secure) | Proper encryption                       |

### API Simplification

Oboron simplifies symmetric encryption compared to lower-level
cryptographic libraries:

**Before (libsodium/ring - complex, byte-oriented):**
```rust
// Manual key and nonce management
let key = generic_hash::Key::generate();
let nonce = randombytes::randombytes(24);
let ciphertext = secretbox::seal(plaintext, &nonce, &key)?;

// Manual encoding required
let encoded = base64::encode(ciphertext);
```

**After (Oboron - simplified, string-oriented):**
```rust
let ob = AasvC32::new(&env::var("OBORON_KEY")?);
let ot = ob.enc("Hello World")?;
```

**Benefits:**
- No manual hex/base64 encoding/decoding
- Keys as base64 strings (no byte array management)
- Built-in nonce generation where applicable
- Consistent error handling
- Single dependency vs multiple cryptographic crates

**When Oboron is appropriate:**
- General symmetric encryption requirements
- Need for compact, referenceable outputs
- Simplified key management (single 512-bit key)
- String-to-string interface preferred

**When lower-level libraries may be preferable:**
- Need for specific algorithms (ChaCha20-Poly1305, etc.)
- Streaming encryption of large files
- Asymmetric encryption cryptography requirements
- Specialized protocols (Signal, Noise, etc.)

### Pattern Implementation Examples

#### Database ID Obfuscation

**Before (Hashids - insecure, encoding only):**
```rust
let hashids = Hashids::new("salt", 6);
let obfuscated = hashids.encode(&[123]); // "k2d3e4"
```

**After (Oboron - encrypted, reversible, secure):**
```rust
let ob = AasvC32::new(&env::var("OBORON_KEY")?);
let ot = ob.enc("user:123")?; // "uf2glao2xd7f"
// Can include namespace prefixes to prevent type confusion
```

**Advantages:**
- Encodes arbitrary strings (vs integer-only encoding)
- Actual encryption (not just encoding)
- Can embed metadata (e.g., `"user:"`, `"order:"` prefixes, or JSON)
- Referenceable short prefixes
- Tamper-proof with authenticated schemes

#### State Tokens

**Before (JWT - large, complex):**
```rust
// 150+ characters, requires JWT library
let token = encode(&Header::default(), &claims, &EncodingKey)?;
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**After (Oboron - compact, simple):**
```rust
let ob = AagsC32::new(&env::var("OBORON_KEY")?);
let state = serde_json::to_string(&claims)?;
let token = ob.enc(&state)?; // ~50 characters
// "b4g9lao2xd7fnbq5z53cb63ukc"
```

**When to prefer Oboron over JWT:**
- Simple symmetric encryption requirements
- Compact size important (URL parameters)
- JWT standardization not required
- Performance considerations

**When JWT may be preferable:**
- Industry-standard tokens required
- Public/private key signatures needed
- Complex claims with registered names

## Compatibility

Oboron implementations maintain full cross-language compatibility:
- Identical encryption algorithms and key management
- Consistent encoding formats and scheme specifications
- Interoperable encoded values across Rust, Python, and Go (latter
  currently under development)

All implementations must pass the common
[test vectors](tests/test-vectors.jsonl)

## Related Crates

- [`oboron-cli`](https://crates.io/crates/oboron-cli) — Command-line interface (`ob` and `obz` binaries)
- [`oboron-py`](https://crates.io/crates/oboron-py) — Python bindings ([PyPI](https://pypi.org/project/oboron/))

## Getting Help

- [Documentation](https://docs.rs/oboron)
- [Issues](https://gitlab.com/oboron/oboron-rs/-/issues) (GitLab)

## License

Licensed under the MIT license ([LICENSE](LICENSE)).

## Changelog

See [CHANGELOG.md](https://gitlab.com/oboron/oboron-rs/-/blob/master/CHANGELOG.md) for release history.

## Appendix: Obtext Lengths

`mock1` is a non-cryptographic scheme used for testing, whose ciphertext
is equal to the plaintext bytes (identity transformation). It is
included in the tables below as baseline.

(Note: the `mock1` scheme is feature gated: use it by enabling the `mock`
feature)

## Base32 encoding (b32/c32)

| Format    | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
|-----------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.b32 | 10 | 16 |  23 |  29 |  42 |  55 | 106 |  208 |
|  aags.b32 | 36 | 42 |  48 |  55 |  68 |  80 | 132 |  234 |
|  aasv.b32 | 36 | 42 |  48 |  55 |  68 |  80 | 132 |  234 |
|  apgs.b32 | 55 | 61 |  68 |  74 |  87 | 100 | 151 |  253 |
|  apsv.b32 | 61 | 68 |  74 |  80 |  93 | 106 | 157 |  260 |
|  upbc.b32 | 55 | 55 |  55 |  55 |  80 |  80 | 132 |  234 |
| zrbcx.b32 | 29 | 29 |  29 |  29 |  55 |  55 | 106 |  208 |

## Base64 Encoding (b64)

| Format    | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
|-----------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.b64 |  8 | 14 |  19 |  24 |  35 |  46 |  88 |  174 |
|  aags.b64 | 30 | 35 |  40 |  46 |  56 |  67 | 110 |  195 |
|  aasv.b64 | 30 | 35 |  40 |  46 |  56 |  67 | 110 |  195 |
|  upbc.b64 | 46 | 46 |  46 |  46 |  67 |  67 | 110 |  195 |
|  apgs.b64 | 46 | 51 |  56 |  62 |  72 |  83 | 126 |  211 |
|  apsv.b64 | 51 | 56 |  62 |  67 |  78 |  88 | 131 |  216 |
| zrbcx.b64 | 24 | 24 |  24 |  24 |  46 |  46 |  88 |  174 |

## Hex Encoding (hex)

| Format    | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
| ----------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.hex | 12 | 20 |  28 |  36 |  52 |  68 | 132 |  260 |
|  aags.hex | 44 | 52 |  60 |  68 |  84 | 100 | 164 |  292 |
|  aasv.hex | 44 | 52 |  60 |  68 |  84 | 100 | 164 |  292 |
|  upbc.hex | 68 | 68 |  68 |  68 | 100 | 100 | 164 |  292 |
|  apgs.hex | 68 | 76 |  84 |  92 | 108 | 124 | 188 |  316 |
|  apsv.hex | 76 | 84 |  92 | 100 | 116 | 132 | 196 |  324 |
| zrbcx.hex | 36 | 36 |  36 |  36 |  68 |  68 | 132 |  260 |
