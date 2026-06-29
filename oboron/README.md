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
  works across all schemes — used directly by the SIV family and via
  HKDF derivation for the GCM-SIV family
- *[Prefix-focused entropy](#referenceable-prefixes)*: Maximizes
  entropy in initial characters for referenceable short prefixes (similar
  to Git commit hashes)

In essence, Oboron provides an accessible interface over established
cryptographic primitives—implementing AES-GCM-SIV and AES-SIV—with a
focus on developer ergonomics and output characteristics. Each scheme
follows a consistent naming pattern that encodes its security
properties, making it easier to choose the right tool without deep
cryptographic expertise: e.g., `dsiv` = Deterministic + SiV algorithm
(AES-SIV).

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
- [Performance Tuning](#performance-tuning)
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
# oboron = { version = "1.0", features = ["dsiv", "psiv"] }
```

Generate your 512-bit key (128 hex characters) using the keygen script
(always included with the crate, not feature-gated):
```shell
cargo run --bin keygen
```
or in your code:
```rust
let key = oboron::generate_key();
```
then save the key as an environment variable.

Use DsivC32 (a secure scheme, 256-bit encrypted with AES-SIV, encoded
using Crockford's base32 variant) for enc/dec:
```rust
use oboron::DsivC32;

let key = env::var("OBORON_KEY")?; // get the key

let ob = DsivC32::new(&key)?; // create codec instance

let ot = ob.enc("hello, world")?; // encrypt+encode
let pt2 = ob.dec(&ot)?; // decode+decrypt

println!("obtext: {}", ot);
// "obtext: cbv74r1m7a7cf8n6gzdy6tf2vjddkhwdtwa5ssgv78v5c1g"

assert_eq!(pt2, "hello, world");
```

## Formats

An Oboron *format* represents the full transformation of the plaintext to
the encrypted text (obtext), including:

1. *Encryption*: Plaintext UTF-8 string encrypted to ciphertext bytes
   using a cryptographic algorithm
2. *Encoding*: The binary payload is encoded to a string representation

### Scheme + Encoding = Format

Formats combine a scheme (cryptographic algorithm) with an encoding
(string representation):
- *Scheme*: Cryptographic algorithm + mode + parameters (e.g., `dsiv`)
- *Encoding*: String representation method (e.g., `c32`)
- *Format*: Scheme + encoding = complete transformation (e.g.,
  `dsiv.c32`)


Given an encryption key, the format thus uniquely specifies the complete
transformation from a plaintext string to an encoded *obtext* string.

Formats are represented by identifiers:
- `ob:{scheme}.{encoding}`, (URI-like syntax, e.g., `ob:dsiv.c32`),
- `{scheme}.{encoding}`, when the context is clear

**API Notes**:
- The `ob:` namespace prefix is not used in the `oboron` API.
  Formats like `dsiv.c32` are used directly.
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

Schemes define the encryption algorithm and its properties. Oboron is
authenticated-only: every scheme provides both confidentiality and
integrity protection.

> The unauthenticated (`upcbc`) and obfuscation (`zdcbc`) schemes live
> in the separate [`obu`](https://gitlab.com/oboron/obu-rs) crate, which
> shares no code with oboron's authenticated core.

#### Scheme Properties

The first letter of the scheme ID describes the determinism property of
the scheme:
- **`d...` - deterministic**
  - *deterministic* => same plaintext always produces same obtext
  - entropy uniformly distributed; change in any byte of plaintext
    completely changes the entire obtext (hash-like property)
  - Examples: `dsiv`, `dgcmsiv`
- **`p...` - probabilistic**
  - Different output each time
  - Examples: `psiv`, `pgcmsiv`

#### Scheme Cryptographic Algorithms

The remaining letters in scheme IDs indicate the algorithm:
- `gcmsiv` = AES-GCM-SIV
- `siv` = AES-SIV

#### Summary Table

| Scheme     | Algorithm   | Deterministic? | Notes                          |
| :--------- | :---------- | :------------- | :----------------------------- |
| `dsiv`     | AES-SIV     | Yes            | General purpose, deterministic |
| `dgcmsiv`  | AES-GCM-SIV | Yes            | Deterministic alternative      |
| `psiv`     | AES-SIV     | No             | Maximum privacy protection     |
| `pgcmsiv`  | AES-GCM-SIV | No             | Probabilistic alternative      |

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

- `dsiv`: General-purpose secure encryption with deterministic output
  and compact size
- `psiv`: Maximum privacy with probabilistic output (larger size due
  to nonce)

> *Note on encryption strength*: All oboron schemes use 256-bit AES
  encryption.


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

The obtext payload is exactly the AEAD output of the chosen scheme —
there is no oboron-specific framing. The scheme is always supplied by
the caller via the format, so no marker is embedded in the obtext.


## Key Management

### Single Master Key Model

Oboron uses a single 512-bit (64-byte) master key. Each scheme family
obtains its key material from it differently:

- `dsiv`, `psiv` (AES-SIV): the full 64-byte master is used directly as
  the AES-SIV key — no derivation. AES-SIV internally splits it into a
  256-bit S2V/CMAC authentication subkey (bytes 0–31) and a 256-bit
  CTR-mode encryption subkey (bytes 32–63).
- `dgcmsiv`, `pgcmsiv` (AES-GCM-SIV): a 32-byte AES-256-GCM-SIV key is
  derived with `HKDF-Expand(PRK = master, info = "gcmsiv", L = 32)`
  (HMAC-SHA-256), shared by both. HKDF-Extract is omitted — the 512-bit
  master is already a uniform pseudorandom key.

**Design Rationale:** the SIV family is the small-input choice, so it
skips key derivation entirely to keep latency low; the GCM-SIV family
wins on larger inputs, where the one-time HKDF-Expand cost is negligible
against the AEAD work. Sharing one key across each family's
deterministic and probabilistic schemes is safe because both AEADs are
nonce-misuse-resistant.

The master key never leaves your application; the derived GCM-SIV key
material is held only transiently and never cached or stored.

> **FAQ:** *Why use a single key across all schemes?*
>
> - Simplifies deployment: Store one key instead of multiple
> - Reduces errors: No risk of mismatching keys to algorithms

### Key Format

The canonical key input format is hex: a 128-character lowercase string
encoding the 512-bit master key. Hex was chosen for its strict
alphabet — no padding edge cases, no `-`/`_` characters, double-click
selectable in any terminal — and is what `oboron::generate_key()` and
`cargo run --bin keygen` produce. This is consistent with Oboron's
strings-first API design: typical production use reads the key from an
environment variable, and the string can be passed straight into any
constructor.

Raw byte keys are also supported unconditionally:
```rust
let ob = DsivC32::from_bytes(&key_bytes)?;
```

#### Keyless mode

Enable the `keyless` feature for testing or non-security obfuscation —
it provides `::new_keyless()` constructors that use a publicly
documented hardcoded key. Not for production.

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

Oboron is optimized for performance with short strings: it
comfortably outperforms JWT on both encode and decode while staying
in the same ballpark as a bare SHA256 digest — despite providing
reversible, *authenticated* encryption rather than a one-way hash.
Figures below are 8-byte inputs from a native build
(`-C target-cpu=native`; see [Performance Tuning](#performance-tuning)).

> **Note:** As a general-purpose encryption library, Oboron is not a
> replacement for either JWT or SHA256.  We use those two for baseline
> comparison, as they are both standard and highly optimized libraries.

| Scheme       | 8B Encode | 8B Decode | Security      | Use Case                        |
|--------------|----------:|----------:|---------------|---------------------------------|
| `dsiv`       | 263 ns    | 237 ns    | Secure + Auth | Balanced performance + security |
| JWT          | 696 ns    | 1095 ns   | Auth only`*`  | Signature without encryption    |
| SHA256       | 124 ns    | N/A       | One-way       | Hashing only                    |

`*` **Note**: JWT baseline (HMAC-SHA256) provides authentication without
encryption.  Despite comparing against our stronger authenticated
encryption (confidentiality + integrity), Oboron maintains performance
advantages while providing full confidentiality.

More detailed benchmark results are presented in a separate document:
- [BENCHMARKS.md](BENCHMARKS.md).
Data from JWT and SHA256 benchmarks performed on the same machine is
available here:
- [BASELINE_BENCHMARKS.md](BASELINE_BENCHMARKS.md)

**Performance advantages:**
- All Oboron authenticated schemes outperform JWT for both encoding and
  decoding

### Output Length Comparison

| Method          | Small string output length |
|-----------------|----------------------------|
| `dsiv`          | 31-48 characters           |
| `psiv`          | 56-74 characters           |
| SHA256          | 64 characters              |
| JWT             | 150+ characters            |

A more complete output length comparison is given in the
[Appendix](#appendix-obtext-lengths).

## Performance Tuning

### Native CPU builds (POLYVAL / AES acceleration)

The GCM-SIV schemes (`dgcmsiv`, `pgcmsiv`) hash their input with
POLYVAL, and every scheme runs AES. Recent x86-64 CPUs provide wide
vector instructions for both — VAES and VPCLMULQDQ — but the
underlying RustCrypto backends only emit those wide paths when the
crate is compiled with the matching target features enabled. A
default `cargo build` uses the baseline AES-NI / CLMUL path and does
*not* select the wide path at runtime.

Enabling native codegen measured 12–33% faster encryption across
schemes on an 11th-gen Intel (the largest gains land on the
AES-heavy SIV schemes, which pick up VAES):

```shell
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Because `target-cpu` is a `rustc` codegen flag — not a `Cargo.toml`
profile key — a library cannot set it on your behalf. The choice
belongs to whoever builds the final binary or image. The durable
form is a `.cargo/config.toml` in *your* project (see
[`.cargo/config.toml.example`](.cargo/config.toml.example)):

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

> **Docker / distribution caveat:** `target-cpu=native` bakes in the
> microarchitecture of the *build* host. If you build in CI and run
> the image on different hardware that lacks those instructions, the
> binary aborts with an illegal-instruction fault (SIGILL) — there is
> no graceful fallback. Use `native` only when the build host and run
> host are the same class of machine. For images shipped to
> heterogeneous hosts, pin an explicit floor that every run host is
> guaranteed to support instead, e.g.
> `-C target-feature=+aes,+vaes,+vpclmulqdq,+avx2` or
> `-C target-cpu=x86-64-v4`. (VAES / VPCLMULQDQ sit above the common
> `x86-64-v3` baseline, so they must be asserted explicitly.)

### SIV vs GCM-SIV: choosing by input length

`siv` (AES-SIV) and `gcmsiv` (AES-GCM-SIV) trade off by payload size:

- **AES-SIV** (`dsiv`, `psiv`) has lower fixed per-message cost but
  passes over the data with AES twice (S2V + CTR), so its cost rises
  faster with length.
- **AES-GCM-SIV** (`dgcmsiv`, `pgcmsiv`) pays a higher fixed cost (a
  per-message key derivation) but hashes with POLYVAL in a single
  pass, giving better throughput on longer inputs.

The result is a crossover: short inputs favor SIV, longer inputs
favor GCM-SIV. Measured enc, `*.c32`, native build:

| Input  |    `dsiv` | `dgcmsiv` |    `psiv` | `pgcmsiv` |
| -----: | --------: | --------: | --------: | --------: |
|   32 B |  **272 ns** |    348 ns |  **349 ns** |    361 ns |
|  128 B |  **395 ns** |    486 ns |  **464 ns** |    476 ns |
|  256 B |  **592 ns** |    614 ns |    648 ns |  **618 ns** |
| 1024 B |   1.61 µs | **1.39 µs** |   1.73 µs | **1.44 µs** |

(Bold = faster of the SIV / GCM-SIV pair at that size.)

Rule of thumb:

- **Short payloads (≲128 B)** — tokens, identifiers, referenceable
  prefixes, the typical oboron use case — prefer **SIV** (`dsiv` /
  `psiv`). It is as fast or faster *and* produces shorter obtext.
- **Larger payloads (≳256 B)** — prefer **GCM-SIV** (`dgcmsiv` /
  `pgcmsiv`); its single-pass POLYVAL throughput pulls ahead and the
  margin widens with length (~15% faster at 1 KB).
- The exact crossover depends on the build: a default build crosses
  near ~256 B, while a native build keeps SIV ahead a little longer
  because VAES accelerates SIV's double AES pass more than it helps
  GCM-SIV. The probabilistic pair (`psiv` / `pgcmsiv`) crosses earlier
  than the deterministic pair (`dsiv` / `dgcmsiv`).

This is purely a performance trade-off — both algorithms are
nonce-misuse-resistant authenticated AEADs. Choose the property you need
(deterministic `d...` vs probabilistic `p...`) first, then SIV vs
GCM-SIV by size. See [BENCHMARKS.md](BENCHMARKS.md) for the full
matrix.

## Rust API Overview

Oboron provides multiple API styles supporting different use cases.  For
most production applications, *compile-time format selection* (option 1
below) offers the best combination of performance, type safety, and
clarity.

### 1. Compile-time Format Selection (Recommended for Production)

Use fixed-format types when formats are known at compile time for optimal
performance and type safety:
```rust
use oboron::PgcmsivB64;

let key = env::var("OBORON_KEY")?;
let pgcmsiv = PgcmsivB64::new(&key)?;

let ot = pgcmsiv.enc("hello")?;
let pt2 = pgcmsiv.dec(&ot)?;
assert_eq!(pt2, "hello");
```

Available types include all combinations of scheme variants (e.g.,
`Dgcmsiv`, `Pgcmsiv`, `Dsiv`, `Psiv`) with encoding specifications
(`B64`, `Hex`, `B32`, or `C32`), and concatenates the two in struct
names, for example:
- `DgcmsivHex` - encoder for `ob:dgcmsiv.hex` format
- `DgcmsivB64` - encoder for `ob:dgcmsiv.b64` format
- `DsivC32` - encoder for `ob:dsiv.c32` format.

### 2. Runtime Format Selection (`Ob`)

When format specification at runtime is required, use `Ob`:
```rust
use oboron::Ob;

let key = env::var("OBORON_KEY")?;
let ob = Ob::new("dsiv.b64", &key)?;

let ot = ob.enc("hello")?;
let pt2 = ob.dec(&ot)?;
assert_eq!(pt2, "hello");
```
The format can also be changed with mutable instances:
```rust
let mut ob = Ob::new("dgcmsiv.b64", &key)?;
let ot = ob.enc("hello")?; // dgcmsiv.b64 obtext

// Format modification
ob.set_format("psiv.hex")?;
let ot_hex = ob.enc("world")?; // psiv.hex obtext
```

### 3. Multiple Format Support (`Omnib`)

`Omnib` differs in format management: it stores no format and takes one
per call.

**Multi-Format Workflow:** Designed for simultaneous work with different
formats, requiring format specification in each operation:
```rust
use oboron::Omnib;

let omb = Omnib::new(&key)?;

// Format specification per operation
let ot = omb.enc("test", "psiv.b64");
let pt2 = omb.dec(&ot, "psiv.b64");
let pt_other = omb.dec(&other, "dsiv.c32");
```

### Using Format Constants

For type safety and discoverability, use the provided format constants
instead of string literals:

```rust
use oboron::{Ob, Omnib, DSIV_B64, DSIV_HEX};

let key = oboron::generate_key();

// With Ob (runtime format selection)
let ob = Ob::new(DSIV_B64, &key)?;

// With Omnib (multi-format operations)
let omb = Omnib::new(&key)?;
let ot_b64 = omb.enc("data", DSIV_B64)?;
let ot_hex = omb.enc("data", DSIV_HEX)?;
```

Available constants:
- `DGCMSIV_C32`, `DGCMSIV_B32`, `DGCMSIV_B64`, `DGCMSIV_HEX`
- `PGCMSIV_C32`, `PGCMSIV_B32`, `PGCMSIV_B64`, `PGCMSIV_HEX`
- `DSIV_C32`, `DSIV_B32`, `DSIV_B64`, `DSIV_HEX`
- `PSIV_C32`, `PSIV_B32`, `PSIV_B64`, `PSIV_HEX`
- Testing:  `MOCK1_C32`, `MOCK2_B32`, etc.

### Advanced: `Format` Objects

`Format` structs provide a more fine-grained type safety than format
string constants:
```rust
use oboron::{Ob, Format, Scheme, Encoding};

let format = Format::new(Scheme::Dsiv, Encoding::B64);
let ob = Ob::new(format, &key)?;
```

### Typical Production Use

For compile-time known schemes and encodings, however, static types
provide optimal performance, concise syntax, and strongest type
guarantees:
```rust
use oboron::DsivB64;
let ob = DsivB64::new(&key)?;
let ot = ob.enc("secret")?;
```
The format is built into the struct, no format strings, constants, or
Format structs are needed.

### Feature Flags

Oboron exposes a small set of optional features so you can opt out of
schemes you don't need. This is mainly useful for WebAssembly builds
where bundle size matters.

**Default:** all four authenticated production-ready schemes (`dsiv`,
`psiv`, `dgcmsiv`, `pgcmsiv`).

Available features:

- **`secure-schemes`** — bundles all four authenticated schemes
  (default).
- **`dsiv`**, **`psiv`**, **`dgcmsiv`**, **`pgcmsiv`** —
  individual schemes; enable only what you need to minimize
  binary size.
- **`mock`** — mock1, mock2 testing schemes (no encryption).
- **`keyless`** — hardcoded-key constructors for tests/obfuscation.

Hex and raw-byte key input are always available — no feature flag
needed (`DsivC32::new(&hex_key)`, `DsivC32::from_bytes(&key_bytes)`).

Examples:

```toml
# Minimal: only dsiv (deterministic AES-SIV).
oboron = { version = "1.0", default-features = false, features = ["dsiv"] }

# Both SIV schemes.
oboron = { version = "1.0", default-features = false, features = ["dsiv", "psiv"] }

# All authenticated schemes.
oboron = { version = "1.0", default-features = false, features = ["secure-schemes"] }
```

At least one scheme feature must be enabled — building with no
features will fail with a compile error.

### The `ObtextCodec` Trait

All types except `Omnib` implement the `ObtextCodec` trait, providing a
consistent interface:

- `enc(plaintext: &str) -> Result<String, Error>` - Encode plaintext to
  obtext
- `dec(obtext: &str) -> Result<String, Error>` - Decode obtext using the
  codec's bound format
- `scheme() -> Scheme` - Current scheme
- `encoding() -> Encoding` - Current encoding
- `format() -> Format` - Current format (scheme + encoding)

### Working with Keys

```rust
// main interface: pass a 128-char hex key string.
let ob = DgcmsivB64::new(&env::var("OBORON_KEY")?);       // hex key
// explicit hex constructor:
let ob = DgcmsivB64::from_hex_key(&env::var("HEX_KEY")?); // hex key
// raw bytes:
let ob = DgcmsivB64::from_bytes(&key_bytes)?;             // raw bytes key
// with "keyless" feature enabled:
let ob = DgcmsivB64::new_keyless()?;              // insecure/testing only
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
| Short unique IDs    | UUIDv4 (36 chars)    | `ob:dsiv.c32` (34-47 chars, reversible) |
| URL parameters      | JWT (150+ chars)     | `ob:dsiv.b64` (4.5x smaller, 4x faster) |
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
let ob = DsivC32::new(&env::var("OBORON_KEY")?);
let ot = ob.enc("Hello World")?;
```

**Benefits:**
- No manual hex/base64 encoding/decoding
- Keys as hex strings (no byte array management)
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
let ob = DsivC32::new(&env::var("OBORON_KEY")?);
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
let ob = DgcmsivC32::new(&env::var("OBORON_KEY")?);
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

All implementations must pass the common test vectors, which live
in a dedicated repo:
[`oboron-test-vectors`](https://gitlab.com/oboron/oboron-test-vectors).
This crate consumes them via a git submodule mounted at
`oboron/tests/vectors/` — clone with `--recurse-submodules` (or
run `git submodule update --init` afterwards) before
`cargo test --workspace`.

## Related Crates

- [`oboron-cli`](https://crates.io/crates/oboron-cli) — Command-line interface (`ob` binary)
- [`oboron-py`](https://crates.io/crates/oboron-py) — Python bindings ([PyPI](https://pypi.org/project/oboron/))
- [`obu`](https://gitlab.com/oboron/obu-rs) — the separate unauthenticated (`upcbc`) and obfuscation (`zdcbc`) crate

## Getting Help

- [Documentation](https://docs.rs/oboron)
- [Issues](https://gitlab.com/oboron/oboron-rs/-/issues) (GitLab)

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as
above, without any additional terms or conditions.

## Changelog

See [CHANGELOG.md](https://gitlab.com/oboron/oboron-rs/-/blob/master/CHANGELOG.md) for release history.

## Appendix: Obtext Lengths

`mock1` is a non-cryptographic scheme used for testing, whose ciphertext
is equal to the plaintext bytes (identity transformation). It is
included in the tables below as baseline.

(Note: the `mock1` scheme is feature gated: use it by enabling the `mock`
feature)

## Base32 encoding (b32/c32)

| Format       | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
|--------------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.b32    | 10 | 16 |  23 |  29 |  42 |  55 | 106 |  208 |
| dgcmsiv.b32  | 36 | 42 |  48 |  55 |  68 |  80 | 132 |  234 |
| dsiv.b32     | 36 | 42 |  48 |  55 |  68 |  80 | 132 |  234 |
| pgcmsiv.b32  | 55 | 61 |  68 |  74 |  87 | 100 | 151 |  253 |
| psiv.b32     | 61 | 68 |  74 |  80 |  93 | 106 | 157 |  260 |

## Base64 Encoding (b64)

| Format       | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
|--------------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.b64    |  8 | 14 |  19 |  24 |  35 |  46 |  88 |  174 |
| dgcmsiv.b64  | 30 | 35 |  40 |  46 |  56 |  67 | 110 |  195 |
| dsiv.b64     | 30 | 35 |  40 |  46 |  56 |  67 | 110 |  195 |
| pgcmsiv.b64  | 46 | 51 |  56 |  62 |  72 |  83 | 126 |  211 |
| psiv.b64     | 51 | 56 |  62 |  67 |  78 |  88 | 131 |  216 |

## Hex Encoding (hex)

| Format       | 4B | 8B | 12B | 16B | 24B | 32B | 64B | 128B |
| -------------|---:|---:|----:|----:|----:|----:|----:|-----:|
| mock1.hex    | 12 | 20 |  28 |  36 |  52 |  68 | 132 |  260 |
| dgcmsiv.hex  | 44 | 52 |  60 |  68 |  84 | 100 | 164 |  292 |
| dsiv.hex     | 44 | 52 |  60 |  68 |  84 | 100 | 164 |  292 |
| pgcmsiv.hex  | 68 | 76 |  84 |  92 | 108 | 124 | 188 |  316 |
| psiv.hex     | 76 | 84 |  92 | 100 | 116 | 132 | 196 |  324 |
