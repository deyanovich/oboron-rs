# oboron

[![PyPI](https://img.shields.io/pypi/v/oboron)](https://pypi.org/project/oboron/)
[![Python Versions](https://img.shields.io/pypi/pyversions/oboron)](https://pypi.org/project/oboron/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![oboron crate](https://img.shields.io/crates/v/oboron?label=oboron)](https://crates.io/crates/oboron)

Python bindings for [`oboron`][oboron] — a *string-in,
string-out* symmetric encryption and encoding library. One call
takes plaintext to **obtext** (encrypted + encoded), one call
brings it back. Multiple authenticated AES-based schemes
(deterministic and probabilistic) share a single key and a
uniform API.

[oboron]: https://oboron.org/
[obcrypt-py]: https://pypi.org/project/obcrypt/

For the bytes-in/bytes-out cryptographic core (no encoding, no
UTF-8 validation), see [`obcrypt-py`][obcrypt-py]. oboron-py
layers encoding and format strings on top.

## Install

```bash
pip install oboron
```

Wheels are published for Linux (x86_64, aarch64), macOS (arm64,
x86_64), and Windows (x86_64). The extension is built against
PyO3's stable ABI (`abi3-py38`); a single wheel per platform
covers CPython 3.8 and later.

## Keys

Keys are **128-character hex strings** — the canonical oboron
key form, the same form that comes out of env vars, config
files, and secrets managers. Generate one:

```python
import oboron

key = oboron.generate_key()
# 'b5129efd1cf34b0c7a83...'  (128 lowercase hex chars)
```

Wherever oboron takes a key, it takes that string directly.
Raw 64-byte key material is available via the `key_bytes`
property and `generate_key_bytes()` for interop with byte-native
APIs (HSMs, `cryptography`, `pynacl`, custom storage), but hex
is the canonical input everywhere.

## Quick start

### Fixed-format codec (most common)

```python
import oboron

key = oboron.generate_key()
ob = oboron.DsivC32(key)

obtext = ob.enc("hello, world")
plaintext = ob.dec(obtext)
assert plaintext == "hello, world"
```

`DsivC32` binds a key + the `dsiv.c32` format together — most
ergonomic when one codec handles many messages of the same
format. Available classes follow the `{Scheme}{Encoding}`
pattern: `DgcmsivB64`, `DsivHex`, `PsivC32`, `PgcmsivB32`, etc.

Or, from an env var:

```python
import os, oboron
ob = oboron.DsivC32(os.environ["OBORON_KEY"])
```

### Runtime-flexible (`Ob`)

When the format is chosen at runtime (config, user input), use
`Ob` — same shape, but `set_format` / `set_scheme` /
`set_encoding` mutate the format in place.

```python
ob = oboron.Ob("dsiv.b64", key)
obtext = ob.enc("hello")

ob.set_encoding("c32")        # now dsiv.c32
ob.set_scheme("dgcmsiv")      # now dgcmsiv.c32
ob.set_format("psiv.hex")     # now psiv.hex
```

### Multi-format (`Omnib`)

`Omnib` doesn't store a format — pass one per call.

```python
omb = oboron.Omnib(key)

ot_dsiv = omb.enc("hello", "dsiv.b64")
ot_dgcmsiv = omb.enc("hello", "dgcmsiv.c32")

assert omb.dec(ot_dsiv, "dsiv.b64") == "hello"
assert omb.dec(ot_dgcmsiv, "dgcmsiv.c32") == "hello"
```

### Free functions

For one-off operations without instantiating a codec:

```python
import oboron
from oboron import formats

key = oboron.generate_key()

obtext = oboron.enc("hello", formats.DSIV_B64, key)
plaintext = oboron.dec(obtext, formats.DSIV_B64, key)
```

## Schemes

| Name      | Determinism   | Algorithm   | Use case                                |
| --------- | ------------- | ----------- | --------------------------------------- |
| `dsiv`    | deterministic | AES-SIV     | General-purpose auth, nonce-misuse safe |
| `psiv`    | probabilistic | AES-SIV     | Auth + max privacy + nonce-misuse safe  |
| `dgcmsiv` | deterministic | AES-GCM-SIV | Auth + compact + deterministic          |
| `pgcmsiv` | probabilistic | AES-GCM-SIV | Auth + max privacy                      |

Every oboron scheme is authenticated. In general,
AES-SIV and AES-GCM-SIV have similar properties, with
AES-SIV being typically more performant on short inputs,
while AES-GCM-SIV scales better with input size, and
outperforms AES-SIV on long inputs.

The unauthenticated (`upcbc`) and obfuscation (`zdcbc`) layers
live in the separate [`obu`](https://gitlab.com/oboron/obu-rs)
crate, not these bindings.

## Encodings

| Encoding | Description                            | Notes                                   |
| -------- | -------------------------------------- | --------------------------------------- |
| `b32`    | RFC 4648 base32                        | Uppercase                               |
| `c32`    | Crockford base32                       | Lowercase (obscenity safe)              |
| `b64`    | RFC 4648 URL-safe base64               | Most compact                            |
| `hex`    | Hexadecimal                            | Longest output (slightly faster decode) |

Format = `scheme.encoding`, e.g. `dsiv.c32`, `dgcmsiv.b64`,
`psiv.hex`. The `oboron.formats` module exposes every valid
combination as a constant: `formats.DSIV_C32`,
`formats.DGCMSIV_B64`, etc. — useful for typo-resistance and
editor autocomplete.

## Exceptions

All errors inherit from `oboron.OboronError`:

- `InvalidKey` — bad hex / wrong-length key
- `InvalidFormat` — unknown scheme, unknown encoding, malformed
  format string
- `EncryptionFailed` — AEAD failure / empty plaintext
- `DecryptionFailed` — tag check, obtext-decode failure,
  post-decrypt UTF-8 validation

```python
try:
    ob = oboron.DsivC32("not-a-real-key")
except oboron.InvalidKey as e:
    ...
```

## Inheritance / isinstance

All codec classes plus `Ob` are registered as virtual
subclasses of `oboron.OboronBase`. Useful for generic code:

```python
def encrypt_each(cipher: oboron.OboronBase, items: list[str]) -> list[str]:
    return [cipher.enc(item) for item in items]
```

## Keyless mode

Every codec accepts `keyless=True` instead of a key — it
substitutes a publicly hardcoded key. This is for testing and
obfuscation contexts where you actively want the output to be
recoverable without secret material. **Never use `keyless=True`
when confidentiality matters.**

```python
ob = oboron.DgcmsivB64(keyless=True)
```

## Development build

```bash
pip install maturin
cd oboron-py
maturin develop --release
python -m oboron.test_inheritance
```

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
