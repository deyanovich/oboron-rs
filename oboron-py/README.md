# oboron

[![PyPI](https://img.shields.io/pypi/v/oboron)](https://pypi.org/project/oboron/)
[![Python Versions](https://img.shields.io/pypi/pyversions/oboron)](https://pypi.org/project/oboron/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://gitlab.com/oboron/oboron-rs/-/blob/master/oboron-py/LICENSE)
[![oboron crate](https://img.shields.io/crates/v/oboron?label=oboron)](https://crates.io/crates/oboron)

Python bindings for [`oboron`][oboron-rs] — a *string-in,
string-out* symmetric encryption and encoding library. One call
takes plaintext to **obtext** (encrypted + encoded), one call
brings it back. Multiple AES-based schemes (deterministic and
probabilistic, authenticated and unauthenticated) share a single
key and a uniform API.

[oboron-rs]: https://gitlab.com/oboron/oboron-rs
[oboron]: https://oboron.org/
[obcrypt-py]: https://pypi.org/project/obcrypt/

For the bytes-in/bytes-out cryptographic core (no encoding, no
UTF-8 validation), see [`obcrypt-py`][obcrypt-py]. oboron-py
layers encoding, format strings, and autodetection on top.

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

The legacy 86-character base64 form is still accepted for
backward compatibility, but is deprecated and will be removed
when the oboron core ships 1.0. New code should use hex.

## Quick start

### Fixed-format codec (most common)

```python
import oboron

key = oboron.generate_key()
ob = oboron.AasvC32(key)

obtext = ob.enc("hello, world")
plaintext = ob.dec(obtext)
assert plaintext == "hello, world"
```

`AasvC32` binds a key + the `aasv.c32` format together — most
ergonomic when one codec handles many messages of the same
format. Available classes follow the `{Scheme}{Encoding}`
pattern: `AagsB64`, `AasvHex`, `ApsvC32`, `UpbcB32`, etc.

Or, from an env var:

```python
import os, oboron
ob = oboron.AasvC32(os.environ["OBORON_KEY"])
```

### Runtime-flexible (`Ob`)

When the format is chosen at runtime (config, user input), use
`Ob` — same shape, but `set_format` / `set_scheme` /
`set_encoding` mutate the format in place.

```python
ob = oboron.Ob("aasv.b64", key)
obtext = ob.enc("hello")

ob.set_encoding("c32")     # now aasv.c32
ob.set_scheme("aags")      # now aags.c32
ob.set_format("upbc.hex")  # now upbc.hex
```

### Multi-format (`Omnib`)

`Omnib` doesn't store a format — pass one per call, and
`autodec` detects both scheme and encoding from the obtext.

```python
omb = oboron.Omnib(key)

ot_aasv = omb.enc("hello", "aasv.b64")
ot_aags = omb.enc("hello", "aags.c32")

assert omb.autodec(ot_aasv) == "hello"   # detects aasv + b64
assert omb.autodec(ot_aags) == "hello"   # detects aags + c32
```

Autodetection retries across encodings; expect ~3x worst-case
overhead vs known-format `dec`, though the heuristic encoding
detector keeps the average much closer to single-`dec` cost.

### Free functions

For one-off operations without instantiating a codec:

```python
import oboron
from oboron import formats

key = oboron.generate_key()

obtext = oboron.enc("hello", formats.AASV_B64, key)
plaintext = oboron.dec(obtext, formats.AASV_B64, key)
plaintext_auto = oboron.autodec(obtext, key)
```

## Schemes

| Name    | Tier   | Determinism   | Algorithm      | Use case                                   |
| ------- | ------ | ------------- | -------------- | ------------------------------------------ |
| `aags`  | a      | deterministic | AES-GCM-SIV    | Auth + compact + deterministic             |
| `apgs`  | a      | probabilistic | AES-GCM-SIV    | Auth + max privacy                         |
| `aasv`  | a      | deterministic | AES-SIV        | General-purpose auth, nonce-misuse safe    |
| `apsv`  | a      | probabilistic | AES-SIV        | Auth + max privacy + nonce-misuse safe     |
| `upbc`  | u      | probabilistic | AES-CBC        | Confidentiality only (auth handled extern) |
| `zrbcx` | z      | deterministic | AES-CBC, fixed | **Obfuscation only — NOT SECURE**          |

Tier letters: **a** = authenticated, **u** = unauthenticated
but real cryptography, **z** = obfuscation only (no
cryptographic security). For new security-sensitive work, pick
an a-tier scheme; `aasv` is a strong default.

The z-tier (`zrbcx`, `legacy`) lives under `oboron.ztier` and
uses a 32-byte **secret** instead of a 64-byte master key:

```python
import oboron
from oboron.ztier import ZrbcxC32

secret = oboron.generate_secret()   # 64-char hex
z = ZrbcxC32(secret)
obtext = z.enc("hello")             # 'c38jrtewavbm9609ga970bjxx5k42'
```

For obfuscation contexts where everyone is allowed to decrypt
(IDs, captcha challenges, URL slugs), use `keyless=True`:

```python
z = ZrbcxC32(keyless=True)
```

## Encodings

| Encoding | Description                            | Notes                          |
| -------- | -------------------------------------- | ------------------------------ |
| `b32`    | RFC 4648 base32                        | Uppercase, no obscenity rules  |
| `c32`    | Crockford base32                       | Lowercase, obscenity-aware     |
| `b64`    | RFC 4648 URL-safe base64               | Most compact                   |
| `hex`    | Hexadecimal                            | Longest output, fastest decode |

Format = `scheme.encoding`, e.g. `aasv.c32`, `aags.b64`,
`upbc.hex`. The `oboron.formats` module exposes every valid
combination as a constant: `formats.AASV_C32`, `formats.AAGS_B64`,
etc. — useful for typo-resistance and editor autocomplete.

## Exceptions

All errors inherit from `oboron.OboronError`:

- `InvalidKey` — bad hex / base64 / wrong-length key
- `InvalidFormat` — unknown scheme, unknown encoding, malformed
  format string
- `EncryptionFailed` — AEAD failure / empty plaintext
- `DecryptionFailed` — tag check, padding, obtext-decode
  failure, post-decrypt UTF-8 validation

```python
try:
    ob = oboron.AasvC32("not-a-real-key")
except oboron.InvalidKey as e:
    ...
```

## Inheritance / isinstance

All a/u-tier codec classes plus `Ob` are registered as virtual
subclasses of `oboron.OboronBase`; z-tier codecs (`ZrbcxC32`,
`Legacy`, etc.) plus `Obz` register against
`oboron.ztier.ZtierBase`. Useful for generic code:

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
ob = oboron.AagsB64(keyless=True)
```

## Development build

```bash
pip install maturin
cd oboron-py
maturin develop --release
python -m oboron.test_inheritance
```

## License

MIT — see
[LICENSE](https://gitlab.com/oboron/oboron-rs/-/blob/master/oboron-py/LICENSE).
