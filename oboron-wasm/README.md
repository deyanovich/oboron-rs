# oboron-wasm

WebAssembly / JavaScript bindings for [`oboron`][oboron-rs] — a
*string-in, string-out* symmetric encryption and encoding library.
One call takes plaintext to **obtext** (encrypted + encoded), one
call brings it back. Multiple authenticated AES-based schemes
(deterministic and probabilistic) share a single key and a uniform
API.

[oboron-rs]: https://gitlab.com/oboron/oboron-rs
[oboron]: https://oboron.org/
[obcrypt-wasm]: https://gitlab.com/oboron/obcrypt-rs

For the bytes-in / bytes-out cryptographic core (no encoding, no
UTF-8 validation), see [`obcrypt-wasm`][obcrypt-wasm]. oboron-wasm
layers encoding and format strings on top.

## Install

```bash
npm install oboron-wasm
```

The package is built with [`wasm-pack`][wasm-pack]; the compiled
wasm and generated TypeScript declarations ship in the package.
Plaintext and obtext are JS strings; keys are hex strings.

[wasm-pack]: https://rustwasm.github.io/wasm-pack/

## Keys

Keys are **128-character hex strings** — the canonical oboron key
form, the same form that comes out of env vars, config files, and
secrets managers. Generate one:

```js
import * as oboron from "oboron-wasm";

const key = oboron.generateKey();
// 'b5129efd1cf34b0c...'  (128 lowercase hex chars)
```

Wherever oboron takes a key, it takes that string directly. Raw
64-byte key material is available via the `keyBytes` getter and
`generateKeyBytes()` for byte-native interop, but the hex form is
the canonical input everywhere.

## Quick start

### Fixed-format codec (most common)

Binds a key + the `dsiv.c32` format together — most ergonomic
when one codec handles many messages of the same format.

```js
import { DsivC32, generateKey } from "oboron-wasm";

const key = generateKey();
const ob = new DsivC32(key);

const obtext = ob.enc("hello, world");
const plaintext = ob.dec(obtext);
// plaintext === "hello, world"
```

Available classes follow the `{Scheme}{Encoding}` pattern:
`DgcmsivB64`, `DsivHex`, `PsivC32`, `PgcmsivB32`, etc.

### Runtime-flexible (`Ob`)

When the format is chosen at runtime (config, user input), use
`Ob` — same shape, but `setFormat` / `setScheme` / `setEncoding`
mutate the format in place.

```js
import { Ob, generateKey } from "oboron-wasm";

const ob = new Ob("dsiv.b64", generateKey());
const obtext = ob.enc("hello");

ob.setEncoding("c32");        // now dsiv.c32
ob.setScheme("dgcmsiv");      // now dgcmsiv.c32
ob.setFormat("psiv.hex");     // now psiv.hex
```

### Multi-format (`Omnib`)

`Omnib` doesn't store a format — pass one per call.

```js
import { Omnib, generateKey } from "oboron-wasm";

const omb = new Omnib(generateKey());

const otDsiv = omb.enc("hello", "dsiv.b64");
const otDgcmsiv = omb.enc("hello", "dgcmsiv.c32");

omb.dec(otDsiv, "dsiv.b64");        // "hello"
omb.dec(otDgcmsiv, "dgcmsiv.c32");  // "hello"
```

### Free functions

For one-off operations without instantiating a codec:

```js
import { enc, dec, generateKey } from "oboron-wasm";

const key = generateKey();
const obtext = enc("hello", "dsiv.b64", key);

dec(obtext, "dsiv.b64", key);   // "hello"
```

## Schemes

| Name      | Determinism   | Algorithm   | Use case                                |
| --------- | ------------- | ----------- | --------------------------------------- |
| `dgcmsiv` | deterministic | AES-GCM-SIV | Auth + compact + deterministic          |
| `pgcmsiv` | probabilistic | AES-GCM-SIV | Auth + max privacy                      |
| `dsiv`    | deterministic | AES-SIV     | General-purpose auth, nonce-misuse safe |
| `psiv`    | probabilistic | AES-SIV     | Auth + max privacy + nonce-misuse safe  |

Every oboron scheme is authenticated. For new
security-sensitive work, `dsiv` is a strong default.

The unauthenticated (`upcbc`) and obfuscation (`zdcbc`) layers live
in the separate [`obu`](https://gitlab.com/oboron/obu-rs) crate,
not these bindings.

## Encodings

| Encoding | Description              | Notes                          |
| -------- | ------------------------ | ------------------------------ |
| `b32`    | RFC 4648 base32          | Uppercase, no obscenity rules  |
| `c32`    | Crockford base32         | Lowercase, obscenity-aware     |
| `b64`    | RFC 4648 URL-safe base64 | Most compact                   |
| `hex`    | Hexadecimal              | Longest output, fastest decode |

Format = `scheme.encoding`, e.g. `dsiv.c32`, `dgcmsiv.b64`,
`psiv.hex`.

## Keyless mode

For obfuscation contexts where everyone is allowed to decrypt
(IDs, captcha challenges, URL slugs), every codec class offers a
`keyless()` static factory that substitutes a publicly hardcoded
key. **Never use it when confidentiality matters.**

```js
import { DsivC32 } from "oboron-wasm";

const z = DsivC32.keyless();
```

The free functions `encKeyless` / `decKeyless` do the same for
one-off calls.

## Errors

Operations throw a JS `Error` whose message describes the failure
— bad hex / wrong-length key, unknown scheme or encoding,
malformed format string, AEAD failure / empty plaintext, or a
failed decryption (tag check, padding, obtext-decode failure,
post-decrypt UTF-8 validation). Wrap calls in `try` / `catch` to
handle them.

## Development build

Requires the `wasm32-unknown-unknown` target and
[`wasm-pack`][wasm-pack]:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

cd oboron-wasm

# Bundler target (webpack, Vite, …); also: --target web | nodejs
wasm-pack build --release --target bundler

# Run the roundtrip tests in Node
wasm-pack test --node
```

The generated npm package lands in `pkg/`.

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
