# oboron-rs

Rust reference implementation of the
[oboron](https://oboron.org/) protocol — a *string-in,
string-out* symmetric encryption protocol.

## Workspace

- **[oboron](./oboron)** — Core encryption library
  ([crates.io](https://crates.io/crates/oboron)).
- **[oboron-py](./oboron-py)** — Python bindings for oboron
  ([PyPI](https://pypi.org/project/oboron/)). Ships to PyPI
  only (not crates.io); see `oboron-py/README.md` for the
  Python API.
- **[oboron-wasm](./oboron-wasm)** — WebAssembly / JavaScript
  bindings for oboron. Ships to npm only (not crates.io) via
  wasm-pack; see `oboron-wasm/README.md` for the JS API.

## Related

- **CLI tooling** (`ob` and `obcrypt` binaries plus the
  `oboron-cli-conformance` cross-implementation test suite)
  lives in
  [`oboron-tools-rs`](https://gitlab.com/oboron/oboron-tools-rs).
- **Cryptographic core** — the bytes-in / bytes-out layer
  this library depends on — lives in
  [`obcrypt-rs`](https://gitlab.com/oboron/obcrypt-rs).
- **Obfuscation / unauthenticated tier** — the `obu` crate
  (`upcbc`, `zdcbc`): **not** cryptographically secure, shares
  no code with this library, lives in
  [`obu-rs`](https://gitlab.com/oboron/obu-rs).
- **Test vectors** live in
  [`oboron-test-vectors`](https://gitlab.com/oboron/oboron-test-vectors).

## Build

```bash
cargo build --workspace
cargo test --workspace
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
