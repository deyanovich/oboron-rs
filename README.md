# oboron-rs

Rust reference implementation of the
[oboron](https://oboron.org/) protocol — a *string-in,
string-out* symmetric encryption protocol.

## Workspace

- **[oboron](./oboron)** — Core encryption library
  ([crates.io](https://crates.io/crates/oboron)).

## Related

- **CLI tooling** (`ob`, `obz`, `obcrypt` binaries plus the
  `oboron-cli-conformance` cross-implementation test suite)
  lives in
  [`oboron-tools-rs`](https://gitlab.com/oboron/oboron-tools-rs).
- **Cryptographic core** — the bytes-in / bytes-out layer
  this library depends on — lives in
  [`obcrypt-rs`](https://gitlab.com/oboron/obcrypt-rs).
- **Test vectors** live in
  [`oboron-test-vectors`](https://gitlab.com/oboron/oboron-test-vectors).

## Build

```bash
cargo build --workspace
cargo test --workspace
```

## License

MIT
