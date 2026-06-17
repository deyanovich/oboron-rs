# Changelog

All notable changes to `oboron-wasm` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [1.0.0-rc1] - 2026-06-16

### Added

- Initial WebAssembly / JavaScript binding surface for `oboron`
  via wasm-bindgen, mirroring `oboron-py`. Authenticated-only:
  the unauthenticated / obfuscation (`obu`) layer is a separate
  package and is not bound here.
  - Free functions: `enc`, `dec`, their keyless variants
    (`encKeyless` / `decKeyless`), `generateKey`,
    `generateKeyBytes`, and `version`.
  - One fixed-format codec class per scheme+encoding — `DsivC32`,
    `DgcmsivB64`, `PsivHex`, etc. — each constructed from a
    128-character hex key, with `enc` / `dec` methods, a
    `keyless()` static factory, and `format` / `scheme` /
    `encoding` / `key` / `keyHex` / `keyBytes` getters.
  - Runtime-flexible `Ob` (with `setFormat` / `setScheme` /
    `setEncoding`) and multi-format `Omnib` (format supplied per
    `dec` call).
- Per-scheme cargo features (`dgcmsiv`, `pgcmsiv`, `dsiv`,
  `psiv`, `mock`) plus `keyless`, each forwarding to the
  corresponding `oboron` feature; the default set mirrors
  `oboron-py`.
- wasm-bindgen-test roundtrip suite (`tests/roundtrip.rs`),
  runnable via `wasm-pack test --node`.

### Notes

- JS-facing names are camelCase (`generateKey`, `keyBytes`,
  `setFormat`); plaintext / obtext are JS strings, raw key
  material maps to `Uint8Array`. Keys are 128-character hex
  strings. Errors surface as JS `Error`s carrying the underlying
  `oboron::Error` message.
- Randomness on wasm32 flows through oboron's getrandom "js"
  backend; no separate getrandom dependency is declared here.
- Ships to npm via wasm-pack — not a crates.io publication target.
