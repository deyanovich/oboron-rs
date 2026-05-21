CHANGELOG
=========

All notable changes to Oboron will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
but note that pre-1.0 releases may not adhere strictly to all guidelines.


[Unreleased]
------------

### Added

### Changed

### Fixed


[oboron v0.8.0] - 2026-05-20
------------------------------

### Changed (Breaking)

- **Cryptographic core extracted** to a separate `obcrypt`
  crate ([crates.io](https://crates.io/crates/obcrypt),
  source at
  [`gitlab.com/oboron/obcrypt-rs`](https://gitlab.com/oboron/obcrypt-rs)).
  The internal `src/obcrypt/` module is replaced with a
  path/registry dep on the external crate; the library's
  public API surface is unchanged.
- **Hex keys are now canonical.** `Key::from_hex` /
  `Key::to_hex` are the primary key text encoding;
  base64 key support moved behind the (default-on,
  deprecated) `base64-keys` feature gate. Implicit
  constructors auto-detect hex (128 chars) vs base64
  (86 chars). Base64 key APIs slated for removal at
  `oboron 1.0`.
- **Feature surface trimmed from 31 to 10.** Removed
  grouping / marker features that didn't earn their keep
  (`std`, `full`, `dev`, `secure-min`, `experimental`,
  `convenience`, `atier`, `utier`, `ztier`,
  `all-cbc-schemes`, `all-gcm-schemes`, `all-siv-schemes`,
  `deterministic-schemes`, `probabilistic-schemes`,
  `all-alt-keys`). Folded `zmock` into `mock`. Removed
  `hex-keys` and `bytes-keys` gates (both unconditional
  now). Per-scheme features forward to `obcrypt/*` so they
  gate the AES backend pulled by obcrypt, not just the
  wrapper code.
- **Workspace trimmed**: `oboron-cli` moved to the
  [`oboron-tools-rs`](https://gitlab.com/oboron/oboron-tools-rs)
  workspace (next CLI release publishes from there);
  `ob-cli-tests` removed (superseded by
  [`oboron-cli-conformance`](https://crates.io/crates/oboron-cli-conformance)).

### Performance

- **Dynamic-format dispatch** (`Omnib::*`, `Ob::*`,
  `dec_any_format`) is alloc-parity with the in-tree
  predecessor thanks to obcrypt's zero-extra-allocation
  `encrypt_into` / `decrypt_into` variants and a
  workspace-level `[profile.release] lto = true` hoist
  (cross-crate inlining is critical now that the hot path
  crosses a workspace boundary).


[oboron v0.7.1] - 2026-05-20
------------------------------

### Changed

- **Repository URL migrated** to `gitlab.com/oboron/oboron-rs`.
  The GitHub repository at `github.com/ob-enc/oboron-rs` is
  frozen at this release as a historical reference of pre-1.0
  development; future releases publish from GitLab with a
  rewritten per-release git history.
- **README updates** reflecting the migration.

No code changes; metadata-only release to register the
canonical-repo move on crates.io before the GitHub mirror
was frozen.


[oboron-cli v0.3.1] - 2026-05-20
----------------------------------

Final release of `oboron-cli` from the `oboron-rs`
workspace. Future releases publish from
[`oboron-tools-rs`](https://gitlab.com/oboron/oboron-tools-rs).

### Changed

- Repository URL → `gitlab.com/oboron/oboron-tools-rs`.
- `oboron` dependency bumped from `0.7.0` to `0.7.1`.
- README updates reflecting the move.


[oboron-py v0.7.1] - 2026-05-20
---------------------------------

### Changed

- Repository URL → `gitlab.com/oboron/oboron-rs`.
- `oboron-py` is no longer published to crates.io; PyPI
  is the sole distribution channel. Previous crates.io
  releases yanked.
- Version jump from `0.3.0` to `0.7.1` to track the
  `oboron` library version going forward.
- `oboron` dependency bumped from `0.7.0` to `0.7.1`.


[oboron v0.7.0] - 2026-03-02
------------------------------

### Security

- **`MasterKey` now zeroizes key material on drop.**
  - Added `Zeroize` and `ZeroizeOnDrop` derives (via `zeroize` crate) to `MasterKey`,
    ensuring the 512-bit key is securely wiped from memory when the struct is dropped.
  - New dependency: `zeroize = { version = "1", features = ["derive"] }`.

### Changed

- **`dec_any_format`: single-pass encoding classification.**
  - Replaced multiple `chars().any(...)` passes with a single byte-scan loop, improving
    performance of auto-format detection.
- **`upbc::decrypt`: in-place CBC decryption.**
  - Changed signature to `decrypt(master_key: &[u8; 64], data: &mut [u8])`.
  - Decryption now operates directly on the decode buffer, eliminating one intermediate
    heap allocation per `upbc` decrypt call.


[oboron v0.6.0] - 2026-03-01
------------------------------

### Changed

- **`Error` enum hardened for forward compatibility.**
  - Added `#[non_exhaustive]` attribute so new error variants can be added in
    future minor versions without breaking downstream `match` exhaustiveness.
  - Added `Clone`, `PartialEq`, and `Eq` derives for ergonomic error comparison
    in tests and application code.

### Fixed

- Fixed typo in `Cargo.toml` feature comment: `unchecked-utf8` description
  corrected from "enhacement" to "enhancement".


[oboron-py v0.2.0] - 2026-03-01
---------------------------------

### Changed (Breaking)

- **Legacy scheme simplified to a single format.**
  - The four legacy encoding variants (`LegacyB32`, `LegacyC32`, `LegacyB64`,
    `LegacyHex`) have been replaced by a single `Legacy` class.
  - `Legacy` uses lowercase RFC base32 encoding (matching production obtext).
  - Format identifier changed from `"legacy.b32"` to `"legacy"`.
  - Python format constant renamed: `formats.LEGACY_B32` → `formats.LEGACY`.

### Fixed

- `Omnib.autodec()` / `Obz.autodec()` legacy fallback now correctly decodes
  lowercase RFC base32 obtext (was erroneously using uppercase alphabet).
- `Obz` instances configured with the legacy format no longer panic on
  `enc()`/`dec()` calls.


[oboron v0.5.0] - 2026-03-01
------------------------------

### Changed (Breaking)

- **Legacy scheme simplified to a single format.**
  - The four legacy encoding types (`LegacyB32`, `LegacyC32`, `LegacyB64`,
    `LegacyHex`) have been replaced by a single `Legacy` struct
    (`oboron::ztier::Legacy`).
  - `Legacy` uses a new `BASE32_RFC_LOWER` lowercase RFC base32 alphabet
    for both encoding and decoding, producing lowercase obtext that matches
    the production format.
  - The format string for the legacy scheme is now `"legacy"` (was `"legacy.b32"`).
    `Format::from_str("legacy")` resolves to
    `Format::new(Scheme::Legacy, Encoding::B32)`.
  - `Format::Display` for `Scheme::Legacy` now emits `"legacy"` instead of
    `"legacy.b32"`.
  - Format constant renamed: `LEGACY_B32` / `LEGACY_B32_STR` →
    `LEGACY` / `LEGACY_STR`.
  - `Obz::set_format("legacy")` and `Obz::set_scheme(Scheme::Legacy)` now
    work correctly without requiring `--b32` in the CLI.

### Fixed

- `zdec_auto` legacy fallback used the wrong (uppercase) base32 alphabet;
  fixed to use `BASE32_RFC_LOWER` matching `Legacy::dec`.
- `Obz::enc` / `Obz::dec` with `Scheme::Legacy` no longer hit
  `unreachable!()` panic; now dispatches through `Legacy::from_master_secret`.

### Added

- `oboron::base32::BASE32_RFC_LOWER`: lowercase RFC 4648 base32 alphabet
  (no padding), used internally by the `Legacy` scheme.
- Production test vectors for the legacy scheme: `tests/test-vectors-legacy.jsonl`
  with 165 vectors tied to the actual production secret (embedded as a
  self-contained `meta` entry in the JSONL file).


[1.0.0-rc.1] - 2026-01-09
-------------------------

This is a major revision with a completely revised API and with breaking changes in the data format.

### Changed (summary)

- API
  - Renamed schemes:
    - ob01  -> zrbcx
    - ob21p -> upbc
    - ob31  -> aags
    - ob31p -> apgs
    - ob32  -> aasv
    - ob32p -> apsv
    - ob70  -> mock1
    - ob71  -> mock2
    - ob00  -> legacy
  - new names reflect algorithm properties better in the prefix
    - first letter:
      - "a": authenticated (ob3x tier)
      - "u": unauthenticated (ob2x tier)
      - "z": insecure (ob0x, ob1x tiers)
      - "t": testing (ob7x tier)
    - second letter: mode
      - "d": deterministic / no avalanche effect
      - "a": avalanche (deterministic + hash-like - change in any one byte changes obtext completely)
      - "r": referenceable (avalanche effect restricted to the prefix: like "a" but effect localized in the prefix only)
      - "p": probabilistic
  - "a"-scheme names use last 2 letters for algorithms (instead of numbers):
    - "gs": AES-GCM-SIV
    - "sv": AES-SIV

  - Renamed formats:
    - ob01:c32  -> zrbcx.c32
    - ob01:b32  -> zrbcx.b32
    - ob21p:b64 -> upbc.b64
    - ob31:hex  -> aags.hex
    - ob32p:c32 -> aasv.c32
    - etc.
    - new format uses "." as separator instead of colon

  - Renamed structs:
    - Ob01, Ob01Base32Crockford  -> ZrbcxC32
    - Ob01Base32Rfc              -> ZrbcxB32
    - Ob01Base64                 -> ZrbcxB64
    - Ob01Hex                    -> ZrbcxHex
    - Ob31, Ob31Base32Crockford  -> AagsC32
    - Ob31Base32Rfc              -> AagsB32
    - Ob31Base64                 -> AagsB64
    - Ob31Hex                    -> AagsHex
    - Ob31p, Ob31pBase32Crockford-> ApgsC32
    - Ob31pBase32Rfc             -> ApgsB32
    - Ob31pBase64                -> ApgsB64
    - Ob31pHex                   -> ApgsHex
    - etc.

  - ObMulti renamed -> Omnib
    - enc()
    - dec()
    - autodec() -> autodec(obtext) - full autodecode

  - ObtextCodec API change:
    - renamed dec_strict() -> dec()
    - removed former scheme-autodetecting dec() method
    - no more autodetection on static types

  - Removed ObFlex; Ob inherited full ObFlex functionality

  - Ob API change
    - former scheme-autodetecting dec() now strict (like in fixed format types)
    - autodec() works like in Omnib but optimized (tries current encoding first)

  - Insecure schemes separated in ztier module - no shared code with secure schemes
    - Equivalent generic structs/classes: Obz for Ob, Omnibz for Ominb
    - No more key sharing between ztier and others: ztier uses "secret" concept instead of "key"
    - ztier secret: 256 bits (43-char base64)

  - Format constans from str to &Format:
    - AASV_C32: &str "aasv.c32" -> &Format{Scheme::Aasv, Encoding::C32}
    - new AASV_C32_STR constants

  - Feature-gated convenience functions ("convenience" feature)

- Data format
  - 2-byte scheme marker instead of single scheme byte

- Algorithm changes:
  - zrbcx (former ob01): instead of reversing ciphertext, XORs first block with last
  - upbc (former ob21p): no longer reverses ciphertext; uses 256-bit AES-CBC


[0.3.0] - 2025-12-18
--------------------

### Changed

- Post-decryption UTF-8 validation now default

### Added

- "unchecked-utf8" feature for previous unsafe behavior (non-validated post-decryption return value)


[0.2.0] - 2025-12-18
--------------------

### Changed

- BREAKING CHANGES:
  - Changed payload: scheme byte mixed-in with ciphertext
  - Changed hardcoded key ("keyless"-feature-gated): now starts with "OBKEYz..."

- Regenerated tests/test-vectors.jsonl


[0.1.1] - 2025-12-19
--------------------

### Fixed

- Fixed wrong feature gate ("hex-keys"/"bytes-keys" mix-up)

### Added

- Test to ensure the keys feature gates mix-up doesn't happen again.

### Changed

- Harmonize parameter names - consitently use `key`: base64; `key_hex`: hex; `key_bytes`: bytes


[0.1.0] - 2025-12-17
--------------------

First release
