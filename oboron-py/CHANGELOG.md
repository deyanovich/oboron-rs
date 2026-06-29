# Changelog

All notable changes to `oboron-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


## [1.0.2] - 2026-06-29

### Fixed

- Added the **`py.typed`** marker (PEP 561). The bundled `_oboron.pyi`
  type stubs were present and the `Typing :: Typed` classifier was
  set, but without the marker type checkers (mypy, pyright) ignored
  the stubs and treated the package as untyped. The stubs are now
  actually honored by downstream type checking. Packaging-only change
  — no API or behavior difference.


## [1.0.1] - 2026-06-28

Tracks oboron core **1.0.1** — a documentation / metadata / hygiene
cleanup with no API or wire-format change. Binding-side fixes:

### Documentation

- Replaced the MIT-only README license badge with a dual
  `MIT OR Apache-2.0` badge linking the in-README license section
  (the old badge pointed at a nonexistent `LICENSE` file).
- The PyPI package summary now reads "authenticated symmetric
  encryption", matching the crate description.


## [1.0.0] - 2026-06-28

First stable release, tracking oboron core **1.0.0**
(authenticated-only, protocol spec 1.0).

### Changed

- Depend on the published **oboron / obcrypt 1.0.0** (was the
  `1.0.0-rc1` prerelease).
- Declare the real dual license (`MIT OR Apache-2.0`) in the package
  metadata.

### Removed

- The no-encryption `mock` codecs are no longer in the default
  feature set, so they are not shipped in the published wheel (still
  available behind `--features mock` for tests).


## [1.0.0-rc1] - 2026-06-16

Catches the Python bindings up to oboron core 1.0.0-rc1
(authenticated-only, protocol spec 1.0). Pure core: the
unauthenticated / obfuscation (z-tier) layer is no longer bound
here.

### Changed

- **Schemes renamed** to the property-prefixed form: codec
  classes `AasvC32`→`DsivC32`, `ApsvB64`→`PsivB64`,
  `AagsHex`→`DgcmsivHex`, `ApgsC32`→`PgcmsivC32`, and the
  matching `oboron.formats.*` constants.

### Removed

- **The z-tier / obu surface** — the `oboron.ztier` submodule and
  the `Obz` / `Omnibz` / `Zrbcx*` / `Zmock1*` / `Legacy` classes,
  plus `generate_secret()` / `generate_secret_bytes()`. The
  unauthenticated and obfuscation schemes live in the separate
  `obu` package; `oboron-py` no longer depends on the `obu` crate.
- **The `upbc` codec classes** (`UpbcC32`/etc.).
- **`autodec` / `autodec_keyless`** — the module functions and the
  `Ob` / `Omnib` methods. The scheme is supplied by the caller via
  the format.
- **Base64 keys** — `from_base64_key` / `key_base64` and the
  `base64-keys` feature. Keys are 128-character hex.


## [0.9.0] - 2026-05-22

First PyPI publication of `oboron-py` under the harmonized
`oboron` 0.9.0 core API.

### Added

- **Custom exception hierarchy.** All errors inherit from
  `oboron.OboronError`:
  - `InvalidKey` — bad hex / base64 / wrong-length key
  - `InvalidFormat` — unknown scheme, unknown encoding,
    malformed format string
  - `EncryptionFailed` — AEAD failure / empty plaintext
  - `DecryptionFailed` — tag check, padding,
    obtext-decode failure, post-decrypt UTF-8 validation
- **`oboron.ztier` submodule** for z-tier codecs and the
  `ZtierBase` virtual-subclass anchor. All z-tier classes
  (`ZrbcxC32`/etc., `Legacy`, `Zmock1*`, plus `Obz` /
  `Omnibz`) register here.
- **`generate_secret()` / `generate_secret_bytes()`** module
  functions, mirroring `generate_key()` / `generate_key_bytes()`
  for the z-tier 32-byte secret form.

### Changed

- **Hex-canonical key and secret strings throughout.** Keys
  are now documented as 128-character hex strings; secrets as
  64-character hex strings. Both still accept the legacy
  base64 forms (86 / 43 chars respectively) as a transitional
  input — the oboron core length-routes them. Returned by
  `.key` / `.secret` getters: hex.
- **Tracks oboron core 0.9.0**, which moved hex to canonical
  on the z-tier and harmonized constructor naming to
  `from_<format>_<target>` (e.g. `from_hex_key`,
  `from_base64_secret`).
- **PyO3 upgraded to 0.28 with the stable ABI** (`abi3-py38`).
  One wheel per platform now covers CPython 3.8+ instead of
  one wheel per Python minor version.
- **Workflow:** PyPI publishing moved to GitHub Actions
  (`.github/workflows/publish-pypi.yml`) with OIDC trusted
  publishing, triggered by `py/v*` tag pushes to the GitHub
  mirror.

### Notes

- The `oboron` PyPI package name is unchanged from earlier
  pre-publication revisions; this is the first version to
  ship under the harmonized 0.9.0 core.
