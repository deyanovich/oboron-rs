# Changelog

All notable changes to `oboron-py` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


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
