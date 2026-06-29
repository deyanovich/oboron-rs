# Security model — `oboron`

`oboron` is the string-in / string-out layer of the oboron family.
It adds compact text encoding and key-text parsing on top of the
[`obcrypt`](https://gitlab.com/oboron/obcrypt-rs) authenticated-
encryption core. The cryptography itself — algorithm choices,
key derivation, usage limits, and the full threat model — lives in
obcrypt and is documented in its
[`SECURITY.md`](https://gitlab.com/oboron/obcrypt-rs/-/blob/master/obcrypt/SECURITY.md).
This document covers the guarantees specific to the `oboron` layer;
read it alongside obcrypt's.

## What oboron provides

`oboron` encrypts a UTF-8 **string** under one of four authenticated
schemes and encodes the result to compact **obtext** (Crockford
base32, RFC base32, base64url, or hex). Decoding reverses both steps.

All four schemes — `dsiv`, `psiv`, `dgcmsiv`, `pgcmsiv` — are
authenticated (confidentiality + integrity), inheriting obcrypt's
guarantees:

| Property | All four schemes |
|---|---|
| Confidentiality | yes |
| Authenticity (integrity) | yes (AEAD tag) |
| Tampering detection | yes (`DecryptionFailed`) |
| Wrong-key detection | yes (`DecryptionFailed`) |
| Wrong-scheme detection | yes (`DecryptionFailed`) |
| Determinism | `dsiv` / `dgcmsiv` deterministic; `psiv` / `pgcmsiv` probabilistic |

The obtext carries no scheme marker — the scheme is part of the
caller's context, exactly as in obcrypt. Decoding under the wrong
scheme fails the authentication check, like a wrong key.

The `dec` path **always validates UTF-8** and never returns an
unchecked string: non-UTF-8 plaintext is rejected with
`Error::InvalidUtf8` (spec §4.1). There is no `unchecked-utf8`
escape hatch.

## What oboron does not provide

`oboron` is a thin layer; it adds no cryptography of its own and
delegates every cryptographic guarantee to obcrypt. In particular it
does **not** add key exchange, key rotation, transport, or any
side-channel hardening beyond what obcrypt and its upstream
RustCrypto primitives provide. See obcrypt's threat model and
"what it does not provide" sections.

## Usage limits

The deterministic schemes (`dsiv`, `dgcmsiv`) encrypt under a fixed
all-zero nonce. This is sound **only** because AES-SIV and
AES-GCM-SIV are nonce-misuse-resistant
([RFC 5297](https://www.rfc-editor.org/rfc/rfc5297),
[RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)): the sole
confidentiality cost is the deterministic-equality leak those
schemes expose by design — equal plaintexts produce equal obtext.

The binding limit is therefore **cumulative data volume per key**,
not nonce reuse: security degrades only as the total data encrypted
under one master key approaches the AES-GCM-SIV birthday bound — far
out of practical reach for the short-string workloads oboron targets.
The library is stateless and tracks no cumulative usage, so honoring
that bound is a deployment responsibility: rotate the master key well
before it under high-volume use. obcrypt's `SECURITY.md` carries the
detailed analysis.

## Key handling

The canonical — and only — key text encoding is **128 lowercase hex
characters** (spec §3.3). There is no base64 key form. Uppercase hex
is rejected, so a key has exactly one textual representation.

The 64-byte master key is stored in obcrypt's `Key` type, which
zeroizes its bytes on drop; oboron's transient hex-decode and
key-generation buffers are wrapped in `Zeroizing` so they zero on
drop too. Generate keys with `oboron::generate_key()`.

## Mock schemes

The testing-only `mock1` / `mock2` schemes perform **no encryption**.
They are gated behind the off-by-default `mock` feature and are not
selectable through any string/config channel (`Scheme::from_str`,
`Format::from_str`, the string-format factories, the convenience
functions, `Ob`, `Omnib`, and the bindings all reject them) — a
no-encryption scheme must never be reachable from external input.
Construct them explicitly by value if needed in tests.

## Audit status

Neither `oboron` nor its `obcrypt` core has been independently
security-audited. The cryptographic constructions follow RFC 5297,
RFC 8452, and RFC 5869, and the wire format is pinned by the oboron
protocol's cross-implementation test vectors. Evaluate accordingly
for high-assurance use.

## Reporting vulnerabilities

If you find a security issue in `oboron`, please email the maintainer
at **dev@deyanovich.org** with the subject line beginning
`[oboron security]`. Include reproduction details, affected versions,
and (if possible) a proposed fix or mitigation.

For non-security bugs, file an issue on the
[GitLab repository](https://gitlab.com/oboron/oboron-rs/-/issues).

Coordinated disclosure: I'll acknowledge receipt within 7 days and
work with you on a disclosure timeline appropriate to the severity.
