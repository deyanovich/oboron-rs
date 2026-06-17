# obcrypt-refactor: Performance Comparison

Side-by-side benchmark of `oboron` before and after the refactor that
moves the cryptographic core out into a separate `obcrypt-rs` crate.

The refactor keeps obtext encoding, format-string parsing, and UTF-8
validation inside `oboron`; only the byte-level crypto (per-scheme
encrypt/decrypt for the authenticated schemes) is delegated
to `obcrypt`. oboron's `enc_to_format` / `dec_from_format` and the
`codec.rs` static-dispatch macros call `obcrypt::schemes::*::{encrypt,
decrypt}` directly.

## Build profile

The refactor introduces a workspace → path-dep boundary
(`obcrypt = { path = "../obcrypt-rs" }`). Without LTO, the compiler
can't inline across that boundary, which is fatal on a hot path where
the AEAD call is just a few hundred nanoseconds. Pre-refactor, the
`oboron` package set `[profile.release] lto = true` — but Cargo
ignores per-package profiles on non-root members, so it was a no-op.
The refactor hoists the profile to **workspace level**, so LTO is
genuinely active for both release and bench builds:

```toml
# Cargo.toml (workspace root)
[profile.release]
opt-level = 3
lto = true
codegen-units = 1

[profile.bench]
inherits = "release"
```

All benchmark numbers below are measured under this profile on both
sides of the comparison.

## Method

- Hardware: same machine, runs back-to-back.
- Harness: criterion, `--warm-up-time 1 --measurement-time 2
  --sample-size 30`.
- 16-byte plaintext, Crockford base32 (`c32`) encoding.
- Two probe schemes:
  - `dsiv` — deterministic AES-SIV, representative AEAD scheme.
  - `mock1` — identity (no crypto), isolates pure layering /
    cross-crate overhead from AEAD cost.

## Results — `Omnib` dynamic path (post-bypass + workspace LTO)

| Scheme | Op      | master+LTO | branch+LTO | Δ %    | Verdict           |
|--------|---------|-----------:|-----------:|-------:|-------------------|
| dsiv   | enc     |   338.2 ns |   340.0 ns |  +0.5% | noise             |
| dsiv   | dec     |   344.9 ns |   338.8 ns |  −1.8% | improved (p<.05)  |
| mock1  | enc     |    78.8 ns |    75.4 ns |  −4.3% | noise             |
| mock1  | dec     |    40.8 ns |    43.9 ns |  +7.5% | regressed (p<.05) |

For real-world AEAD schemes (`dsiv`) the crypto cost dominates and
the layering overhead is invisible — both ops within ~2% of
master. For `mock1` (no crypto, pure layering signal) the worst case
is dec at +7.5%, which is **+3 ns absolute** — the residual cost of
the cross-crate call into `obcrypt::schemes::mock1::decrypt` that LTO
doesn't fully erase, plus criterion noise.

## Why the path was re-shaped four times

This benchmark went through several rounds, each diagnostic of one
specific cost source:

1. **Initial refactor** (branch commit `4de102b`): dynamic path
   routed through `obcrypt::encrypt_into` / `decrypt_as` /
   `decrypt`. Caused ~5–11% regression on `Omnib::dec` across
   all schemes. The framed obcrypt API adds an extra dispatch layer
   that the inliner couldn't collapse under default Cargo profile.
2. **Bypass framed API** (this commit's `enc.rs` / `dec.rs`): call
   per-scheme `obcrypt::schemes::*::encrypt` / `decrypt` directly.
   Recovered most of the dec regression but enc still regressed
   +5–7% on deterministic schemes.
3. **Per-scheme split in obcrypt** (obcrypt-rs commit `1cafca5`):
   per-scheme owned `encrypt` / `decrypt` had been routed through
   their `_into` counterparts, paying the `TailBuffer` indirection
   cost even for "give me a Vec" callers. Split each form so it
   uses the right primitive: owned calls the AEAD's own `encrypt` /
   `decrypt` (exact-capacity Vec, no adapter); `_into` keeps
   `TailBuffer` + `encrypt_in_place` for zero-extra-allocation.
4. **Workspace LTO** (this commit's `Cargo.toml`): moved
   `[profile.release] lto = true` from the (silently-ignored)
   `oboron` package profile to the workspace profile. This is the
   change that finally lets the inliner cross the
   workspace → path-dep boundary.

The mock1-isolation benchmark (per user suggestion) made the
diagnosis tractable — each round's residual cost was visible on
mock1 even when AEAD-scheme noise hid it.

## Decision

**Within noise on real schemes; ~7% worst-case (3 ns absolute) on
the mock1-only layering test.** Refactor is safe to merge once the
user is satisfied with the numbers. The branch stays unmerged until
that confirmation.

## Reproducing

```bash
# Baseline (master with the LTO workspace profile so it's a fair
# fight — the package-level [profile.release] in oboron/Cargo.toml
# is silently ignored).
git checkout master
# Temporarily add the same workspace-level profile to the workspace
# Cargo.toml; also add the mock1 specs to benchmarks_omnib.jsonl
# (see this branch's diff for both).
cargo bench -p oboron --bench omnib -- --warm-up-time 1 \
  --measurement-time 2 --sample-size 30 '(dsiv|mock1)\.c32/16B$'

# Refactor
git checkout obcrypt-refactor
cargo bench -p oboron --bench omnib -- --warm-up-time 1 \
  --measurement-time 2 --sample-size 30 '(dsiv|mock1)\.c32/16B$'
```
