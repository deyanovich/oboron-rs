# oboron-ffi — TODO

Next steps for the C ABI binding. Written for a cold start: read
the Context first, then work the steps in priority order.

## Context

`oboron-ffi` is a C ABI over the oboron core — the third binding
strategy alongside `oboron-py` (PyO3) and `oboron-wasm`
(wasm-bindgen). It exists so languages without a first-class Rust
bridge (Perl, C#, Java via Panama, Ruby, C, …) can call oboron
through FFI. One `extern "C"` surface; each language is then a thin
binding against the generated header.

Current state — **scaffold complete and verified**:

- `src/lib.rs` exposes `oboron_generate_key`, `oboron_enc` /
  `oboron_dec`, the two keyless variants (behind the `keyless`
  feature), plus `oboron_last_error` and `oboron_string_free`
  — 7 functions, all exported unmangled.
- The contract (full text in the `src/lib.rs` module docs and
  `README.md`): inputs are NUL-terminated UTF-8; each `out` string
  is heap-allocated and caller-owned, freed with
  `oboron_string_free` (never libc `free`); the return is a status
  code (0 ok, <0 FFI fault, >0 oboron error) with a message from
  the thread-local `oboron_last_error`; panics are caught at every
  boundary via `catch_unwind`, centralised in the `finish` helper.
- `include/oboron.h` is the committed reference header consumers
  bind to; `cbindgen.toml` regenerates it.
- `examples/smoke.c` (a working C consumer) and
  `examples/oboron.pl` (an `FFI::Platypus` reference) demonstrate
  the round-trip across the boundary.

Confirm the baseline before changing anything:

- `cargo test -p oboron-ffi` → 4 passing tests.
- `cargo build -p oboron-ffi` then build & run `examples/smoke.c`
  (command in its header) → prints a live round-trip.
- `nm -D --defined-only target/debug/liboboron_ffi.so | grep
  oboron_` → 9 `T` symbols.

## Next steps

1. **Binary / CBOR path — decide the crate split first.**
   The ABI is string-only (NUL-terminated UTF-8), matching oboron's
   string-in/string-out scope. Binary payloads (the CBOR encoding
   obsigil uses) can contain NUL and go through `obcrypt`
   (bytes-in/bytes-out), not oboron. The clean, consistent move is
   a sibling **`obcrypt-ffi`** crate (mirroring the oboron/obcrypt
   split) exposing `(const uint8_t *ptr, size_t len)` in and a
   length-returning out buffer with its own `*_bytes_free`, rather
   than bloating oboron-ffi with a base64-wrapped bytes path.
   Confirm that split, then build it the same way (thread-local
   last-error, `finish`-style helper, paired free).

2. **cbindgen drift guard.** `include/oboron.h` is committed and
   hand-maintainable. Add a CI check that runs `cbindgen --config
   cbindgen.toml` and fails if the output differs from the
   committed header, so the ABI surface can't silently drift.
   (Optionally a `build.rs`, but gate it behind a feature/env so
   the default offline build doesn't require cbindgen.)

3. **Conformance vectors through the ABI.** Run the
   cross-implementation test vectors (oboron-test-vectors /
   oboron-cli-conformance) through the C ABI and assert
   byte-identical output with the Rust/Go/Python paths. This is the
   real proof the binding is conformant, not merely self-consistent.

4. **Artifact distribution.** Decide and automate how consumers
   obtain `liboboron_ffi.{so,dylib,dll}`: prebuilt per-platform
   artifacts attached to releases vs build-from-source. This blocks
   every downstream language package, so it gates step 5.

5. **Downstream Perl dist (`oboron-perl`).** A separate package:
   an `FFI::Platypus` binding plus an `Alien::`/build step that
   compiles or bundles `liboboron_ffi`, packaged for CPAN.
   `examples/oboron.pl` is the starting reference. The same C ABI
   then serves C#, Ruby, and Java (Panama) next.

6. **ABI stability + versioning.** Once the surface settles,
   document the stability contract (the header is the contract — no
   breaking change without a major bump) and fix the versioning
   policy relative to oboron core (currently tracks 0.9.x). Add an
   `oboron_abi_version()` so consumers can check at runtime.

7. **Platform & polish.**
   - Windows symbol export / calling convention, and the
     `liboboron_ffi` → `oboron_ffi.dll` naming difference.
   - A test that deliberately triggers and catches a panic to
     exercise the `catch_unwind` path (no current oboron call
     panics, so it is untested).
   - Document the threading model (`last_error` is per-thread).
   - Expose `generate_key_bytes` / fixed-format codecs only if a
     consumer actually needs them — keep the surface minimal.
