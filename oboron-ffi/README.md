# oboron-ffi

A C ABI for [oboron](https://oboron.org) — a thin `extern "C"`
surface over the oboron core so languages without a first-class
Rust bridge can call it through FFI. It is the third binding
strategy alongside its siblings:

| binding        | mechanism      | consumers          |
|----------------|----------------|--------------------|
| `oboron-py`    | PyO3           | Python             |
| `oboron-wasm`  | wasm-bindgen   | JS / TS (browser)  |
| **`oboron-ffi`** | **C ABI**    | Perl, C#, Java (Panama), Ruby, C, … |

Unlike PyO3 and wasm-bindgen, nothing here is automatic: the
boundary speaks only C primitives and raw pointers, so
marshalling, memory ownership, errors, and panics are handled by
hand. One `extern "C"` surface, then each language is a thin
binding against the generated header.

## The contract

- **Strings in** — NUL-terminated UTF-8 (`const char *`).
  oboron's inputs (plaintext, obtext, hex keys, format strings)
  are all NUL-safe.
- **Strings out** — heap-allocated, written through an `out`
  parameter, **owned by the caller**, released with
  `oboron_string_free()`. Never libc `free` — the buffer is
  Rust-allocated.
- **Return** — a status code: `0` (`OBORON_OK`) on success,
  negative for an FFI-layer fault (null pointer, non-UTF-8 input,
  caught panic), positive for an oboron error. On any nonzero
  return do **not** read `*out`; fetch a message from
  `oboron_last_error()` (valid until the next call on the thread).
- **Panics** never cross the boundary — every entry point is
  wrapped in `catch_unwind`.

## Build

```sh
cargo build --release -p oboron-ffi
# → target/release/liboboron_ffi.{so,dylib,dll}  (cdylib)
#   target/release/liboboron_ffi.a               (staticlib)
```

The committed C header lives in [`include/oboron.h`](include/oboron.h).
Regenerate it from the Rust source with
[cbindgen](https://github.com/mozilla/cbindgen):

```sh
cbindgen --config cbindgen.toml --output include/oboron.h
```

## Try it

- C: [`examples/smoke.c`](examples/smoke.c) — build/run command in
  its header comment.
- Perl: [`examples/oboron.pl`](examples/oboron.pl) — `FFI::Platypus`
  reference binding (the round-trip the Rust tests do, across the
  real FFI boundary).

## Scope

Exposes the core string-in/string-out API: `generate_key`, `enc` /
`dec`, and the keyless variants (behind the `keyless` feature). The
binary CBOR path (`(ptr, len)` rather than a C string) is not
exposed yet. Scheme features mirror oboron's, so a consumer can trim
the ABI to the schemes it needs.
