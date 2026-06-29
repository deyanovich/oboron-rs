//! C ABI for oboron — a thin `extern "C"` surface over the oboron
//! core so languages without a first-class Rust bridge (Perl, C#,
//! Java via Panama, Ruby, …) can call it through FFI.
//!
//! Unlike the PyO3 (`oboron-py`) and wasm-bindgen (`oboron-wasm`)
//! bindings, nothing here is automatic: the boundary speaks only C
//! primitives and raw pointers, so marshalling, ownership, errors,
//! and panics are all handled by hand. The contract every consumer
//! relies on:
//!
//! - **Strings in** are NUL-terminated UTF-8 (`const char *`).
//!   oboron's inputs — plaintext, obtext, hex keys, format strings —
//!   are all NUL-safe, so plain C strings suffice. (A binary CBOR
//!   payload would need a `(ptr, len)` pair instead; not exposed
//!   here yet.)
//! - **Strings out** are heap-allocated NUL-terminated UTF-8 written
//!   through an `out` parameter. The caller **owns** them and MUST
//!   release each with [`oboron_string_free`]. Freeing with libc
//!   `free` is undefined behavior — the buffer is Rust-allocated.
//! - **Return value** is a status code: [`OBORON_OK`] (0) on
//!   success, negative for an FFI-layer fault (null pointer,
//!   non-UTF-8 input, caught panic), positive for an oboron error.
//!   On any nonzero return the caller MUST NOT read `*out`; a
//!   human-readable message is available from [`oboron_last_error`].
//! - **Panics never cross the boundary**: every entry point is
//!   wrapped in `catch_unwind`.

// Every `extern "C"` entry point dereferences caller-supplied raw
// pointers by design — pointer validity is the documented C-caller
// contract (see the module docs above), not something Rust can enforce.
// The `unsafe`-fn marker would be invisible to the C callers these are
// written for, so we scope the safety reasoning to the per-call
// `unsafe { cstr(...) }` blocks instead.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

/// Success.
pub const OBORON_OK: i32 = 0;
/// A required pointer argument was null.
pub const OBORON_ERR_NULL_ARG: i32 = -1;
/// An input string was not valid UTF-8.
pub const OBORON_ERR_UTF8: i32 = -2;
/// The result could not be returned as a C string (interior NUL).
pub const OBORON_ERR_INTERIOR_NUL: i32 = -3;
/// A panic was caught at the FFI boundary.
pub const OBORON_ERR_PANIC: i32 = -4;
/// oboron rejected the operation; see [`oboron_last_error`].
pub const OBORON_ERR_OBORON: i32 = 1;

thread_local! {
    /// Per-thread last-error message, so the function signatures stay
    /// clean (status + out) while still carrying oboron's error text.
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<Vec<u8>>) {
    let mut bytes = msg.into();
    bytes.retain(|&b| b != 0); // a stored message can't contain NUL
    let cstr = CString::new(bytes).expect("interior NULs stripped above");
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(cstr));
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

/// Map an oboron error onto the C status code, recording its text.
fn oboron_err(e: oboron::Error) -> i32 {
    set_last_error(e.to_string());
    OBORON_ERR_OBORON
}

/// Borrow an incoming C string as `&str`.
///
/// # Safety
/// `p` must be null or a valid NUL-terminated UTF-8 string that
/// outlives the returned borrow.
unsafe fn cstr<'a>(p: *const c_char, name: &str) -> Result<&'a str, i32> {
    if p.is_null() {
        set_last_error(format!("argument `{name}` was null"));
        return Err(OBORON_ERR_NULL_ARG);
    }
    CStr::from_ptr(p).to_str().map_err(|_| {
        set_last_error(format!("argument `{name}` was not valid UTF-8"));
        OBORON_ERR_UTF8
    })
}

/// Run `f` and marshal its `Result<String, i32>` into the ABI: on
/// success write a freshly heap-allocated C string to `*out` and
/// return [`OBORON_OK`]; on error leave `*out` untouched (the caller
/// must not read it) and return the code. Catches panics.
fn finish(out: *mut *mut c_char, f: impl FnOnce() -> Result<String, i32>) -> i32 {
    let ran = catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            set_last_error("output pointer argument was null");
            return OBORON_ERR_NULL_ARG;
        }
        clear_last_error();
        match f() {
            Ok(s) => match CString::new(s) {
                // SAFETY: `out` checked non-null above; caller owns it.
                Ok(cs) => {
                    unsafe { *out = cs.into_raw() };
                    OBORON_OK
                }
                Err(_) => {
                    set_last_error("output contained an interior NUL byte");
                    OBORON_ERR_INTERIOR_NUL
                }
            },
            Err(code) => code,
        }
    }));
    ran.unwrap_or_else(|_| {
        set_last_error("oboron-ffi: caught a panic at the FFI boundary");
        OBORON_ERR_PANIC
    })
}

/// Borrow this thread's last error message as a NUL-terminated C
/// string, or null if the last call on this thread succeeded.
///
/// The pointer is valid only until the next `oboron_*` call on this
/// thread; copy it if you need to keep it. Do **not** free it.
#[no_mangle]
pub extern "C" fn oboron_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| match &*slot.borrow() {
        Some(cstr) => cstr.as_ptr(),
        None => ptr::null(),
    })
}

/// Free a string this library returned through an `out` parameter.
/// Passing null is a no-op. Passing any other pointer, or freeing the
/// same one twice, is undefined behavior.
#[no_mangle]
pub extern "C" fn oboron_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: per the contract `s` came from `CString::into_raw`.
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// Generate a fresh random key as a 128-char hex string.
#[no_mangle]
pub extern "C" fn oboron_generate_key(out: *mut *mut c_char) -> i32 {
    finish(out, || Ok(oboron::generate_key()))
}

/// Encrypt `plaintext` under `format` (e.g. `"psiv.b64"`) and `key`
/// (128-char hex). Writes the obtext to `*out`.
#[no_mangle]
pub extern "C" fn oboron_enc(
    plaintext: *const c_char,
    format: *const c_char,
    key: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    finish(out, || {
        let plaintext = unsafe { cstr(plaintext, "plaintext") }?;
        let format = unsafe { cstr(format, "format") }?;
        let key = unsafe { cstr(key, "key") }?;
        oboron::enc(plaintext, format, key).map_err(oboron_err)
    })
}

/// Decrypt `obtext` with an explicit `format` and `key`. Writes the
/// plaintext to `*out`. The scheme is supplied by `format`, not
/// detected from the obtext.
#[no_mangle]
pub extern "C" fn oboron_dec(
    obtext: *const c_char,
    format: *const c_char,
    key: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    finish(out, || {
        let obtext = unsafe { cstr(obtext, "obtext") }?;
        let format = unsafe { cstr(format, "format") }?;
        let key = unsafe { cstr(key, "key") }?;
        oboron::dec(obtext, format, key).map_err(oboron_err)
    })
}

/// Encrypt `plaintext` keyless (oboron's public built-in key) under
/// `format`. Writes the obtext to `*out`. Provides no secrecy or
/// authentication against an adversary — see the obsigil manifest
/// layer for where this is appropriate.
#[cfg(feature = "keyless")]
#[no_mangle]
pub extern "C" fn oboron_enc_keyless(
    plaintext: *const c_char,
    format: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    finish(out, || {
        let plaintext = unsafe { cstr(plaintext, "plaintext") }?;
        let format = unsafe { cstr(format, "format") }?;
        oboron::enc_keyless(plaintext, format).map_err(oboron_err)
    })
}

/// Decrypt a keyless `obtext` with an explicit `format`. Writes the
/// plaintext to `*out`.
#[cfg(feature = "keyless")]
#[no_mangle]
pub extern "C" fn oboron_dec_keyless(
    obtext: *const c_char,
    format: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    finish(out, || {
        let obtext = unsafe { cstr(obtext, "obtext") }?;
        let format = unsafe { cstr(format, "format") }?;
        oboron::dec_keyless(obtext, format).map_err(oboron_err)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read and take ownership of an `out` string the way a C caller
    /// would: copy it, then free the Rust buffer.
    unsafe fn take(out: *mut c_char) -> String {
        assert!(!out.is_null());
        let s = CStr::from_ptr(out).to_str().unwrap().to_owned();
        oboron_string_free(out);
        s
    }

    fn cs(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn round_trip_through_the_c_abi() {
        // Generate a key via the ABI…
        let mut kout: *mut c_char = ptr::null_mut();
        assert_eq!(oboron_generate_key(&mut kout), OBORON_OK);
        let key = cs(&unsafe { take(kout) });

        // …encrypt…
        let mut ct: *mut c_char = ptr::null_mut();
        assert_eq!(
            oboron_enc(cs("hello obsigil").as_ptr(), cs("psiv.b64").as_ptr(), key.as_ptr(), &mut ct),
            OBORON_OK
        );
        let obtext = cs(&unsafe { take(ct) });

        // …and round-trip back with the same explicit format.
        let mut pt: *mut c_char = ptr::null_mut();
        assert_eq!(
            oboron_dec(obtext.as_ptr(), cs("psiv.b64").as_ptr(), key.as_ptr(), &mut pt),
            OBORON_OK
        );
        assert_eq!(unsafe { take(pt) }, "hello obsigil");
        assert!(oboron_last_error().is_null(), "no error on success");
    }

    #[test]
    fn null_argument_is_reported_not_dereferenced() {
        let mut out: *mut c_char = ptr::null_mut();
        let code = oboron_enc(ptr::null(), cs("psiv.b64").as_ptr(), cs("ab").as_ptr(), &mut out);
        assert_eq!(code, OBORON_ERR_NULL_ARG);
        assert!(out.is_null());
        assert!(!oboron_last_error().is_null());
    }

    #[test]
    fn oboron_error_surfaces_with_a_message() {
        // A bad key (not valid hex / wrong length) is an oboron error.
        let mut out: *mut c_char = ptr::null_mut();
        let code = oboron_enc(cs("x").as_ptr(), cs("psiv.b64").as_ptr(), cs("nothex").as_ptr(), &mut out);
        assert_eq!(code, OBORON_ERR_OBORON);
        assert!(out.is_null());
        assert!(!oboron_last_error().is_null());
    }

    #[cfg(feature = "keyless")]
    #[test]
    fn keyless_round_trip() {
        let mut ct: *mut c_char = ptr::null_mut();
        assert_eq!(
            oboron_enc_keyless(cs("public claim").as_ptr(), cs("dsiv.b64").as_ptr(), &mut ct),
            OBORON_OK
        );
        let obtext = cs(&unsafe { take(ct) });
        let mut pt: *mut c_char = ptr::null_mut();
        assert_eq!(
            oboron_dec_keyless(obtext.as_ptr(), cs("dsiv.b64").as_ptr(), &mut pt),
            OBORON_OK
        );
        assert_eq!(unsafe { take(pt) }, "public claim");
    }
}
