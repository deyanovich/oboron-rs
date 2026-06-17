//! Roundtrip tests for the wasm bindings.
//!
//! These exercise the actual wasm build and so run under a JS host:
//!
//! ```text
//! wasm-pack test --node
//! # or, in a headless browser:
//! wasm-pack test --headless --firefox
//! ```
//!
//! Gated to `wasm32` so a host-target `cargo test` compiles them away
//! to nothing rather than failing to link.
#![cfg(target_arch = "wasm32")]

use oboron_wasm::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn free_function_roundtrip() -> Result<(), JsValue> {
    let key = generate_key();
    assert_eq!(key.len(), 128);

    let obtext = enc("hidden message", "dsiv.b64", &key)?;
    let plaintext = dec(&obtext, "dsiv.b64", &key)?;
    assert_eq!(plaintext, "hidden message");
    Ok(())
}

#[wasm_bindgen_test]
fn codec_class_roundtrip() -> Result<(), JsValue> {
    let key = generate_key();
    let codec = DsivC32::new(&key)?;

    assert_eq!(codec.scheme(), "dsiv");
    assert_eq!(codec.encoding(), "c32");
    assert_eq!(codec.format(), "dsiv.c32");
    assert_eq!(codec.key(), key);
    assert_eq!(codec.key_bytes().len(), 64);

    let obtext = codec.enc("hello")?;
    let plaintext = codec.dec(&obtext)?;
    assert_eq!(plaintext, "hello");
    Ok(())
}

#[wasm_bindgen_test]
fn ob_runtime_format_switch() -> Result<(), JsValue> {
    let key = generate_key();
    let mut ob = Ob::new("dsiv.b64", &key)?;
    assert_eq!(ob.format(), "dsiv.b64");

    ob.set_encoding("c32")?;
    assert_eq!(ob.format(), "dsiv.c32");
    ob.set_scheme("dgcmsiv")?;
    assert_eq!(ob.format(), "dgcmsiv.c32");
    ob.set_format("psiv.hex")?;
    assert_eq!(ob.format(), "psiv.hex");

    let obtext = ob.enc("hello")?;
    assert_eq!(ob.dec(&obtext)?, "hello");
    Ok(())
}

#[wasm_bindgen_test]
fn omnib_multi_format() -> Result<(), JsValue> {
    let key = generate_key();
    let omb = Omnib::new(&key)?;

    let ot_dsiv = omb.enc("hello", "dsiv.b64")?;
    let ot_dgcmsiv = omb.enc("hello", "dgcmsiv.c32")?;

    assert_eq!(omb.dec(&ot_dsiv, "dsiv.b64")?, "hello");
    assert_eq!(omb.dec(&ot_dgcmsiv, "dgcmsiv.c32")?, "hello");
    Ok(())
}

#[wasm_bindgen_test]
fn bad_key_throws() {
    assert!(DsivC32::new("not-hex").is_err());
    assert!(enc("x", "dsiv.b64", "short").is_err());
    assert!(Ob::new("nonsense.format", &generate_key()).is_err());
}
