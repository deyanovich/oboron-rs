use data_encoding::BASE64URL_NOPAD;
use std::env;
use std::process;

/// Valid byte lengths for oboron keys and secrets.
const KEY_BYTES: usize = 64; // MasterKey: 64 bytes = 128 hex chars
const SECRET_BYTES: usize = 32; // ZSecret:  32 bytes =  64 hex chars

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: hex2b64 <hex-string>");
        eprintln!();
        eprintln!("Convert a key or secret from hex to the base64 format used by oboron.");
        eprintln!();
        eprintln!("Accepted lengths:");
        eprintln!("  128 hex chars (64 bytes) — key");
        eprintln!("   64 hex chars (32 bytes) — secret");
        process::exit(1);
    }

    let hex_input = args[1].trim();

    let bytes = match hex::decode(hex_input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: invalid hex input: {e}");
            process::exit(1);
        }
    };

    match bytes.len() {
        KEY_BYTES => {}
        SECRET_BYTES => {}
        other => {
            eprintln!(
                "Error: hex decodes to {other} bytes, but oboron requires \
                 {KEY_BYTES} bytes (key) or {SECRET_BYTES} bytes (secret)"
            );
            process::exit(1);
        }
    }

    println!("{}", BASE64URL_NOPAD.encode(&bytes));
}
