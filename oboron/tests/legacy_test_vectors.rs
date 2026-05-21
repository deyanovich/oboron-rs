#![cfg(feature = "legacy")]

use oboron::ztier::{Legacy, Obz};
use oboron::ObtextCodec;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct TestVector {
    format: String,
    plaintext: String,
    obtext: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MetaEntry {
    #[serde(rename = "type")]
    entry_type: String,
    secret: Option<String>,
}

/// Load test vectors, returning (secret, vectors).
/// The first line of the JSONL is a metadata entry containing the secret.
fn load_test_vectors() -> (Option<String>, Vec<TestVector>) {
    let possible_paths = vec![
        PathBuf::from("tests/legacy-test-vectors.jsonl"),
        PathBuf::from("oboron/tests/legacy-test-vectors.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/legacy-test-vectors.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            println!("Found legacy test vectors at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read legacy-test-vectors.jsonl");
            let mut lines = data.lines().filter(|line| !line.trim().is_empty());

            // First line may be a meta entry
            let first = lines.next().expect("Empty test vector file");
            let (secret, extra_vector) =
                if let Ok(meta) = serde_json::from_str::<MetaEntry>(first) {
                    if meta.entry_type == "meta" {
                        (meta.secret, None::<TestVector>)
                    } else {
                        // First line is a regular vector, not a meta entry
                        let v: TestVector =
                            serde_json::from_str(first).expect("Failed to parse first vector");
                        (None::<String>, Some(v))
                    }
                } else {
                    let v: TestVector =
                        serde_json::from_str(first).expect("Failed to parse first vector");
                    (None::<String>, Some(v))
                };

            let mut vectors: Vec<TestVector> = extra_vector.into_iter().collect();
            vectors.extend(
                lines.map(|line| serde_json::from_str(line).expect("Failed to parse test vector")),
            );
            return (secret, vectors);
        }
    }

    panic!("legacy-test-vectors.jsonl not found");
}

#[test]
fn test_legacy_vectors() {
    println!("Starting test_legacy_vectors");

    let (secret, vectors) = load_test_vectors();
    println!("Successfully loaded {} test vectors", vectors.len());
    if secret.is_some() {
        println!("Using secret from test vector metadata");
    }

    // Build the codec once using the secret from metadata (or keyless fallback)
    let legacy: Legacy = match &secret {
        Some(s) => Legacy::new(s).expect("Failed to create Legacy with test vector secret"),
        None => Legacy::new_keyless().expect("Failed to create keyless Legacy"),
    };

    let mut passed = 0usize;
    let mut failed = 0usize;

    for (index, vector) in vectors.iter().enumerate() {
        // All vectors in this file use the "legacy" format
        if vector.format != "legacy" {
            println!(
                "Skipping vector {} with unsupported format: {}",
                index, vector.format
            );
            continue;
        }

        // Test encoding
        let ot = match legacy.enc(&vector.plaintext) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("FAIL vector {}: enc error: {}", index, e);
                failed += 1;
                continue;
            }
        };

        if ot != vector.obtext {
            eprintln!(
                "FAIL vector {}: enc mismatch\n  plaintext={:?}\n  got      ={:?}\n  expected ={:?}",
                index, vector.plaintext, ot, vector.obtext
            );
            failed += 1;
            continue;
        }

        // Test decoding
        let pt2 = match legacy.dec(&vector.obtext) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("FAIL vector {}: dec error: {}", index, e);
                failed += 1;
                continue;
            }
        };

        if pt2 != vector.plaintext {
            eprintln!(
                "FAIL vector {}: dec mismatch\n  obtext  ={:?}\n  got     ={:?}\n  expected={:?}",
                index, vector.obtext, pt2, vector.plaintext
            );
            failed += 1;
            continue;
        }

        // Test autodetection via Obz
        let obz = Obz::new("legacy", legacy.secret().as_str()).unwrap();
        match obz.autodec(&vector.obtext) {
            Ok(pt) if pt == vector.plaintext => {}
            Ok(pt) => {
                eprintln!(
                    "FAIL vector {}: autodec mismatch — got {:?}, expected {:?}",
                    index, pt, vector.plaintext
                );
                failed += 1;
                continue;
            }
            Err(e) => {
                eprintln!("FAIL vector {}: autodec error: {}", index, e);
                failed += 1;
                continue;
            }
        }

        passed += 1;
    }

    println!("Test completed: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "{} test vector(s) failed", failed);
    assert!(passed > 0, "No test vectors were executed");
}
