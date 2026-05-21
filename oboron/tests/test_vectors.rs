use oboron::{Format, Omnib};
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

fn load_test_vectors() -> Vec<TestVector> {
    let possible_paths = vec![
        PathBuf::from("tests/test-vectors.jsonl"),
        PathBuf::from("oboron/tests/test-vectors.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test-vectors.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            println!("Found test vectors at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read test-vectors.jsonl");
            return data
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("Failed to parse test vector"))
                .collect();
        }
    }

    panic!("test-vectors.jsonl not found");
}

#[test]
fn test_all_vectors() {
    let vectors = load_test_vectors();
    println!("Loaded {} test vectors", vectors.len());

    let omb = Omnib::new_keyless().expect("Failed to create Omnib");

    for vector in vectors {
        let format = Format::from_str(&vector.format)
            .unwrap_or_else(|e| panic!("Invalid format '{}': {:?}", vector.format, e));

        let is_probabilistic = format.scheme().is_probabilistic();

        if is_probabilistic {
            // For probabilistic schemes, we can only test decoding
            // (encoding produces different output each time)

            // Test decoding with format
            let pt2 = omb.dec(&vector.obtext, &vector.format).unwrap_or_else(|e| {
                panic!(
                    "Failed to dec '{}' with format '{}': {:?}",
                    vector.obtext, vector.format, e
                )
            });

            assert_eq!(
                pt2, vector.plaintext,
                "Decoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.format, vector.plaintext, pt2
            );

            // Test autodetection
            let autodetected = omb
                .autodec(&vector.obtext)
                .unwrap_or_else(|e| panic!("Failed to autodetect '{}': {:?}", vector.obtext, e));

            assert_eq!(
                autodetected, vector.plaintext,
                "Autodetection mismatch for '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.plaintext, autodetected
            );

            // Test that we can enc and then dec (roundtrip)
            let new_ot = omb
                .enc(&vector.plaintext, &vector.format)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to enc '{}' with format '{}': {:?}",
                        vector.plaintext, vector.format, e
                    )
                });

            let roundtrip = omb.dec(&new_ot, &vector.format).unwrap_or_else(|e| {
                panic!(
                    "Failed to dec roundtrip '{}' with format '{}': {:?}",
                    new_ot, vector.format, e
                )
            });

            assert_eq!(
                roundtrip, vector.plaintext,
                "Roundtrip mismatch for '{}' with format '{}'",
                vector.plaintext, vector.format
            );
        } else {
            // For deterministic schemes, test both encoding and decoding

            // Test encoding
            let ot = omb
                .enc(&vector.plaintext, &vector.format)
                .unwrap_or_else(|e| {
                    panic!(
                        "Failed to enc '{}' with format '{}': {:?}",
                        vector.plaintext, vector.format, e
                    )
                });

            assert_eq!(
                ot, vector.obtext,
                "Encoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.plaintext, vector.format, vector.obtext, ot
            );

            // Test decoding
            let pt2 = omb.dec(&vector.obtext, &vector.format).unwrap_or_else(|e| {
                panic!(
                    "Failed to dec '{}' with format '{}': {:?}",
                    vector.obtext, vector.format, e
                )
            });

            assert_eq!(
                pt2, vector.plaintext,
                "Decoding mismatch for '{}' with format '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.format, vector.plaintext, pt2
            );

            // Test autodetection
            let autodetected = omb
                .autodec(&vector.obtext)
                .unwrap_or_else(|e| panic!("Failed to autodetect '{}': {:?}", vector.obtext, e));

            assert_eq!(
                autodetected, vector.plaintext,
                "Autodetection mismatch for '{}'\nExpected: {}\nGot: {}",
                vector.obtext, vector.plaintext, autodetected
            );
        }
    }
}
