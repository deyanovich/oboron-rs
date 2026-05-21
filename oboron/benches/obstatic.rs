use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct BenchmarkSpec {
    id: String,
    operation: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    encoding: Option<String>,
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    precompute: Option<PrecomputeSpec>,
    #[allow(dead_code)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct PrecomputeSpec {
    #[allow(dead_code)]
    operation: String,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    encoding: Option<String>,
    plaintext: String,
}

fn load_benchmark_specs() -> Vec<BenchmarkSpec> {
    let possible_paths = vec![
        PathBuf::from("benches/benchmarks.jsonl"),
        PathBuf::from("oboron/benches/benchmarks.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/benchmarks.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            eprintln!("Found benchmark specs at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read benchmarks.jsonl");
            return data
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("Failed to parse benchmark spec"))
                .collect();
        }
    }

    eprintln!("Warning: benchmarks.jsonl not found");
    vec![]
}

fn precompute_value(spec: &PrecomputeSpec) -> Option<String> {
    let format = spec.format.as_ref()?;
    let ob = oboron::new_keyless(format).ok()?;
    ob.enc(&spec.plaintext).ok()
}

fn run_standard_benchmarks(c: &mut Criterion) {
    let specs = load_benchmark_specs();

    if specs.is_empty() {
        eprintln!("No benchmark specs loaded, skipping standard benchmarks");
        return;
    }

    eprintln!("Loaded {} benchmark specifications", specs.len());

    for spec in specs {
        match spec.operation.as_str() {
            "enc" => {
                // For enc, format is at top level
                let format = match &spec.format {
                    Some(f) => f,
                    None => continue,
                };

                // Create ob ONCE, outside the timed loop
                let ob = match oboron::new_keyless(format) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                if let Some(plaintext) = spec.plaintext {
                    // Only the enc operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.enc(black_box(&plaintext)).unwrap());
                    });
                }
            }
            "dec" => {
                // For dec, format is at top level
                let format = match &spec.format {
                    Some(f) => f,
                    None => continue,
                };

                // Create ob ONCE, outside the timed loop
                let ob = match oboron::new_keyless(format) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                if let Some(precompute) = spec.precompute {
                    if let Some(ot) = precompute_value(&precompute) {
                        // Only the dec operation is timed
                        c.bench_function(&spec.id, |b| {
                            b.iter(|| ob.dec(black_box(&ot)).unwrap());
                        });
                    }
                }
            }
            "autodec" => {
                // Static ObXX interface doesn't support autodec
            }
            _ => {}
        }
    }
}

criterion_group!(benches, run_standard_benchmarks);
criterion_main!(benches);
