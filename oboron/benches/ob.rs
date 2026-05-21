use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oboron::Ob;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct BenchmarkSpec {
    id: String,
    operation: String,
    #[serde(default)]
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    format: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    encoding: Option<String>,
    plaintext: String,
}

fn load_benchmark_specs() -> Vec<BenchmarkSpec> {
    let possible_paths = vec![
        PathBuf::from("benches/benchmarks_ob.jsonl"),
        PathBuf::from("oboron/benches/benchmarks_ob.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/benchmarks_ob.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            eprintln!("Found ob benchmarks at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read benchmarks");
            let specs: Vec<BenchmarkSpec> = data
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("Failed to parse"))
                .collect();
            eprintln!("Loaded {} ob benchmark specifications", specs.len());
            return specs;
        }
    }

    eprintln!("Warning: benchmarks_ob.jsonl not found");
    vec![]
}

fn precompute_value(spec: &PrecomputeSpec, ob: &Ob) -> String {
    ob.enc(&spec.plaintext).unwrap()
}

fn run_ob_benchmarks(c: &mut Criterion) {
    let specs = load_benchmark_specs();

    if specs.is_empty() {
        eprintln!("No ob specs loaded");
        return;
    }

    // Create ob once, OUTSIDE the timed loop

    let mut bench_count = 0;
    for spec in specs {
        let format = match spec.format {
            Some(f) => f,
            None => {
                eprintln!("Skipping {} - no format", spec.id);
                continue;
            }
        };
        let ob = Ob::new_keyless(format.as_str()).unwrap();
        match spec.operation.as_str() {
            "enc" => {
                if let Some(plaintext) = spec.plaintext {
                    bench_count += 1;

                    // Only the enc operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.enc(black_box(&plaintext)).unwrap());
                    });
                }
            }
            "dec" => {
                if let Some(precompute) = spec.precompute {
                    // Precompute and set format outside timed loop
                    let ot = precompute_value(&precompute, &ob);
                    bench_count += 1;

                    // Only the dec operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.dec(black_box(&ot)).unwrap());
                    });
                }
            }
            "autodec" => {
                if let Some(precompute) = spec.precompute {
                    // Precompute and set format outside timed loop
                    let ot = precompute_value(&precompute, &ob);
                    bench_count += 1;

                    // Only the dec operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.autodec(black_box(&ot)).unwrap());
                    });
                }
            }
            _ => {
                eprintln!(
                    "Skipping {} - unsupported operation: {}",
                    spec.id, spec.operation
                );
            }
        }
    }
    eprintln!("Registered {} ob benchmarks", bench_count);
}

criterion_group!(benches, run_ob_benchmarks);
criterion_main!(benches);
