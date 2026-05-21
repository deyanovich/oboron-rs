use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oboron::Omnib;
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
    format: String,
    plaintext: String,
}

fn load_benchmark_specs() -> Vec<BenchmarkSpec> {
    let possible_paths = vec![
        PathBuf::from("benches/benchmarks_omnib.jsonl"),
        PathBuf::from("oboron/benches/benchmarks_omnib.jsonl"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/benchmarks_omnib.jsonl"),
    ];

    for path in &possible_paths {
        if path.exists() {
            eprintln!("Found omnib benchmarks at: {:?}", path);
            let data = fs::read_to_string(path).expect("Failed to read benchmarks_omnib.jsonl");
            let specs: Vec<BenchmarkSpec> = data
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("Failed to parse benchmark spec"))
                .collect();
            eprintln!("Loaded {} omnib benchmark specifications", specs.len());
            return specs;
        }
    }

    eprintln!("Warning: benchmarks_omnib.jsonl not found");
    vec![]
}

fn run_omnib_benchmarks(c: &mut Criterion) {
    let specs = load_benchmark_specs();

    if specs.is_empty() {
        eprintln!("No omnib specs loaded");
        return;
    }

    // Create Omnib once, OUTSIDE the timed loop
    let ob = Omnib::new_keyless().unwrap();

    let mut bench_count = 0;
    for spec in specs {
        match spec.operation.as_str() {
            "enc" => {
                let format = match spec.format {
                    Some(f) => f,
                    None => {
                        eprintln!("Skipping {} - no format", spec.id);
                        continue;
                    }
                };

                if let Some(plaintext) = spec.plaintext {
                    bench_count += 1;
                    // Only the enc operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.enc(black_box(&plaintext), &format).unwrap());
                    });
                }
            }
            "dec" => {
                let format = match spec.format {
                    Some(f) => f,
                    None => {
                        eprintln!("Skipping {} - no format", spec.id);
                        continue;
                    }
                };

                if let Some(precompute) = spec.precompute {
                    // Precompute outside timed loop
                    let ot = ob.enc(&precompute.plaintext, &precompute.format).unwrap();
                    bench_count += 1;

                    // Only the dec operation is timed
                    c.bench_function(&spec.id, |b| {
                        b.iter(|| ob.dec(black_box(&ot), &format).unwrap());
                    });
                }
            }
            "autodec" => {
                if let Some(precompute) = spec.precompute {
                    // Precompute outside timed loop
                    let ot = ob.enc(&precompute.plaintext, &precompute.format).unwrap();
                    bench_count += 1;

                    // Only the autodec operation is timed
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
    eprintln!("Registered {} omnib benchmarks", bench_count);
}

criterion_group!(benches, run_omnib_benchmarks);
criterion_main!(benches);
