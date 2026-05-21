use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};

fn benchmark_sha256_hex_8b(c: &mut Criterion) {
    let plaintext = b"12345678"; // 8 bytes
    c.bench_function("baseline_sha256_hex_8b", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(plaintext));
            let result = hasher.finalize();
            hex::encode(result)
        });
    });
}

fn benchmark_sha256_hex_12b(c: &mut Criterion) {
    let plaintext = b"123456789012"; // 12 bytes
    c.bench_function("baseline_sha256_hex_12b", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(plaintext));
            let result = hasher.finalize();
            hex::encode(result)
        });
    });
}

fn benchmark_sha256_hex_16b(c: &mut Criterion) {
    let plaintext = b"1234567890123456"; // 16 bytes
    c.bench_function("baseline_sha256_hex_16b", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(plaintext));
            let result = hasher.finalize();
            hex::encode(result)
        });
    });
}

fn benchmark_sha256_hex_32b(c: &mut Criterion) {
    let plaintext = b"12345678901234567890123456789012"; // 32 bytes
    c.bench_function("baseline_sha256_hex_32b", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(plaintext));
            let result = hasher.finalize();
            hex::encode(result)
        });
    });
}

fn benchmark_sha256_hex_64b(c: &mut Criterion) {
    let plaintext = b"1234567890123456789012345678901234567890123456789012345678901234"; // 64 bytes
    c.bench_function("baseline_sha256_hex_64b", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(plaintext));
            let result = hasher.finalize();
            hex::encode(result)
        });
    });
}

fn benchmark_sha256_hex_128b(c: &mut Criterion) {
    let plaintext = b"12345678901234567890123456789012345678901234567890123456789012341234567890123456789012345678901234567890123456789012345678901234"; // 128 bytes
    c.bench_function("baseline_sha256_hex_128b", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(plaintext));
            let result = hasher.finalize();
            hex::encode(result)
        });
    });
}

criterion_group!(
    benches,
    benchmark_sha256_hex_8b,
    benchmark_sha256_hex_12b,
    benchmark_sha256_hex_16b,
    benchmark_sha256_hex_32b,
    benchmark_sha256_hex_64b,
    benchmark_sha256_hex_128b
);
criterion_main!(benches);
