use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Minimal payload - just a short string field
#[derive(Debug, Serialize, Deserialize)]
struct TinyClaims {
    d: String, // "data" - keeping it short
}

// Payloads of different sizes
#[derive(Debug, Serialize, Deserialize)]
struct SmallClaims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct MediumClaims {
    sub: String,
    exp: usize,
    role: String,
    iat: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct LargeClaims {
    sub: String,
    exp: usize,
    role: String,
    iat: usize,
    name: String,
    email: String,
}

// Helper to create validation that doesn't require any claims
fn minimal_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = HashSet::new(); // Don't require any claims
    validation.validate_exp = false;
    validation
}

fn benchmark_jwt_encode_8b(c: &mut Criterion) {
    let key = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = TinyClaims {
        d: "12345678".to_owned(), // 8 bytes
    };

    c.bench_function("jwt_encode_8b", |b| {
        b.iter(|| encode(&Header::default(), black_box(&claims), &key).unwrap());
    });
}

fn benchmark_jwt_decode_8b(c: &mut Criterion) {
    let key_enc = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let key_dec = DecodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = TinyClaims {
        d: "12345678".to_owned(),
    };
    let token = encode(&Header::default(), &claims, &key_enc).unwrap();
    let validation = minimal_validation();

    c.bench_function("jwt_decode_8b", |b| {
        b.iter(|| decode::<TinyClaims>(black_box(&token), &key_dec, &validation).unwrap());
    });
}

fn benchmark_jwt_encode_12b(c: &mut Criterion) {
    let key = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = TinyClaims {
        d: "123456789012".to_owned(), // 12 bytes
    };

    c.bench_function("jwt_encode_12b", |b| {
        b.iter(|| encode(&Header::default(), black_box(&claims), &key).unwrap());
    });
}

fn benchmark_jwt_decode_12b(c: &mut Criterion) {
    let key_enc = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let key_dec = DecodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = TinyClaims {
        d: "123456789012".to_owned(),
    };
    let token = encode(&Header::default(), &claims, &key_enc).unwrap();
    let validation = minimal_validation();

    c.bench_function("jwt_decode_12b", |b| {
        b.iter(|| decode::<TinyClaims>(black_box(&token), &key_dec, &validation).unwrap());
    });
}

fn benchmark_jwt_encode_16b(c: &mut Criterion) {
    let key = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = TinyClaims {
        d: "1234567890123456".to_owned(), // 16 bytes
    };

    c.bench_function("jwt_encode_16b", |b| {
        b.iter(|| encode(&Header::default(), black_box(&claims), &key).unwrap());
    });
}

fn benchmark_jwt_decode_16b(c: &mut Criterion) {
    let key_enc = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let key_dec = DecodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = TinyClaims {
        d: "1234567890123456".to_owned(),
    };
    let token = encode(&Header::default(), &claims, &key_enc).unwrap();
    let validation = minimal_validation();

    c.bench_function("jwt_decode_16b", |b| {
        b.iter(|| decode::<TinyClaims>(black_box(&token), &key_dec, &validation).unwrap());
    });
}

fn benchmark_jwt_encode_32b(c: &mut Criterion) {
    let key = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = SmallClaims {
        sub: "user123".to_owned(),
        exp: 9999999999, // Far future timestamp
    };

    c.bench_function("jwt_encode_32b", |b| {
        b.iter(|| encode(&Header::default(), black_box(&claims), &key).unwrap());
    });
}

fn benchmark_jwt_decode_32b(c: &mut Criterion) {
    let key_enc = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let key_dec = DecodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = SmallClaims {
        sub: "user123".to_owned(),
        exp: 9999999999, // Far future timestamp
    };
    let token = encode(&Header::default(), &claims, &key_enc).unwrap();
    let validation = Validation::default();

    c.bench_function("jwt_decode_32b", |b| {
        b.iter(|| decode::<SmallClaims>(black_box(&token), &key_dec, &validation).unwrap());
    });
}

fn benchmark_jwt_encode_64b(c: &mut Criterion) {
    let key = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = MediumClaims {
        sub: "user123".to_owned(),
        exp: 9999999999,
        role: "admin".to_owned(),
        iat: 1234567890,
    };

    c.bench_function("jwt_encode_64b", |b| {
        b.iter(|| encode(&Header::default(), black_box(&claims), &key).unwrap());
    });
}

fn benchmark_jwt_decode_64b(c: &mut Criterion) {
    let key_enc = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let key_dec = DecodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = MediumClaims {
        sub: "user123".to_owned(),
        exp: 9999999999,
        role: "admin".to_owned(),
        iat: 1234567890,
    };
    let token = encode(&Header::default(), &claims, &key_enc).unwrap();
    let validation = Validation::default();

    c.bench_function("jwt_decode_64b", |b| {
        b.iter(|| decode::<MediumClaims>(black_box(&token), &key_dec, &validation).unwrap());
    });
}

fn benchmark_jwt_encode_128b(c: &mut Criterion) {
    let key = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = LargeClaims {
        sub: "user123".to_owned(),
        exp: 9999999999,
        role: "admin".to_owned(),
        iat: 1234567890,
        name: "John Doe".to_owned(),
        email: "john@example.com".to_owned(),
    };

    c.bench_function("jwt_encode_128b", |b| {
        b.iter(|| encode(&Header::default(), black_box(&claims), &key).unwrap());
    });
}

fn benchmark_jwt_decode_128b(c: &mut Criterion) {
    let key_enc = EncodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let key_dec = DecodingKey::from_secret(b"your-256-bit-secret-key-here-32b");
    let claims = LargeClaims {
        sub: "user123".to_owned(),
        exp: 9999999999,
        role: "admin".to_owned(),
        iat: 1234567890,
        name: "John Doe".to_owned(),
        email: "john@example.com".to_owned(),
    };
    let token = encode(&Header::default(), &claims, &key_enc).unwrap();
    let validation = Validation::default();

    c.bench_function("jwt_decode_128b", |b| {
        b.iter(|| decode::<LargeClaims>(black_box(&token), &key_dec, &validation).unwrap());
    });
}

criterion_group!(
    benches,
    benchmark_jwt_encode_8b,
    benchmark_jwt_decode_8b,
    benchmark_jwt_encode_12b,
    benchmark_jwt_decode_12b,
    benchmark_jwt_encode_16b,
    benchmark_jwt_decode_16b,
    benchmark_jwt_encode_32b,
    benchmark_jwt_decode_32b,
    benchmark_jwt_encode_64b,
    benchmark_jwt_decode_64b,
    benchmark_jwt_encode_128b,
    benchmark_jwt_decode_128b
);
criterion_main!(benches);
