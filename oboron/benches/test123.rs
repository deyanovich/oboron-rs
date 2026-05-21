use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oboron::Omnib;
#[cfg(feature = "upbc")]
use oboron::UpbcC32;
#[cfg(feature = "aags")]
use oboron::{AagsC32, ApgsC32};
#[cfg(feature = "aasv")]
use oboron::{AasvC32, ApsvC32};
#[cfg(feature = "mock")]
use oboron::{Mock1C32, Mock2C32};

// Baseline benchmarks - no crypto, just encoding overhead

#[cfg(feature = "mock")]
fn benchmark_mock1_enc(c: &mut Criterion) {
    let ob = Mock1C32::new_keyless().unwrap();
    c.bench_function("test123/Mock2C32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "mock")]
fn benchmark_mock1_dec(c: &mut Criterion) {
    let ob = Mock1C32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/Mock1C32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "mock")]
fn benchmark_mock2_enc(c: &mut Criterion) {
    let ob = Mock2C32::new_keyless().unwrap();
    c.bench_function("test123/Mock2C32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "mock")]
fn benchmark_mock2_dec(c: &mut Criterion) {
    let ob = Mock2C32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/Mock2C32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

// Crypto schemes

#[cfg(feature = "aags")]
fn benchmark_aags_enc(c: &mut Criterion) {
    let ob = AagsC32::new_keyless().unwrap();
    c.bench_function("test123/AagsC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "aags")]
fn benchmark_aags_dec(c: &mut Criterion) {
    let ob = AagsC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/AagsC32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "aasv")]
fn benchmark_aasv_enc(c: &mut Criterion) {
    let ob = AasvC32::new_keyless().unwrap();
    c.bench_function("test123/AasvC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "aasv")]
fn benchmark_aasv_dec(c: &mut Criterion) {
    let ob = AasvC32::new_keyless().unwrap();
    let ot = ob.enc("test123/AasvC32/dec").unwrap();
    c.bench_function("dec_aasv", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "apgs")]
fn benchmark_apgs_enc(c: &mut Criterion) {
    let ob = ApgsC32::new_keyless().unwrap();
    c.bench_function("test123/ApgsC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "apgs")]
fn benchmark_apgs_dec(c: &mut Criterion) {
    let ob = ApgsC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/ApgsC32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "apsv")]
fn benchmark_apsv_enc(c: &mut Criterion) {
    let ob = ApsvC32::new_keyless().unwrap();
    c.bench_function("test123/ApsvC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "apsv")]
fn benchmark_apsv_dec(c: &mut Criterion) {
    let ob = ApsvC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/ApsvC32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "upbc")]
fn benchmark_upbc_enc(c: &mut Criterion) {
    let ob = UpbcC32::new_keyless().unwrap();
    c.bench_function("test123/UpbcC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "upbc")]
fn benchmark_upbc_dec(c: &mut Criterion) {
    let ob = UpbcC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/UpbcC32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

// Omnib

#[cfg(feature = "aasv")]
fn benchmark_aasv_omb_enc(c: &mut Criterion) {
    let ob = Omnib::new_keyless().unwrap();
    c.bench_function("test123/Omnib_aasv.c32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123"), "aasv.c32").unwrap());
    });
}

#[cfg(feature = "aasv")]
fn benchmark_aasv_omb_autodec(c: &mut Criterion) {
    let ob = Omnib::new_keyless().unwrap();
    let ot = ob.enc("test123", "aasv.c32").unwrap();
    c.bench_function("test123/Omnib_aasv.c32/autodec", |b| {
        b.iter(|| ob.autodec(black_box(&ot)).unwrap());
    });
}

criterion_group!(
    benches,
    // Mock
    benchmark_mock1_enc,
    benchmark_mock1_dec,
    benchmark_mock2_enc,
    benchmark_mock2_dec,
    // Crypto
    benchmark_aags_enc,
    benchmark_aags_dec,
    benchmark_aasv_enc,
    benchmark_aasv_dec,
    benchmark_apgs_enc,
    benchmark_apgs_dec,
    benchmark_apsv_enc,
    benchmark_apsv_dec,
    benchmark_upbc_enc,
    benchmark_upbc_dec,
    // Omnib
    benchmark_aasv_omb_enc,
    benchmark_aasv_omb_autodec,
);
criterion_main!(benches);
