use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oboron::Omnib;
#[cfg(feature = "dgcmsiv")]
use oboron::{DgcmsivC32, PgcmsivC32};
#[cfg(feature = "dsiv")]
use oboron::{DsivC32, PsivC32};
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

#[cfg(feature = "dgcmsiv")]
fn benchmark_dgcmsiv_enc(c: &mut Criterion) {
    let ob = DgcmsivC32::new_keyless().unwrap();
    c.bench_function("test123/DgcmsivC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "dgcmsiv")]
fn benchmark_dgcmsiv_dec(c: &mut Criterion) {
    let ob = DgcmsivC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/DgcmsivC32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "dsiv")]
fn benchmark_dsiv_enc(c: &mut Criterion) {
    let ob = DsivC32::new_keyless().unwrap();
    c.bench_function("test123/DsivC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "dsiv")]
fn benchmark_dsiv_dec(c: &mut Criterion) {
    let ob = DsivC32::new_keyless().unwrap();
    let ot = ob.enc("test123/DsivC32/dec").unwrap();
    c.bench_function("dec_dsiv", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "pgcmsiv")]
fn benchmark_pgcmsiv_enc(c: &mut Criterion) {
    let ob = PgcmsivC32::new_keyless().unwrap();
    c.bench_function("test123/PgcmsivC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "pgcmsiv")]
fn benchmark_pgcmsiv_dec(c: &mut Criterion) {
    let ob = PgcmsivC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/PgcmsivC32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

#[cfg(feature = "psiv")]
fn benchmark_psiv_enc(c: &mut Criterion) {
    let ob = PsivC32::new_keyless().unwrap();
    c.bench_function("test123/PsivC32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123")).unwrap());
    });
}

#[cfg(feature = "psiv")]
fn benchmark_psiv_dec(c: &mut Criterion) {
    let ob = PsivC32::new_keyless().unwrap();
    let ot = ob.enc("test123").unwrap();
    c.bench_function("test123/PsivC32/dec", |b| {
        b.iter(|| ob.dec(black_box(&ot)).unwrap());
    });
}

// Omnib

#[cfg(feature = "dsiv")]
fn benchmark_dsiv_omb_enc(c: &mut Criterion) {
    let ob = Omnib::new_keyless().unwrap();
    c.bench_function("test123/Omnib_dsiv.c32/enc", |b| {
        b.iter(|| ob.enc(black_box("test123"), "dsiv.c32").unwrap());
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
    benchmark_dgcmsiv_enc,
    benchmark_dgcmsiv_dec,
    benchmark_dsiv_enc,
    benchmark_dsiv_dec,
    benchmark_pgcmsiv_enc,
    benchmark_pgcmsiv_dec,
    benchmark_psiv_enc,
    benchmark_psiv_dec,
    // Omnib
    benchmark_dsiv_omb_enc,
);
criterion_main!(benches);
