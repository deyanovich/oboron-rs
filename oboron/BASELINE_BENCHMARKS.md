# Baseline Bench Results (JWT, SHA256)

Reference figures for the two comparison libraries cited in the
README [Performance Comparison](README.md#performance-comparison):
`jsonwebtoken` (JWT, HS256) and `sha2` (SHA256). Measured on the same
machine, native build (`RUSTFLAGS="-C target-cpu=native"`), and with
the same Criterion settings as [BENCHMARKS.md](BENCHMARKS.md);
figures are medians of the timed call.

## SHA256 (`sha2`, hex digest)

| Input Size | SHA256   |
|-----------:|---------:|
| 8B         | 123.7 ns |
| 12B        | 123.8 ns |
| 16B        | 124.6 ns |
| 32B        | 122.9 ns |
| 64B        | 145.3 ns |
| 128B       | 182.3 ns |

## JWT (`jsonwebtoken`, HS256)

| Input Size | Encode   | Decode    |
|-----------:|---------:|----------:|
| 8B         | 696.4 ns | 1095.3 ns |
| 12B        | 657.6 ns | 1098.2 ns |
| 16B        | 657.8 ns | 1067.8 ns |
| 32B        | 699.1 ns | 1255.5 ns |
| 64B        | 835.3 ns | 1592.4 ns |
| 128B       | 951.1 ns | 1942.5 ns |

## Notes

- SHA256 drops from ~191 ns to ~124 ns at 8 B versus the prior
  default-build figures — consistent with the `sha2` SHA-NI backend
  being enabled under native codegen on this CPU. JWT's crypto
  backend sees no comparable gain, so its figures are flat to
  slightly higher.
- SHA256 is one-way (no decode); JWT HS256 authenticates but does
  not encrypt. Oboron provides reversible, authenticated encryption
  and still beats JWT in both directions at every size measured
  here (see [BENCHMARKS.md](BENCHMARKS.md)).
- The `z_jwt` bench target previously lacked `harness = false` in
  `Cargo.toml`, so it could not accept Criterion CLI flags; that is
  now fixed.
