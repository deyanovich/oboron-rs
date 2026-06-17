# Oboron Performance Benchmarks

Performance metrics for different schemes and input sizes.

All benchmarks use static format structs with Crockford base32
encoding (e.g., `DgcmsivC32`). Figures are Criterion median
estimates for the timed `enc()` / `dec()` call only (codec
constructed outside the loop).

These runs were built with native codegen enabled —
`RUSTFLAGS="-C target-cpu=native"` — which unlocks the wide
VAES / VPCLMULQDQ paths used by AES and POLYVAL. A default build
is 12–33% slower on the authenticated schemes. See the
[Performance Tuning](README.md#performance-tuning) section of the
README for why, and for the Docker / distribution caveat.


## Performance for Typical IDs (8-16 bytes)

| Scheme  | 8B Enc   | 8B Dec   | 16B Enc  | 16B Dec  |
|---------|----------|----------|----------|----------|
| dgcmsiv | 326.5 ns | 250.5 ns | 332.4 ns | 247.5 ns |
| dsiv    | 262.8 ns | 237.3 ns | 262.3 ns | 224.2 ns |

## `enc()` Performance

| Input Size | dgcmsiv  | dsiv     | pgcmsiv  | psiv     |
|-----------:|---------:|---------:|---------:|---------:|
| 8B         | 326.5 ns | 262.8 ns | 338.2 ns | 324.0 ns |
| 12B        | 336.1 ns | 283.1 ns | 342.7 ns | 351.0 ns |
| 16B        | 332.4 ns | 262.3 ns | 350.1 ns | 325.1 ns |
| 32B        | 357.0 ns | 273.7 ns | 364.4 ns | 344.9 ns |
| 64B        | 386.2 ns | 306.9 ns | 395.3 ns | 390.5 ns |
| 128B       | 473.4 ns | 411.8 ns | 490.2 ns | 484.2 ns |


## `dec()` Performance

| Input Size | dgcmsiv  | dsiv     | pgcmsiv  | psiv     |
|-----------:|---------:|---------:|---------:|---------:|
| 8B         | 250.5 ns | 237.3 ns | 256.3 ns | 279.6 ns |
| 12B        | 258.2 ns | 238.7 ns | 262.6 ns | 281.8 ns |
| 16B        | 247.5 ns | 224.2 ns | 252.6 ns | 263.0 ns |
| 32B        | 256.6 ns | 228.2 ns | 265.4 ns | 273.5 ns |
| 64B        | 308.5 ns | 276.9 ns | 312.0 ns | 318.2 ns |
| 128B       | 383.7 ns | 376.3 ns | 381.5 ns | 411.4 ns |


## Notes

- Built with `RUSTFLAGS="-C target-cpu=native"`; a default build
  (baseline AES-NI / CLMUL) runs the authenticated schemes 12–33%
  slower. See [Performance Tuning](README.md#performance-tuning).
- Hardware: 11th-gen Intel (Tiger Lake) i5, single machine for all
  rows.
- At these sizes (≤128 B) AES-SIV (`dsiv`, `psiv`) is at or ahead
  of AES-GCM-SIV (`dgcmsiv`, `pgcmsiv`); GCM-SIV's single-pass
  POLYVAL pulls ahead only on larger payloads (~256 B and up). See
  the README for the length-based crossover and scheme-choice
  guidance.
- Probabilistic variants (pgcmsiv, psiv) add ~16 bytes of nonce
  overhead to the output.
