# Oboron Performance Benchmarks

Performance metrics for different schemes and input sizes.

All benchmarks were carried out with static format structs using
Crockford base32 encoding (e.g., `AagsC32`).


## Performance for Typical IDs (8-16 bytes)

| Scheme | 8B Enc   | 8B Dec   | 16B Enc  | 16B Dec  |
|--------|----------|----------|----------|----------|
| zrbcx  | 131.5 ns | 125.9 ns | 128.3 ns | 122.3 ns |
| aags   | 421.8 ns | 434.7 ns | 424.3 ns | 439.7 ns |
| aasv   | 322.7 ns | 366.4 ns | 321.7 ns | 365.9 ns |
| upbc   | 150.7 ns | 142.3 ns | 165.1 ns | 140.5 ns |

## `enc()` Performance

| Input Size | legacy     | zrbcx     | aags     | aasv     | upbc    | apgs    | apsv    |
|-----------:|----------|----------|----------|----------|----------|----------|----------|
| 8B         | 141.1 ns | 131.5 ns | 421.8 ns | 322.7 ns | 150.7 ns | 443.7 ns | 392.1 ns |
| 12B        | 141.0 ns | 130.2 ns | 432.6 ns | 333.2 ns | 150.0 ns | 446.6 ns | 398.4 ns |
| 16B        | 138.3 ns | 128.3 ns | 424.3 ns | 321.7 ns | 165.1 ns | 442.5 ns | 398.3 ns |
| 32B        | 157.4 ns | 143.0 ns | 445.0 ns | 344.8 ns | 166.9 ns | 460.8 ns | 408.1 ns |
| 64B        | 192.2 ns | 174.7 ns | 475.3 ns | 372.6 ns | 197.3 ns | 500.9 ns | 448.3 ns |
| 128B       | 270.2 ns | 246.5 ns | 545.2 ns | 454.2 ns | 265.7 ns | 578.3 ns | 520.6 ns |


## `dec()` Performance

| Input Size | legacy     | zrbcx     | aags     | aasv     | upbc    | apgs    | apsv    |
|-----------:|----------|----------|----------|----------|----------|----------|----------|
| 8B         | 164.1 ns | 125.9 ns | 434.7 ns | 366.4 ns | 142.3 ns | 438.7 ns | 410.1 ns |
| 12B        | 167.5 ns | 123.6 ns | 448.6 ns | 375.2 ns | 141.5 ns | 448.5 ns | 412.1 ns |
| 16B        | 163.7 ns | 122.3 ns | 439.7 ns | 365.9 ns | 140.5 ns | 436.5 ns | 409.9 ns |
| 32B        | 195.0 ns | 133.3 ns | 456.0 ns | 380.3 ns | 154.0 ns | 454.8 ns | 420.1 ns |
| 64B        | 249.8 ns | 152.0 ns | 486.4 ns | 424.4 ns | 172.7 ns | 495.0 ns | 460.2 ns |
| 128B       | 374.3 ns | 210.8 ns | 558.7 ns | 516.0 ns | 217.9 ns | 570.8 ns | 551.2 ns |


## Notes

- All benchmarks run on the same hardware (Intel i5 CPU)
- Probabilistic variants (upbc, apgs, apsv) add ~16 bytes overhead for nonce
