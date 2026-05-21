# Baseline Bench Results (JWT, SHA256)

## SHA256

```
baseline_sha256_hex_8b  time:   [190.91 ns 191.14 ns 191.38 ns]
                        change: [-0.8821% -0.6567% -0.4283%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe

baseline_sha256_hex_12b time:   [193.92 ns 194.14 ns 194.36 ns]
                        change: [+0.0331% +0.1958% +0.3717%] (p = 0.02 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  2 (2.00%) low mild
  1 (1.00%) high mild

baseline_sha256_hex_16b time:   [192.13 ns 192.33 ns 192.53 ns]
                        change: [-0.1217% +0.1223% +0.3962%] (p = 0.34 > 0.05)
                        No change in performance detected.
Found 9 outliers among 100 measurements (9.00%)
  4 (4.00%) low mild
  2 (2.00%) high mild
  3 (3.00%) high severe

baseline_sha256_hex_32b time:   [192.27 ns 192.42 ns 192.58 ns]
                        change: [-0.3969% -0.1999% -0.0289%] (p = 0.03 < 0.05)
                        Change within noise threshold.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) low mild

baseline_sha256_hex_64b time:   [232.24 ns 232.47 ns 232.69 ns]
                        change: [-0.5934% -0.4438% -0.2958%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) low mild
  2 (2.00%) high mild

baseline_sha256_hex_128b
                        time:   [267.23 ns 267.38 ns 267.55 ns]
                        change: [-0.2157% -0.0921% +0.0309%] (p = 0.14 > 0.05)
                        No change in performance detected.
Found 6 outliers among 100 measurements (6.00%)
  2 (2.00%) low mild
  4 (4.00%) high mild
```



## JWT

```
jwt_encode_8b           time:   [550.26 ns 550.35 ns 550.50 ns]
                        change: [-0.3031% -0.2616% -0.2237%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 12 outliers among 100 measurements (12.00%)
  4 (4.00%) low mild
  5 (5.00%) high mild
  3 (3.00%) high severe

jwt_decode_8b           time:   [845.60 ns 846.10 ns 846.66 ns]
Found 14 outliers among 100 measurements (14.00%)
  2 (2.00%) high mild
  12 (12.00%) high severe

jwt_encode_12b          time:   [541.59 ns 541.69 ns 541.87 ns]
Found 7 outliers among 100 measurements (7.00%)
  2 (2.00%) high mild
  5 (5.00%) high severe

jwt_decode_12b          time:   [849.67 ns 850.09 ns 850.59 ns]
Found 15 outliers among 100 measurements (15.00%)
  3 (3.00%) high mild
  12 (12.00%) high severe

jwt_encode_16b          time:   [543.73 ns 543.77 ns 543.81 ns]
Found 6 outliers among 100 measurements (6.00%)
  3 (3.00%) high mild
  3 (3.00%) high severe

jwt_decode_16b          time:   [844.36 ns 844.77 ns 845.25 ns]
Found 11 outliers among 100 measurements (11.00%)
  9 (9.00%) high mild
  2 (2.00%) high severe

jwt_encode_32b          time:   [557.17 ns 557.19 ns 557.22 ns]
                        change: [-0.4780% -0.4252% -0.3784%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) low severe
  4 (4.00%) high mild
  5 (5.00%) high severe

jwt_decode_32b          time:   [959.36 ns 959.57 ns 959.82 ns]
                        change: [-1.1171% -1.0588% -0.9941%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 10 outliers among 100 measurements (10.00%)
  1 (1.00%) low mild
  4 (4.00%) high mild
  5 (5.00%) high severe

jwt_encode_64b          time:   [654.65 ns 655.36 ns 656.20 ns]
                        change: [+0.8030% +1.0004% +1.1329%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 12 outliers among 100 measurements (12.00%)
  3 (3.00%) high mild
  9 (9.00%) high severe

jwt_decode_64b          time:   [1.1820 µs 1.1827 µs 1.1835 µs]
                        change: [-2.3601% -2.3054% -2.2443%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 15 outliers among 100 measurements (15.00%)
  1 (1.00%) high mild
  14 (14.00%) high severe

jwt_encode_128b         time:   [752.52 ns 752.69 ns 752.89 ns]
                        change: [+0.7736% +0.8374% +0.8897%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) high mild
  2 (2.00%) high severe

jwt_decode_128b         time:   [1.4271 µs 1.4280 µs 1.4291 µs]
                        change: [+0.2921% +0.3725% +0.4567%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild
```
