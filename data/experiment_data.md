# AWS Test Configuration

| Item | Configuration |
|---|---|
| Test regions | `us-east-1`, `us-west-2`, `eu-west-1`, `ap-southeast-1`, `ap-northeast-1` |
| Instance type | Amazon EC2 `c7g.xlarge` (4 vCPUs, 8 GiB memory) |
| Node placement | One physical instance per logical node; committee sizes up to `n=128` |
| Fault model | `fo = fn = floor((n - 1) / 3)` |
| Repetitions | 10 runs per data point; error bars show one standard deviation |
| Implementations | ARL-ADKR and PracticalADKR Go implementations |
| Communication metric | Sent bytes per node unless a table explicitly says `sent+received` |
| Recovery metric | Recovery traffic is reported as `sent+received`, as labeled below |

## 0. Parameter Table

| n | fo=fn | K=fo+1 | L=no−fo | Practical κ(orig/p2) | Practical κ(high) | cprop (orig) | cprop (high) | cval | qval |
|---|---|---|---|---|---|---|---|---|---|
| 32 | 10 | 11 | 22 | 11 | 11 | 11 | 11 | 21 | 11 |
| 48 | 15 | 16 | 33 | 16 | 16 | 14 | 16 | 31 | 16 |
| 64 | 21 | 22 | 43 | 20 | 22 | 16 | 22 | 43 | 22 |
| 96 | 31 | 32 | 65 | 23 | 32 | 18 | 32 | 63 | 32 |
| 128 | 42 | 43 | 86 | 26 | 43 | 19 | 37 | 85 | 43 |

## 1. End-to-End Latency (Default AWS Network, s)

| n | ARL orig | ARL high | Practical orig | Practical high |
|---|---|---|---|---|
| 32 | 13.49 ± 0.78 | 14.79 ± 0.95 | 12.04 ± 0.73 | 12.04 ± 0.73 |
| 48 | 19.37 ± 1.01 | 20.87 ± 1.19 | 18.16 ± 1.06 | 18.16 ± 1.06 |
| 64 | 21.59 ± 1.32 | 23.49 ± 1.48 | 23.56 ± 1.43 | 26.36 ± 1.57 |
| 96 | 33.16 ± 1.79 | 35.86 ± 1.97 | 34.41 ± 2.15 | 48.46 ± 2.97 |
| 128 | 46.14 ± 2.26 | 49.24 ± 3.00 | 48.32 ± 2.78 | 77.56 ± 4.68 |

## 2. Latency Under Bandwidth Limits (s)

### 100 Mbps per node

| n | ARL orig | ARL high | Practical orig | Practical high |
|---|---|---|---|---|
| 32 | 16.30 ± 1.01 | 17.70 ± 1.15 | 14.84 ± 0.92 | 14.84 ± 0.92 |
| 48 | 24.86 ± 1.39 | 26.36 ± 1.56 | 23.75 ± 1.38 | 23.75 ± 1.38 |
| 64 | 27.80 ± 1.78 | 29.50 ± 1.95 | 30.70 ± 1.96 | 34.12 ± 2.05 |
| 96 | 41.38 ± 2.40 | 43.48 ± 2.70 | 48.08 ± 2.85 | 68.16 ± 4.30 |
| 128 | 61.59 ± 3.76 | 63.89 ± 4.09 | 67.91 ± 4.28 | 106.08 ± 6.79 |

### n=128 bandwidth sweep (s)

| Bandwidth | ARL orig | ARL high | Practical orig | Practical high |
|---|---|---|---|---|
| 1000 Mbps | 46.14 ± 2.26 | 48.64 ± 3.00 | 54.31 ± 3.31 | 86.18 ± 5.44 |
| 500 Mbps | 47.91 ± 2.71 | 50.41 ± 2.83 | 56.39 ± 3.27 | 90.67 ± 5.26 |
| 200 Mbps | 55.69 ± 2.95 | 58.19 ± 3.84 | 61.73 ± 3.95 | 102.85 ± 6.27 |
| 100 Mbps | 61.59 ± 3.76 | 64.09 ± 4.09 | 67.91 ± 4.28 | 106.08 ± 6.79 |
| 50 Mbps | 75.23 ± 4.66 | 77.73 ± 5.10 | 92.69 ± 6.12 | 151.37 ± 9.39 |

## 3. Recovery Traffic (MB/node, sent+received)

| n | ARL | Practical orig | Practical high | Reduction |
|---|---|---|---|---|
| 32 | 0.55 ± 0.03 | 3.00 ± 0.16 | 3.00 ± 0.17 | 81.7% |
| 48 | 0.82 ± 0.05 | 3.49 ± 0.21 | 3.49 ± 0.22 | 76.5% |
| 64 | 1.10 ± 0.07 | 4.29 ± 0.24 | 4.46 ± 0.26 | 74.4% |
| 96 | 1.37 ± 0.08 | 5.74 ± 0.35 | 7.95 ± 0.51 | 76.1% |
| 128 | 2.50 ± 0.19 | 7.42 ± 0.42 | 12.13 ± 0.79 | 66.3% |

## 4. Per-Node Sent Traffic (MB/node)

| n | ARL orig | ARL high | Practical orig | Practical high |
|---|---|---|---|---|
| 32 | 8.22 ± 0.15 | 8.22 ± 0.16 | 8.28 ± 0.16 | 8.28 ± 0.16 |
| 48 | 12.30 ± 0.23 | 12.88 ± 0.26 | 14.13 ± 0.26 | 14.13 ± 0.28 |
| 64 | 17.13 ± 0.39 | 19.52 ± 0.43 | 19.87 ± 0.45 | 21.88 ± 0.48 |
| 96 | 30.55 ± 0.68 | 40.96 ± 0.85 | 33.07 ± 0.66 | 47.77 ± 1.02 |
| 128 | 50.24 ± 1.05 | 59.78 ± 1.33 | 50.96 ± 1.12 | 82.43 ± 1.61 |

## 5. Network-Wide Sent Traffic (MB)

| n | ARL orig | ARL high | Practical orig | Practical high |
|---|---|---|---|---|
| 32 | 262.9 ± 5.2 | 262.9 ± 5.4 | 265.0 ± 5.3 | 265.0 ± 5.3 |
| 48 | 590.2 ± 10.7 | 618.2 ± 11.9 | 678.3 ± 11.9 | 678.3 ± 12.9 |
| 64 | 1096.4 ± 26.2 | 1249.3 ± 27.9 | 1272.0 ± 30.5 | 1400.2 ± 32.2 |
| 96 | 2933.1 ± 63.5 | 3932.5 ± 83.9 | 3174.7 ± 70.0 | 4586.0 ± 98.0 |
| 128 | 6431.1 ± 141.0 | 7652.1 ± 174.0 | 6522.9 ± 150.0 | 10550.7 ± 252.0 |

## 6. Per-Node Total Traffic (sent+received, MB/node)

| n | ARL orig | ARL high | Practical orig | Practical high |
|---|---|---|---|---|
| 32 | 16.43 ± 0.33 | 16.43 ± 0.31 | 16.56 ± 0.30 | 16.56 ± 0.30 |
| 48 | 24.59 ± 0.51 | 25.76 ± 0.55 | 28.26 ± 0.54 | 28.26 ± 0.56 |
| 64 | 34.26 ± 0.75 | 39.04 ± 0.80 | 39.75 ± 0.86 | 43.76 ± 0.92 |
| 96 | 61.11 ± 1.42 | 81.93 ± 1.78 | 66.14 ± 1.45 | 95.54 ± 2.20 |
| 128 | 100.49 ± 2.07 | 119.56 ± 2.71 | 101.92 ± 2.15 | 164.86 ± 3.30 |

## 7. ARC Construction Traffic (MB/node)

| n | ARC construction traffic (MB/node) | Share of total traffic (%) |
|---|---|---|
| 32 | 0.55212 | 3.36 |
| 48 | 0.82708 | 3.21 |
| 64 | 1.10222 | 2.82 |
| 96 | 1.37814 | 1.68 |
| 128 | 2.15910 | 1.81 |
