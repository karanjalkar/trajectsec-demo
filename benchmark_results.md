# TrajectSec Benchmark: Incremental Path Invalidation

## Task

A capability token is revoked mid-session. Find every in-flight trajectory hop that depends on it or on any token delegated from it. Both strategies receive the same graph and the same revocation events, and their outputs were asserted identical on every query.

- **Strategy 1, full re-evaluation:** scan all hops of all active paths, O(P·L).
- **Strategy 2, TrajectSec IDCR:** inverse index token → dependent hops, O(K) in the number of affected hops.

## Revocation latency, typical tokens (200 random revocations per row)

| Agents | Paths | Hops | Full re-eval median / p95 (µs) | IDCR median / p95 (µs) | Median speedup |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 300 | 3,000 | 11,909 | 696.4 / 760.0 | 0.90 / 4.90 | 774× |
| 1,000 | 10,000 | 39,905 | 2,206.2 / 3,079.8 | 1.20 / 5.50 | 1,839× |
| 3,000 | 30,000 | 120,140 | 6,958.1 / 7,835.1 | 1.30 / 5.50 | 5,352× |
| 10,000 | 100,000 | 399,870 | 30,309.6 / 49,248.5 | 1.85 / 17.40 | 16,384× |

## Revocation latency, worst case: root tokens (50 revocations per row)

| Agents | Paths | Full re-eval median / p95 (µs) | IDCR median / p95 (µs) | Median speedup |
| ---: | ---: | ---: | ---: | ---: |
| 300 | 3,000 | 719.4 / 774.8 | 1.70 / 7.80 | 423× |
| 1,000 | 10,000 | 2,260.1 / 2,416.2 | 2.20 / 10.40 | 1,027× |
| 3,000 | 30,000 | 7,198.6 / 8,156.7 | 3.30 / 17.20 | 2,181× |
| 10,000 | 100,000 | 31,320.5 / 46,790.3 | 2.55 / 10.30 | 12,283× |

## Cost of the IDCR

| Paths | Index build (ms) | Insert cost per path (µs) | Index memory (MB) | Affected hops per revocation, median / max |
| ---: | ---: | ---: | ---: | ---: |
| 3,000 | 1.6 | 0.52 | 1.0 | 15 / 145 |
| 10,000 | 6.2 | 0.62 | 3.4 | 14 / 184 |
| 30,000 | 28.1 | 0.94 | 10.3 | 13 / 156 |
| 100,000 | 187.7 | 1.88 | 35.0 | 12 / 168 |

## Correctness

Both strategies returned identical affected-hop sets on all 1,000 checked revocations.

## Scope and limitations

- Single-threaded Python reference implementation on a synthetic workload (random seed 42). It is not the planned CozoDB/Rust/Kafka system.
- Measures invalidation lookup only: no network, JSON-RPC, serialization, ingestion pipeline, policy evaluation or concurrency.
- The baseline is a straightforward full scan. An optimized database with its own secondary indexes would narrow the gap.
- Absolute timings depend on hardware. The scaling trend (baseline grows with workload, IDCR grows with affected hops) is the robust result.

Environment: Python 3.13.14 (CPython), Windows AMD64, CPU: Intel64 Family 6 Model 183 Stepping 1, GenuineIntel
