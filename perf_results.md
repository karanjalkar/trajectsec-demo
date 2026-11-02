# TrajectSec live-enforcement performance

```nTrajectSec live-enforcement performance
Measured live 2026-10-29 16:41:56 on Python 3.13.14, Windows AMD64
MEASURED on synthetic sessions (randomly generated, seed 42) — NOT captured from real agent traffic. Single-threaded Python reference; absolute µs would change in the production build, the trends are the result.

1) Per-tool-call enforcement overhead (guard + record), by session length
   Session hops |   Overhead median / p95 (µs)
   ---------------------------------------------
          1,000 |         1.900 /       8.000
         10,000 |         1.800 /       7.400
        100,000 |         1.400 /       5.300

   → Overhead is flat (independent of session length) and ≈ 1.40 µs/call.
   → A single agent LLM turn ≈ 400 ms = 400,000 µs (assumed reference, not measured), so TrajectSec adds ≈ 0.00035% per call — effectively free.

2) 'Which in-flight calls are affected by this revocation?' lookup
   Session hops |   Re-scan med / p95 (µs) |   Indexed med / p95 (µs) |   Speedup | Affected
   --------------------------------------------------------------------------------------------
          1,000 |     25.100 /      27.400 |     0.2000 /      0.3000 |     126× |       10
         10,000 |    292.600 /     405.000 |     0.6500 /      1.0000 |     450× |       10
        100,000 |   2848.000 /    3656.900 |     0.6000 /      0.9000 |   4,747× |       10

   → Re-scan grows with session length; the index stays flat (cost tracks affected calls, not session size). Same property the
     original benchmark measured, now as the gateway's live lookup.
```n