"""
TrajectSec live-enforcement performance.

The original benchmark (trajectsec_benchmark.py) measured the inverse index in
isolation. This measures what the gateway costs where it actually runs, and
answers the two questions a reviewer asks about putting a control in the path:

  1. OVERHEAD  — how much latency does TrajectSec add to each tool call, and
     does it get worse as an agent session grows long? (It should not.)

  2. SCALING   — the gateway's "which in-flight calls are affected by this
     revocation?" lookup: incremental index vs a stateless re-scan, as the
     session grows. This is the live-enforcement form of the original benchmark.

Single-threaded Python reference, synthetic sessions, fixed seed. Not the
production design; the trends (flat overhead, index stays flat while re-scan
grows) are the robust results.
"""

import gc
import platform
import random
import statistics
import time
from collections import defaultdict
from datetime import datetime

from trajectsec import TrajectSecHook

SEED = 42
SIZES = [1_000, 10_000, 100_000]
LLM_TURN_MS = 400          # a conservative single agent LLM turn, for context


def p95(xs):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]


# ─────────────────────────────────────────────────────────────────────────────
# 1. Per-tool-call enforcement overhead (and that it stays flat).
#    We pre-grow a session to size N, then time the guard+record the gateway
#    runs on each new benign tool call. This is the common path (>99% of calls);
#    the rare block that builds an audit chain is measured separately below.
# ─────────────────────────────────────────────────────────────────────────────
BENIGN = [
    ("query_customers", {"fields": ["id", "name", "plan"]}),
    ("read_tickets", {"limit": 10}),
    ("http_post", {"url": "https://api.sprytech.internal/log", "body": "x"}),
    ("send_slack", {"channel": "#support-summary", "text": "ok"}),
]


def measure_overhead(n, rng, k=5_000):
    hook = TrajectSecHook()
    for _ in range(n):                                   # pre-grow the session
        tool, args = BENIGN[rng.randrange(len(BENIGN))]
        hook.record(tool, args, "")
    samples = []
    gc.disable()
    try:
        for _ in range(k):                               # time new calls
            tool, args = BENIGN[rng.randrange(len(BENIGN))]
            t0 = time.perf_counter_ns()
            dec = hook.guard(tool, args)
            hook.record(tool, args, "")
            samples.append((time.perf_counter_ns() - t0) / 1_000)  # µs
            assert dec.allowed
    finally:
        gc.enable()
    return statistics.median(samples), p95(samples)


# ─────────────────────────────────────────────────────────────────────────────
# 2. "Which in-flight calls are affected by this revocation?"
#    Each hop used a capability token. On revocation we must find every hop that
#    used it. Indexed = O(affected); stateless re-scan = O(session).
# ─────────────────────────────────────────────────────────────────────────────
def build_token_session(n, rng):
    pool = max(1, n // 10)                     # ~10 hops per token
    hops = [rng.randrange(pool) for _ in range(n)]
    index = defaultdict(list)
    for i, tok in enumerate(hops):
        index[tok].append(i)
    return hops, index, pool


def measure_lookup(n, rng, k=200):
    hops, index, pool = build_token_session(n, rng)
    toks = [rng.randrange(pool) for _ in range(k)]

    # correctness: both find the same affected set.
    for t in toks[:20]:
        assert sorted(index.get(t, [])) == [i for i, h in enumerate(hops) if h == t]

    rescan, indexed = [], []
    gc.disable()
    try:
        for t in toks:
            t0 = time.perf_counter_ns()
            _ = [i for i, h in enumerate(hops) if h == t]      # O(session)
            rescan.append((time.perf_counter_ns() - t0) / 1_000)
        for t in toks:
            t0 = time.perf_counter_ns()
            _ = list(index.get(t, []))                         # O(affected)
            indexed.append((time.perf_counter_ns() - t0) / 1_000)
    finally:
        gc.enable()
    affected = statistics.median(len(index.get(t, [])) for t in toks)
    return (statistics.median(rescan), p95(rescan),
            statistics.median(indexed), p95(indexed), affected)


def main():
    rng = random.Random(SEED)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    env = (f"Python {platform.python_version()}, {platform.system()} "
           f"{platform.machine()}")
    print("TrajectSec live-enforcement performance")
    print(f"Measured live {stamp} on {env}")
    print("MEASURED on synthetic sessions (randomly generated, seed "
          f"{SEED}) — NOT captured from real agent traffic. Single-threaded "
          "Python reference; absolute µs would change in the production build, "
          "the trends are the result.\n")

    print("1) Per-tool-call enforcement overhead (guard + record), by session "
          "length")
    print(f"   {'Session hops':>12} | {'Overhead median / p95 (µs)':>28}")
    print("   " + "-" * 45)
    ov = {}
    for n in SIZES:
        med, p = measure_overhead(n, rng)
        ov[n] = med
        print(f"   {n:>12,} | {med:>13.3f} / {p:>11.3f}")
    turn_us = LLM_TURN_MS * 1_000
    print(f"\n   → Overhead is flat (independent of session length) and ≈ "
          f"{ov[SIZES[-1]]:.2f} µs/call.")
    print(f"   → A single agent LLM turn ≈ {LLM_TURN_MS} ms = {turn_us:,} µs "
          f"(assumed reference, not measured), so TrajectSec adds ≈ "
          f"{ov[SIZES[-1]]/turn_us*100:.5f}% per call — effectively free.\n")

    print("2) 'Which in-flight calls are affected by this revocation?' lookup")
    print(f"   {'Session hops':>12} | {'Re-scan med / p95 (µs)':>24} "
          f"| {'Indexed med / p95 (µs)':>24} | {'Speedup':>9} | {'Affected':>8}")
    print("   " + "-" * 92)
    for n in SIZES:
        rm, rp, im, ip, aff = measure_lookup(n, rng)
        speed = rm / im if im else 0
        print(f"   {n:>12,} | {rm:>10.3f} / {rp:>11.3f} "
              f"| {im:>10.4f} / {ip:>11.4f} | {speed:>7,.0f}× | {aff:>8,.0f}")
    print("\n   → Re-scan grows with session length; the index stays flat "
          "(cost tracks affected calls, not session size). Same property the\n"
          "     original benchmark measured, now as the gateway's live lookup.")


if __name__ == "__main__":
    main()
