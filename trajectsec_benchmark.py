"""
TrajectSec benchmark: incremental path invalidation vs. full re-evaluation.

Question this benchmark answers
-------------------------------
When a capability token is revoked mid-session (and with it every token
delegated from it), how quickly can we find every in-flight trajectory hop
that depended on it?

Both strategies solve exactly the same problem on exactly the same synthetic
graph, are given exactly the same revocation events, and must return exactly
the same answer (checked with an assertion on every query).

  Strategy 1 - Full re-evaluation (baseline)
      Compute the revoked token closure, then scan every hop of every active
      path. This is what a stateless or "recompute on change" control plane
      has to do. Cost grows with total workload size: O(P * L).

  Strategy 2 - TrajectSec Inverse Dependency Cache (IDCR)
      Maintain an inverse index token -> [(path_id, hop_idx)] as paths are
      ingested. On revocation, compute the same token closure, then read only
      the affected entries. Cost grows with the number of affected hops: O(K).

What is and is not measured (stated honestly in the report)
-----------------------------------------------------------
* This is a single-threaded Python reference implementation on a synthetic
  workload. It is NOT the CozoDB / Rust / Kafka production design and does
  not measure network, serialization, ingestion or concurrency costs.
* The IDCR's costs are reported, not hidden: index build time, per-path
  insert cost, and index memory.
* Latencies are reported as median and p95 over many randomized revocations,
  split into "typical" tokens and worst-case "root" tokens.
"""

import gc
import platform
import random
import statistics
import sys
import time
import tracemalloc
from collections import defaultdict
from dataclasses import dataclass

SEED = 42

# (agents, paths) scenarios. The first matches the application's stated
# workload (300 agents / 3,000 paths); the others show how each strategy scales.
SCENARIOS = [
    (300, 3_000),
    (1_000, 10_000),
    (3_000, 30_000),
    (10_000, 100_000),
]

TOKENS_PER_AGENT = 5          # capability tokens (incl. delegations) per agent
MAX_DELEGATION_DEPTH = 4      # how deep a delegation chain may go
PATH_LEN_RANGE = (2, 6)       # hops per trajectory path
RESOURCES_PER_AGENT = 2

QUERIES_TYPICAL = 200         # revocations of randomly chosen tokens
QUERIES_ROOT = 50             # revocations of root tokens (worst case)
WARMUP = 10


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic workload
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Workload:
    num_agents: int
    num_resources: int
    token_parent: list          # token_id -> parent token_id or -1 (root)
    token_children: list        # token_id -> [child token_ids]
    token_holder: list          # token_id -> agent_id
    token_scope: list           # token_id -> resource_id
    paths: list                 # path_id -> [(agent, resource, token), ...]


def build_workload(num_agents, num_paths, rng):
    num_resources = num_agents * RESOURCES_PER_AGENT
    num_tokens = num_agents * TOKENS_PER_AGENT

    parent, depth, holder, scope = [], [], [], []
    children = [[] for _ in range(num_tokens)]

    # One root token per agent, then delegated tokens hanging off existing ones.
    for t in range(num_tokens):
        if t < num_agents:
            p, d = -1, 0
        else:
            while True:
                p = rng.randrange(t)
                if depth[p] < MAX_DELEGATION_DEPTH:
                    break
            d = depth[p] + 1
            children[p].append(t)
        parent.append(p)
        depth.append(d)
        holder.append(rng.randrange(num_agents))
        scope.append(rng.randrange(num_resources))

    paths = []
    for _ in range(num_paths):
        hops = []
        for _ in range(rng.randint(*PATH_LEN_RANGE)):
            tok = rng.randrange(num_tokens)
            hops.append((holder[tok], scope[tok], tok))
        paths.append(hops)

    return Workload(num_agents, num_resources, parent, children, holder, scope, paths)


def revoked_closure(wl, token):
    """A revoked token also revokes every token delegated from it."""
    out, stack = {token}, [token]
    while stack:
        for c in wl.token_children[stack.pop()]:
            if c not in out:
                out.add(c)
                stack.append(c)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 1: full re-evaluation
# ─────────────────────────────────────────────────────────────────────────────
def invalidate_full_scan(wl, token):
    revoked = revoked_closure(wl, token)
    affected = []
    for pid, hops in enumerate(wl.paths):
        for h, (_, _, tok) in enumerate(hops):
            if tok in revoked:
                affected.append((pid, h))
    return affected


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 2: TrajectSec Inverse Dependency Cache (IDCR)
# ─────────────────────────────────────────────────────────────────────────────
class InverseDependencyCache:
    def __init__(self):
        self.index = defaultdict(list)   # token -> [(path_id, hop_idx)]

    def ingest_path(self, pid, hops):
        for h, (_, _, tok) in enumerate(hops):
            self.index[tok].append((pid, h))

    def invalidate(self, wl, token):
        affected = []
        get = self.index.get
        for tok in revoked_closure(wl, token):
            entries = get(tok)
            if entries:
                affected.extend(entries)
        return affected


# ─────────────────────────────────────────────────────────────────────────────
# Measurement helpers
# ─────────────────────────────────────────────────────────────────────────────
def time_queries(fn, tokens):
    for t in tokens[:WARMUP]:
        fn(t)
    samples = []
    gc.disable()
    try:
        for t in tokens:
            t0 = time.perf_counter_ns()
            fn(t)
            samples.append((time.perf_counter_ns() - t0) / 1_000)  # µs
    finally:
        gc.enable()
    return samples


def p95(xs):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]


def run_scenario(num_agents, num_paths, rng):
    wl = build_workload(num_agents, num_paths, rng)
    total_hops = sum(len(p) for p in wl.paths)

    # Index build cost and memory (the price paid for fast invalidation).
    # Memory is measured on a separate build, because tracing slows it down.
    gc.collect()
    tracemalloc.start()
    _mem_probe = InverseDependencyCache()
    for pid, hops in enumerate(wl.paths):
        _mem_probe.ingest_path(pid, hops)
    index_mem_mb = tracemalloc.get_traced_memory()[0] / 1e6
    tracemalloc.stop()
    del _mem_probe

    gc.collect()
    t0 = time.perf_counter()
    idcr = InverseDependencyCache()
    for pid, hops in enumerate(wl.paths):
        idcr.ingest_path(pid, hops)
    build_ms = (time.perf_counter() - t0) * 1_000

    num_tokens = len(wl.token_parent)
    typical = [rng.randrange(num_tokens) for _ in range(QUERIES_TYPICAL)]
    roots = [rng.randrange(num_agents) for _ in range(QUERIES_ROOT)]

    # Correctness: both strategies must agree on every query.
    affected_counts = []
    for t in typical + roots:
        a = sorted(invalidate_full_scan(wl, t))
        b = sorted(idcr.invalidate(wl, t))
        assert a == b, f"Mismatch on token {t}"
        affected_counts.append(len(a))

    results = {}
    for label, toks in (("typical", typical), ("root", roots)):
        s1 = time_queries(lambda t: invalidate_full_scan(wl, t), toks)
        s2 = time_queries(lambda t: idcr.invalidate(wl, t), toks)
        results[label] = {
            "s1_med": statistics.median(s1), "s1_p95": p95(s1),
            "s2_med": statistics.median(s2), "s2_p95": p95(s2),
            "speedup_med": statistics.median(s1) / statistics.median(s2),
        }

    return {
        "agents": num_agents, "paths": num_paths, "hops": total_hops,
        "tokens": num_tokens,
        "build_ms": build_ms,
        "insert_us": build_ms * 1_000 / num_paths,
        "index_mb": index_mem_mb,
        "affected_med": statistics.median(affected_counts),
        "affected_max": max(affected_counts),
        "queries_checked": len(typical) + len(roots),
        **{f"{k}_{m}": v for k, d in results.items() for m, v in d.items()},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────
def write_report(rows, path="benchmark_results.md"):
    env = (f"Python {platform.python_version()} ({platform.python_implementation()}), "
           f"{platform.system()} {platform.machine()}, "
           f"CPU: {platform.processor() or 'unknown'}")
    L = []
    L.append("# TrajectSec Benchmark: Incremental Path Invalidation\n")
    L.append("## Task\n")
    L.append("A capability token is revoked mid-session. Find every in-flight "
             "trajectory hop that depends on it or on any token delegated from "
             "it. Both strategies receive the same graph and the same revocation "
             "events, and their outputs were asserted identical on every query.\n")
    L.append("- **Strategy 1, full re-evaluation:** scan all hops of all active paths, O(P·L).")
    L.append("- **Strategy 2, TrajectSec IDCR:** inverse index token → dependent hops, O(K) "
             "in the number of affected hops.\n")

    L.append("## Revocation latency, typical tokens "
             f"({QUERIES_TYPICAL} random revocations per row)\n")
    L.append("| Agents | Paths | Hops | Full re-eval median / p95 (µs) "
             "| IDCR median / p95 (µs) | Median speedup |")
    L.append("| ---: | ---: | ---: | ---: | ---: | ---: |")
    for r in rows:
        L.append(f"| {r['agents']:,} | {r['paths']:,} | {r['hops']:,} "
                 f"| {r['typical_s1_med']:,.1f} / {r['typical_s1_p95']:,.1f} "
                 f"| {r['typical_s2_med']:,.2f} / {r['typical_s2_p95']:,.2f} "
                 f"| {r['typical_speedup_med']:,.0f}× |")

    L.append(f"\n## Revocation latency, worst case: root tokens "
             f"({QUERIES_ROOT} revocations per row)\n")
    L.append("| Agents | Paths | Full re-eval median / p95 (µs) "
             "| IDCR median / p95 (µs) | Median speedup |")
    L.append("| ---: | ---: | ---: | ---: | ---: |")
    for r in rows:
        L.append(f"| {r['agents']:,} | {r['paths']:,} "
                 f"| {r['root_s1_med']:,.1f} / {r['root_s1_p95']:,.1f} "
                 f"| {r['root_s2_med']:,.2f} / {r['root_s2_p95']:,.2f} "
                 f"| {r['root_speedup_med']:,.0f}× |")

    L.append("\n## Cost of the IDCR\n")
    L.append("| Paths | Index build (ms) | Insert cost per path (µs) "
             "| Index memory (MB) | Affected hops per revocation, median / max |")
    L.append("| ---: | ---: | ---: | ---: | ---: |")
    for r in rows:
        L.append(f"| {r['paths']:,} | {r['build_ms']:,.1f} | {r['insert_us']:.2f} "
                 f"| {r['index_mb']:.1f} | {r['affected_med']:,.0f} / {r['affected_max']:,} |")

    L.append("\n## Correctness\n")
    L.append(f"Both strategies returned identical affected-hop sets on all "
             f"{sum(r['queries_checked'] for r in rows):,} checked revocations.\n")

    L.append("## Scope and limitations\n")
    L.append("- Single-threaded Python reference implementation on a synthetic "
             "workload (random seed " f"{SEED}). It is not the planned "
             "CozoDB/Rust/Kafka system.")
    L.append("- Measures invalidation lookup only: no network, JSON-RPC, "
             "serialization, ingestion pipeline, policy evaluation or concurrency.")
    L.append("- The baseline is a straightforward full scan. An optimized "
             "database with its own secondary indexes would narrow the gap.")
    L.append("- Absolute timings depend on hardware. The scaling trend "
             "(baseline grows with workload, IDCR grows with affected hops) is "
             "the robust result.")
    L.append(f"\nEnvironment: {env}\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    return path


def main():
    rng = random.Random(SEED)
    print("TrajectSec benchmark: incremental invalidation vs full re-evaluation")
    print(f"Python {platform.python_version()} on {platform.system()} "
          f"{platform.machine()}\n")
    rows = []
    for agents, paths in SCENARIOS:
        print(f"Running {agents:,} agents / {paths:,} paths ...", flush=True)
        r = run_scenario(agents, paths, rng)
        rows.append(r)
        print(f"  typical: full {r['typical_s1_med']:,.1f} µs | "
              f"IDCR {r['typical_s2_med']:,.2f} µs | "
              f"{r['typical_speedup_med']:,.0f}×")
        print(f"  root:    full {r['root_s1_med']:,.1f} µs | "
              f"IDCR {r['root_s2_med']:,.2f} µs | "
              f"{r['root_speedup_med']:,.0f}×")
        print(f"  index build {r['build_ms']:,.1f} ms, {r['index_mb']:.1f} MB; "
              f"results identical on {r['queries_checked']} queries\n")
    out = write_report(rows)
    print(f"Report written to {out}")


if __name__ == "__main__":
    sys.exit(main())
