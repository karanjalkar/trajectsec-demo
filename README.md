# TrajectSec — runtime security for AI agents

**TrajectSec sits in an AI agent's tool-call path and stops it from being
tricked into leaking data — by checking the whole *sequence* of actions, not one
call at a time.**

This repository is a working reference demo (single-process Python) built for
the SprytechLabs / TrajectSec YC application.

---

## The problem — "approval laundering"

Enterprises are connecting AI agents to real systems (databases, Slack, email,
APIs), usually through protocols like **MCP**. An attacker can hide an
instruction in something the agent reads — a support ticket, a web page — telling
it to look up customer data and send it out.

Every individual step is something the agent is *allowed* to do, so today's
guardrails, which check **one call at a time**, let it straight through. The
breach only exists **across the sequence of calls**. We call this *approval
laundering*.

## What TrajectSec does

It runs as a **gateway in front of the agent's tools** and sees every tool call
before it executes. It tracks where each piece of data came from (a session
*trajectory* + an inverse dependency index), and makes one of four decisions on
each call — the full **Agent Control Surface** vocabulary:

| Decision | When | Example |
| --- | --- | --- |
| **allow** | benign call | read a ticket |
| **deny** | PII heading to an attacker host / unapproved channel | block the exfiltration |
| **modify** | PII in an otherwise legitimate call | redact the fields, let it proceed |
| **ask** | PII to a sensitive but sanctioned destination | hold it for human approval |

No single call is malicious; TrajectSec catches the chain.

---

## Run the demo (Windows / PowerShell)

```powershell
# one-time setup
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install anthropic mcp

# deterministic demo — a compromised agent's tool calls, caught at the gateway (no API key needed)
python mcp_demo.py --mode breach

# live demo — a REAL Claude agent over MCP, driven by a prompt injection (needs ANTHROPIC_API_KEY)
python mcp_demo.py --mode live --attempts 5

# performance
python perf_gateway.py          # live gateway overhead per tool call
python trajectsec_benchmark.py  # inverse-index invalidation vs full re-evaluation
```

**Visuals** (open in a browser):
- `architecture.html` — one-page architecture overview.
- `trajectory.html` — animated trajectory + the four decisions, with an
  enforcement on/off toggle. Regenerate its data with `python gen_trajectory_data.py`.

The demo is fully sandboxed: invented customers, standard test card numbers, and
an HTTP POST that never touches the network.

---

## What's in here

| File | Role |
| --- | --- |
| `trajectsec.py` | The TrajectSec hook — the ACS decision engine (allow/deny/modify/ask) + inverse dependency index. |
| `mcp_server.py` | The MCP gateway: the sandbox tools exposed as an MCP server with the hook enforcing on every call. |
| `mcp_demo.py` | Drives the gateway as an MCP client — a real Claude agent (live) and a scripted compromised agent (breach). |
| `sandbox.py` | Fake tools, fake customer DB, mock attacker, and the poisoned ticket. |
| `demo.py` | Non-MCP version of the agent/attack demo. |
| `perf_gateway.py` | Measures per-tool-call enforcement overhead (and that it stays flat). |
| `trajectsec_benchmark.py` | Benchmarks the inverse dependency index vs a full re-evaluation. |
| `architecture.html` / `trajectory.html` | Architecture diagram and the animated trajectory visualizer. |
| `gen_trajectory_data.py` / `viz.py` | Produce the visualizer's data from the real engine. |
| `*_results.md`, `mcp_live.md` | Saved sample outputs. |

---

## Honest scope

This is a **single-threaded Python reference implementation on a synthetic
workload** — not the planned production system (Rust hot path, Datalog/CozoDB
policy engine). Performance numbers are measured but on synthetic sessions; the
*trends* (flat overhead; the index stays flat while a re-scan grows) are the
robust result. The live-agent breach is real but intermittent (frontier models
often refuse the injection); the deterministic breach/visualizer modes
demonstrate the enforcement every time.

## Research

TrajectSec grows out of PhD research on **Effective Security Capability (ESC)** —
determining what an interconnected system of agents can *actually* accomplish
once tools and permissions combine, including capabilities that emerge through
delegation. The goal is to map the dangerous tool-and-permission chains in a
system *before* an attacker finds them.
