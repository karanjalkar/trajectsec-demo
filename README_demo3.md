# TrajectSec live demo (Option 3)

A real Claude agent's tool calls flow through an ACS-style TrajectSec hook. A
prompt injection hidden in a support ticket drives a **multi-step
exfiltration** of customer PII to an attacker-controlled sink. TrajectSec
catches it at the egress hop — the step no single tool call reveals as
malicious.

## Files

| File | Role |
| --- | --- |
| `sandbox.py` | Fake, local tools (`read_tickets`, `query_customers`, `http_post`, `send_slack`), fake customers with standard test card numbers, and the poisoned ticket `T-483` (two injection variants: `blatant` and `realistic`). `http_post` never touches the network. |
| `trajectsec.py` | The ACS-style hook. Carries the benchmark's inverse dependency index into a live setting: tool calls become trajectory hops, reads emit provenance tokens, and a send is blocked when it would carry confidential tokens to an unapproved sink. |
| `demo.py` | Runs the agent and prints the comparison. |
| `mcp_server.py` | **The TrajectSec MCP gateway.** Exposes the sandbox tools as a real MCP (stdio) server with the hook enforcing on every `tools/call`. Any MCP client connects to it. |
| `mcp_demo.py` | An MCP client that drives the gateway — a real Claude agent over MCP (`live`) and a scripted compromised client (`breach`). |
| `claude_desktop_config.snippet.json` | Config to attach the gateway to Claude Desktop so an unmodified external agent uses it. |

## MCP gateway — connecting real external agents

This is the production shape of the ACS hook: TrajectSec is an MCP server, and a
real agent's tool calls reach the tools only by travelling through it over MCP
JSON-RPC.

Run the MCP demo (launches the gateway as a subprocess, drives it as a client):

```bash
C:\demo1\.venv\Scripts\python.exe C:\demo1\mcp_demo.py --report C:\demo1\mcp_results.md
```

- `--mode breach` — scripted compromised MCP client; deterministic, **no API
  calls**; proves the gateway enforces at the protocol boundary.
- `--mode live` — a real Claude agent connected as an MCP client. In testing,
  `claude-haiku-4-5` followed the injection and posted 8 customers' name+email
  to `#crm-export`; TrajectSec's R2 blocked it **live, at the MCP gateway**
  (`claude-haiku-5-5` refused). Intermittent — it sweeps models/attempts.

Enforcement is a gateway setting (`TRAJECTSEC_ENFORCE` env), so the same agent
runs with protection on or off.

### Attach it to Claude Desktop (fully external agent)

Copy the `mcpServers` block from `claude_desktop_config.snippet.json` into
`%APPDATA%\Claude\claude_desktop_config.json`, set the `ANTHROPIC_API_KEY`
value, and restart Claude Desktop. The four tools appear inside Claude Desktop;
ask it to "triage the support queue", and watch TrajectSec gate the calls.
Claude Code can attach the same server via `claude mcp add`.

## Run

The key is read from the `ANTHROPIC_API_KEY` you saved. In PowerShell:

```bash
$env:ANTHROPIC_API_KEY = [Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY','User'); C:\demo1\.venv\Scripts\python.exe C:\demo1\demo.py --report C:\demo1\demo_results.md
```

Options: `--mode live|breach|both`, `--models a,b,c`, `--attempts N`,
`--injection realistic|blatant`.

## The two policy rules TrajectSec enforces

Both are *trajectory* rules — they fire on the combination of an upstream
confidential read and a downstream send, which the live inverse-dependency
index links together. Neither looks at a call in isolation.

- **R1 — confidential → external sink.** An `http_post` to a non-internal host
  while customer PII is in flight. Catches the classic "POST the card numbers
  to the attacker" exfiltration.
- **R2 — confidential → unapproved broadcast sink.** A `send_slack` whose body
  carries customer PII to a channel not on the PII allowlist. Catches the
  subtler leak where data is pushed to an "internal-looking" channel
  (`#crm-export`) that is really attacker-controlled. The clean triage summary
  to `#support-summary` is *not* blocked, because its body carries no PII.

## What the demo shows, honestly

A security control must be demonstrated against an attack that actually
happens — not one that happens only if the model cooperates. So there are two
parts.

### Part 1 — live agent (real Claude)

`demo.py --mode live` sweeps real models and, for each, attempts the injection
a few times (success is probabilistic). When a model follows the injection, it
runs the same model again with TrajectSec in the path and shows the catch.

**What we observed on this key (Oct 2026):**

- The current, well-aligned models (**Haiku 5.5**) refuse this injection
  essentially always.
- The previous generation (**Haiku 4.5**, **Sonnet 4.5**) *will* follow a
  well-framed injection — in testing, a live Sonnet 4.5 / Haiku 4.5 agent
  queried every customer's name and email and posted the full list to the
  attacker's `#crm-export` channel (8 records), which TrajectSec's R2 blocks.
  But they comply only **intermittently**: most runs they recognize the ticket
  as social engineering and refuse. Reproducing it live can take several
  attempts, and is sensitive to the exact injection wording.
- The reliably-susceptible legacy models (Claude 3.x) are **not enabled on this
  key** (404), so they can't be used here.

The takeaway is genuine and is itself the pitch for TrajectSec: a frontier
model *mostly* resists, but an injection attacker only needs one success, and
older or less-defended agents in a real fleet follow these instructions far
more often. Runtime enforcement does not depend on the model winning every
coin flip.

We did **not** try to jailbreak the models' safety training to force a
reliable breach — that would be both unreliable and inappropriate. The
injection here is a realistic social-engineering lure, not a safety bypass.

### Part 2 — assume-breach (compromised agent)

`demo.py --mode breach` is the deterministic demonstration. It assumes the
injection succeeded — as it would against a weaker model, a malicious MCP tool,
or a poisoned agent — and runs an agent that executes exactly what the poisoned
ticket demands: read the queue, pull customer PII, POST it to the attacker
host, then post an innocuous summary. Unprotected, all 8 records leak;
protected by TrajectSec, the egress hop is blocked and nothing leaves. This
uses **no API calls** and reproduces every time. It is the honest way to
demonstrate a guardrail: hold the agent constant and show the control is what
changes the outcome.

### How TrajectSec catches it

The violation lives in the *trajectory*, not any one call: `read_tickets`
(untrusted input enters) → `query_customers` (confidential read) → a send to an
unapproved sink. The hook records provenance tokens as hops run and indexes
them (the same inverse index as the benchmark, live). When the send is
attempted, it looks up which in-flight confidential tokens that hop would carry
and denies it — returning the full chain.

### What this is and is not

- A single-process **reference hook** on a synthetic sandbox — not the
  production CozoDB/Rust design, and not a network/latency measurement.
- The data-flow model is deliberately simple: whole-session taint plus a
  payload-content check, not field-level provenance.
- Part 1 exercises a **real** agent; Part 2 is a **simulated** compromise,
  labelled as such. Neither claims a specific model is broadly exploitable.

For a YC write-up: "a reference ACS hook catching a multi-step exfiltration in
a sandbox — demonstrated live against a real agent that followed an injected
instruction, and deterministically under an assume-breach model — paired with
the benchmark's performance result." Not production traffic.
