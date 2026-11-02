"""
TrajectSec live enforcement: an ACS-style hook that sits in a real agent's
tool-call path and decides each call before it runs.

The idea carried over from the benchmark
----------------------------------------
`trajectsec_benchmark.py` showed one data structure: an inverse dependency
index, token -> [hops that depend on it]. Offline, that index answered
"a capability was revoked; which in-flight trajectory hops are affected?"
in O(affected) instead of O(whole workload).

Here the same index runs live. As the agent calls tools, each call becomes a
hop in the session trajectory. Hops that read data emit provenance tokens
(e.g. a PII token when customer card numbers are read), and the index records
which hops carry which token. When the agent then tries to send data to an
external sink, TrajectSec treats the policy "confidential data must not reach
an untrusted sink" as a revocation of the confidential tokens for that sink,
and the inverse index instantly returns the chain of hops that links the read
to the attempted send. That chain IS the multi-step exfiltration.

Why this matters (and what it is not)
-------------------------------------
No single tool call here is obviously malicious: reading a ticket is fine,
querying customers is fine, an HTTP POST is fine. The violation only exists
across the *trajectory*: untrusted input -> confidential read -> external send.
A per-call allow/deny filter cannot see it; a trajectory-aware control plane
can. TrajectSec enforces at runtime, so the guarantee does not depend on the
agent (or its model) resisting the injection.

This is a single-process reference hook on the synthetic sandbox. It is not
the production CozoDB/Rust design, and the data-flow model here is deliberately
simple (whole-session taint, not field-level provenance).
"""

from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# Policy: how resources and sinks are classified. In a real deployment this is
# configuration; here it is a small, explicit table.
# ─────────────────────────────────────────────────────────────────────────────
INTERNAL_DOMAINS = (".sprytech.internal",)

# Hosts that are sanctioned integrations which legitimately handle customer data,
# but where sending PII is high-impact enough to require a human to sign off
# first. Egress of PII here is neither auto-allowed nor auto-denied -- it is the
# `ask` decision: hold the call for approval.
REVIEW_DOMAINS = ("crm-partner.example", ".crm-partner.example")

# Fields whose presence in a read makes that read confidential.
CONFIDENTIAL_FIELDS = {"email", "card_number"}

# Stable provenance token ids.
TOK_PII = "pii:customers"            # confidential customer data is in context
TOK_UNTRUSTED = "untrusted:tickets"  # externally-authored content is in context

# Channels explicitly approved to receive customer PII. A broadcast sink (Slack)
# not on this list is an unapproved destination for confidential data, even
# though it is "internal". Empty by default here: no channel is a PII sink.
PII_ALLOWLIST = {"#billing-secure"}

# Channels that are a sanctioned part of the agent's job (it SHOULD post here),
# but that must not carry raw PII. A PII-bearing post to one of these is not an
# attack to block outright -- it is legitimate work with too much in the payload,
# so TrajectSec rewrites it (strips the PII) and lets it proceed. This is the
# `modify` decision, as opposed to `deny` for unsanctioned sinks.
OPERATIONAL_CHANNELS = {"#support-summary", "#support-ops"}


@dataclass
class Hop:
    idx: int
    tool: str
    args: dict
    note: str = ""          # human-readable label for the trajectory printout
    tokens: list = field(default_factory=list)  # provenance tokens this hop emits
    blocked: bool = False
    modified: bool = False   # the call was rewritten (PII stripped) and allowed
    held: bool = False       # the call was held pending human approval (`ask`)


@dataclass
class Decision:
    allowed: bool
    action: str = "allow"   # ACS decision: allow | deny | modify | ask
    rule: str = ""          # which policy rule fired
    reason: str = ""        # plain-language explanation
    chain: list = field(default_factory=list)   # the hops that form the violation
    leaked_preview: list = field(default_factory=list)  # what WOULD have left
    new_args: dict = None   # for `modify`: the rewritten (redacted) call args
    stripped: int = 0       # for `modify`: how many records were redacted
    prompt: str = ""        # for `ask`: what a human is being asked to approve


class TrajectSecHook:
    """Wraps tool execution. Call `guard()` before running a tool; if it allows
    the call, run the tool, then call `record()` with the result."""

    def __init__(self, leak_probe=None):
        # The inverse dependency index from the benchmark, live:
        #   token -> [hop_idx, ...]  (hops that carry / established this token)
        self.index = defaultdict(list)
        self.active_tokens = set()   # tokens currently "in flight" this session
        self.path = []               # ordered trajectory of executed/attempted hops
        self.events = []             # decision log, for the report
        # Optional callback body -> [records] to show the concrete impact of a
        # blocked send. Decoupled so the hook needs no sandbox data of its own.
        self._leak_probe = leak_probe or (lambda body: [])

    # ── Classification helpers ──────────────────────────────────────────────
    @staticmethod
    def _is_external(url):
        host = urlparse(url).hostname or ""
        return not host.endswith(INTERNAL_DOMAINS)

    @staticmethod
    def _reads_confidential(tool, args):
        if tool != "query_customers":
            return False
        fields = set(args.get("fields") or [])
        return bool(fields & CONFIDENTIAL_FIELDS)

    @staticmethod
    def _is_review(url):
        host = urlparse(url).hostname or ""
        return host.endswith(REVIEW_DOMAINS)

    # ── The hook: decide a call before it runs ───────────────────────────────
    def guard(self, tool, args):
        """Evaluate the pending tool call against the trajectory so far."""
        hop_idx = len(self.path)

        # Rule R4 (ask): egress of PII to a sanctioned-but-sensitive partner.
        # Not clearly an attack (it is a known integration), not safe to auto-send
        # either -- hold it for a human to approve. Checked before R1 because a
        # review host is also "external".
        if tool == "http_post" and self._is_review(args.get("url", "")):
            confidential = [t for t in self.active_tokens if t.startswith("pii")]
            if confidential:
                host = urlparse(args.get("url", "")).hostname or "?"
                carried = self._leak_probe(args.get("body", ""))
                carriers = sorted({
                    i for tok in confidential for i in self.index.get(tok, [])
                })
                attempted = Hop(hop_idx, tool, args,
                                note=f"http_post -> {host} (partner; HELD for approval)",
                                held=True)
                dec = Decision(
                    allowed=False, action="ask",
                    rule="R4 PII to a sensitive partner -> human approval",
                    reason=(f"An export of customer PII to the partner "
                            f"integration ({host}) was requested. This is a "
                            "sanctioned destination but a high-impact action, so "
                            "TrajectSec held the call for a human to approve "
                            "before any data leaves."),
                    chain=[self.path[i] for i in carriers] + [attempted],
                    leaked_preview=carried,
                    prompt=(f"Approve exporting {len(carried)} customer records "
                            f"(incl. PII) to {host}?"),
                )
                self.events.append(("ASK", tool, dec))
                return dec

        # Rule R1: confidential data must not reach an external (untrusted) sink.
        # This is the exfiltration catch. We only need to look at the egress hop
        # and ask the inverse index which in-flight confidential tokens it would
        # carry -- O(affected hops), exactly as in the benchmark.
        if tool == "http_post" and self._is_external(args.get("url", "")):
            confidential = [t for t in self.active_tokens if t.startswith("pii")]
            if confidential:
                carriers = sorted({
                    i for tok in confidential for i in self.index.get(tok, [])
                })
                chain = [self.path[i] for i in carriers]
                # Also surface the untrusted-input ingress hop, so the full
                # multi-step story (injection -> read -> send) is visible.
                if TOK_UNTRUSTED in self.active_tokens:
                    chain = [self.path[i] for i in sorted(self.index[TOK_UNTRUSTED])] \
                            + [h for h in chain if h not in
                               [self.path[i] for i in self.index[TOK_UNTRUSTED]]]
                attempted = Hop(hop_idx, tool, args,
                                note=f"http_post -> {urlparse(args.get('url','')).hostname} (EXTERNAL)",
                                blocked=True)
                leaked = self._leak_probe(args.get("body", ""))
                dec = Decision(
                    allowed=False, action="deny",
                    rule="R1 confidential -> external-sink",
                    reason=("An external send was attempted while confidential "
                            "customer data was in flight in this session. The "
                            "trajectory links untrusted ticket input to a PII "
                            "read to this egress -- a multi-step exfiltration."),
                    chain=chain + [attempted],
                    leaked_preview=leaked,
                )
                self.events.append(("DENY", tool, dec))
                return dec

        # Rule R2: confidential data must not reach an unapproved broadcast sink.
        # A Slack post is not "external", so R1 does not fire -- but a message
        # that carries customer PII to a channel not approved for it is still a
        # leak. The distinguishing signal from a clean triage summary is that
        # this payload actually carries data from a confidential-read hop, which
        # the inverse index ties back to that read.
        if tool == "send_slack":
            channel = args.get("channel", "")
            confidential = [t for t in self.active_tokens if t.startswith("pii")]
            carried = self._leak_probe(args.get("text", ""))
            if confidential and carried and channel not in PII_ALLOWLIST:
                # R3 (modify): a sanctioned operational channel the agent SHOULD
                # post to, but the payload carries PII. Don't kill the legit
                # post -- redact the PII and let it proceed.
                if channel in OPERATIONAL_CHANNELS:
                    clean = self._redact(args.get("text", ""), carried)
                    carriers = sorted({
                        i for tok in confidential for i in self.index.get(tok, [])
                    })
                    chain = [self.path[i] for i in carriers]
                    attempted = Hop(hop_idx, tool, args,
                                    note=f"send_slack -> {channel} "
                                         f"(PII redacted: {len(carried)}, allowed)")
                    dec = Decision(
                        allowed=True, action="modify",
                        rule="R3 redact PII before an operational sink",
                        reason=(f"A post to the operational channel ({channel}) "
                                "carried customer PII. TrajectSec stripped the "
                                "sensitive fields and let the post proceed, so "
                                "the agent's legitimate work continues."),
                        chain=chain + [attempted],
                        new_args={**args, "text": clean},
                        leaked_preview=carried, stripped=len(carried),
                    )
                    self.events.append(("MODIFY", tool, dec))
                    return dec

                # R2 (deny): an unsanctioned sink has no business with this data.
                carriers = sorted({
                    i for tok in confidential for i in self.index.get(tok, [])
                })
                chain = [self.path[i] for i in carriers]
                attempted = Hop(hop_idx, tool, args,
                                note=f"send_slack -> {channel} "
                                     "(carries PII; channel not approved)",
                                blocked=True)
                dec = Decision(
                    allowed=False, action="deny",
                    rule="R2 confidential -> unapproved broadcast sink",
                    reason=("A Slack post carrying customer PII was attempted to "
                            f"a channel ({channel}) not approved for confidential "
                            "data. The payload carries data from an upstream "
                            "confidential read -- a leak no single call reveals."),
                    chain=chain + [attempted],
                    leaked_preview=carried,
                )
                self.events.append(("DENY", tool, dec))
                return dec

        dec = Decision(allowed=True, action="allow", reason="within policy")
        self.events.append(("ALLOW", tool, dec))
        return dec

    # ── Redaction for the `modify` decision ───────────────────────────────────
    @staticmethod
    def _redact(text, customers):
        """Replace each customer's email and card number with a marker."""
        for c in customers:
            if c.get("email"):
                text = text.replace(c["email"], "[redacted-email]")
            if c.get("card_number"):
                text = text.replace(c["card_number"], "[redacted-card]")
        return text

    # ── Record an executed call's provenance into the index ───────────────────
    def record(self, tool, args, result):
        """After a call runs, note what it brought into the session and index it."""
        idx = len(self.path)
        tokens, note = [], tool

        if tool == "read_tickets":
            tokens.append(TOK_UNTRUSTED)
            note = "read_tickets (untrusted external content enters context)"
        elif self._reads_confidential(tool, args):
            tokens.append(TOK_PII)
            fields = ", ".join(args.get("fields") or [])
            note = f"query_customers [{fields}] (CONFIDENTIAL read)"
        elif tool == "query_customers":
            note = f"query_customers {args.get('fields') or ['id','name','plan']}"
        elif tool == "http_post":
            host = urlparse(args.get("url", "")).hostname or "?"
            scope = "internal" if not self._is_external(args.get("url", "")) else "external"
            note = f"http_post -> {host} ({scope})"
        elif tool == "send_slack":
            note = f"send_slack -> {args.get('channel')}"

        for tok in tokens:
            self.active_tokens.add(tok)
            self.index[tok].append(idx)   # live inverse-index insert

        self.path.append(Hop(idx, tool, args, note=note, tokens=tokens))

    # ── Record a blocked call so the trajectory printout is complete ──────────
    def record_blocked(self, tool, args):
        idx = len(self.path)
        if tool == "send_slack":
            note = f"send_slack -> {args.get('channel')} (carries PII) [BLOCKED]"
        else:
            host = urlparse(args.get("url", "")).hostname or "?"
            note = f"http_post -> {host} (EXTERNAL) [BLOCKED]"
        self.path.append(Hop(idx, tool, args, note=note, blocked=True))

    # ── Record a modified (redacted) call that was allowed to proceed ─────────
    def record_modified(self, tool, args, stripped):
        idx = len(self.path)
        note = (f"send_slack -> {args.get('channel')} "
                f"(PII redacted: {stripped}) [MODIFIED]")
        self.path.append(Hop(idx, tool, args, note=note, modified=True))

    # ── Record a call held pending human approval (`ask`) ─────────────────────
    def record_ask(self, tool, args):
        idx = len(self.path)
        host = urlparse(args.get("url", "")).hostname or "?"
        note = f"http_post -> {host} (partner) [HELD for approval]"
        self.path.append(Hop(idx, tool, args, note=note, held=True))

    # ── Pretty trajectory for the report ──────────────────────────────────────
    def trajectory_lines(self):
        out = []
        for h in self.path:
            mark = "✗" if h.blocked else "•"
            toks = f"  tokens={h.tokens}" if h.tokens else ""
            out.append(f"  {mark} hop {h.idx}: {h.note}{toks}")
        return out

    # ── Structured export for the visualizer (trajectory.html) ────────────────
    def _viz_class(self, h):
        if h.blocked:
            return "blocked"
        if getattr(h, "held", False):
            return "ask"
        if getattr(h, "modified", False):
            return "modified"
        if h.tool == "read_tickets":
            return "untrusted"
        if h.tool == "query_customers":
            fields = set(h.args.get("fields") or [])
            return "pii" if fields & CONFIDENTIAL_FIELDS else "read"
        if h.tool in ("http_post", "send_slack"):
            return "sink-ok"
        return "read"

    def viz_hops(self):
        """Hops in the shape trajectory.html animates, with the decision on each
        blocked or modified hop (matched to DENY / MODIFY events in order)."""
        denies = [d for v, _, d in self.events if v == "DENY"]
        modifies = [d for v, _, d in self.events if v == "MODIFY"]
        asks = [d for v, _, d in self.events if v == "ASK"]
        di = mi = ai = 0
        out = []
        for h in self.path:
            entry = {
                "idx": h.idx, "tool": h.tool,
                "label": (h.note.replace(" [BLOCKED]", "")
                          .replace(" [MODIFIED]", "")
                          .replace(" [HELD for approval]", "")),
                "tokens": list(h.tokens), "class": self._viz_class(h),
                "blocked": h.blocked,
                "modified": getattr(h, "modified", False),
                "held": getattr(h, "held", False),
            }
            if h.blocked and di < len(denies):
                d = denies[di]; di += 1
                entry["decision"] = {
                    "rule": d.rule, "reason": d.reason,
                    "chain": [hh.note for hh in d.chain],
                    "prevented": len(d.leaked_preview),
                }
            elif getattr(h, "modified", False) and mi < len(modifies):
                d = modifies[mi]; mi += 1
                entry["decision"] = {
                    "rule": d.rule, "reason": d.reason,
                    "chain": [hh.note for hh in d.chain],
                    "prevented": d.stripped,
                }
            elif getattr(h, "held", False) and ai < len(asks):
                d = asks[ai]; ai += 1
                entry["decision"] = {
                    "rule": d.rule, "reason": d.reason,
                    "chain": [hh.note for hh in d.chain],
                    "prevented": len(d.leaked_preview),
                }
            out.append(entry)
        return out

    def would_leak(self):
        """Records that would have left, had TrajectSec not acted (deny, modify
        or ask all prevent a leak)."""
        return max((len(d.leaked_preview)
                    for v, _, d in self.events
                    if v in ("DENY", "MODIFY", "ASK")), default=0)
