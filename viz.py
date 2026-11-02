"""
Shared writer for the trajectory visualizer (trajectory.html).

Keeps the run data in viz_runs.json, mirrors it to trajectory_data.js, and
injects it inline into trajectory.html between the data markers so the page is
self-contained (works on double-click, no server). Both the scripted generator
(gen_trajectory_data.py) and the live demo (mcp_demo.py --viz) write through here.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
VIZ_JSON = os.path.join(HERE, "viz_runs.json")
HTML = os.path.join(HERE, "trajectory.html")
JS = os.path.join(HERE, "trajectory_data.js")
START = "/* TRAJECTSEC_DATA_START */"
END = "/* TRAJECTSEC_DATA_END */"


def load():
    if os.path.exists(VIZ_JSON):
        with open(VIZ_JSON, encoding="utf-8") as f:
            return json.load(f)
    return {"runs": [], "pii_allowlist": []}


def write_all(payload):
    """Persist the payload and push it into both the JS file and the HTML."""
    with open(VIZ_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    assign = "window.TRAJECTSEC_RUNS = " + json.dumps(payload, indent=2) + ";"
    with open(JS, "w", encoding="utf-8") as f:
        f.write(assign + "\n")
    try:
        with open(HTML, encoding="utf-8") as f:
            html = f.read()
        i, j = html.find(START), html.find(END)
        if i != -1 and j != -1:
            html = html[:i + len(START)] + "\n" + assign + "\n" + html[j:]
            with open(HTML, "w", encoding="utf-8") as f:
                f.write(html)
    except FileNotFoundError:
        pass


def update_run(run, pii_allowlist=None):
    """Insert or replace a single run (matched by its id), keeping the rest."""
    payload = load()
    runs = payload.setdefault("runs", [])
    for k, r in enumerate(runs):
        if r.get("id") == run["id"]:
            runs[k] = run
            break
    else:
        runs.append(run)
    if pii_allowlist is not None:
        payload["pii_allowlist"] = sorted(pii_allowlist)
    write_all(payload)


# Canonical titles for the two scenarios, keyed by the rule that fired.
SCENARIO = {
    "R1": ("external", "External exfiltration — POST to attacker host",
           "A poisoned ticket drives the agent to ship card numbers to an "
           "outside server."),
    "R2": ("slack", "Broadcast exfiltration — PII to an unapproved channel",
           "The subtler leak: a customer roster pushed to an attacker-named "
           "Slack channel."),
}


def run_from_report(rep, note=""):
    """Build a visualizer run dict from a gateway trajectsec_report payload.
    Picks the scenario (id/title) from the rule that fired."""
    rule = rep["denies"][0]["rule"] if rep.get("denies") else ""
    key = "R1" if rule.startswith("R1") else "R2"
    run_id, title, subtitle = SCENARIO[key]
    if note:
        subtitle = subtitle + "  " + note
    return {
        "id": run_id, "title": title, "subtitle": subtitle,
        "hops": rep.get("hops", []),
        "blocked": rep["denies"][0] if rep.get("denies") else None,
        "would_leak": rep.get("would_leak", 0),
        "leaked": rep.get("leaked_external", 0) + rep.get("leaked_slack", 0),
        "total_customers": rep.get("total_customers", 0),
    }
