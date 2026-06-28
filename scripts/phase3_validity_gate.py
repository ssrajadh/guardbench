#!/usr/bin/env python3
"""Phase 3 of the FPR experiment: the benign-corpus validity gate.

Mining (Phase 1+2) produces a *draft* of benign tool defs. But real servers ship
real bugs, and a genuinely exploitable mined tool is a TRUE positive when a
scanner flags it — NOT a false positive. Leaving such a tool in the benign set
would inflate FPR by scoring correct detections as errors. This gate screens the
draft so a human can quarantine anything actually dangerous before it is locked.

It is deliberately *conservative*: it over-flags (favours review/quarantine over
benign) because a missed live sink corrupts the headline number, whereas an
over-cautious quarantine only costs us a benign sample. It does NOT decide
benign-ness on its own — it triages and proposes; a human makes the final call
on everything in the REVIEW/QUARANTINE buckets (see the emitted worksheet).

Triage logic per entry:
  * repo red-flag (name screams exploit/vuln/poc/demo/malicious) -> QUARANTINE
  * a dangerous sink whose argument is TAINTED by a tool parameter:
      - shell/eval/exec/deserialization  -> QUARANTINE (likely true positive)
      - sql-string-built / path / network -> REVIEW   (often intended + safe)
  * a dangerous sink with NO visible taint -> REVIEW (human confirms)
  * no sink at all                         -> BENIGN (auto; lowest risk)

Outputs (guardbench/corpus/working/):
  * benign_mined_triage.json  — full per-entry detail (sinks, taint, verdict)
  * benign_mined_triage.csv   — human worksheet (one row per non-BENIGN entry)
  * benign_mined_autobenign.json — the auto-BENIGN entries (no sink)

Nothing is locked here. After the human pass, scripts/apply_validity_gate.py
(separate) merges the human verdicts and writes the frozen corpus_benign_mined.json.
"""

from __future__ import annotations

import ast
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WORK = ROOT / "guardbench" / "corpus" / "working"
BENIGN = ROOT / "guardbench" / "corpus" / "benign"
DRAFT = WORK / "benign_mined_draft.json"
MANIFEST = BENIGN / "benign_mined_manifest.json"
LICENSES = WORK / "mined_licenses.json"  # optional backfill {repo: spdx}

OUT_TRIAGE_JSON = WORK / "benign_mined_triage.json"
OUT_TRIAGE_CSV = WORK / "benign_mined_triage.csv"
OUT_AUTOBENIGN = WORK / "benign_mined_autobenign.json"

# Licenses under which we may redistribute a derived snippet in the released
# corpus. A no-license or copyleft repo is dropped for redistribution reasons —
# distinct from exploitability (it is NOT a scanner false positive, just
# unshippable), so it gets its own verdict and is excluded from FPR scoring.
PERMISSIVE_LICENSES = {
    "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "isc", "0bsd", "unlicense",
}

# Repo names that advertise themselves as not-a-benign-server. A tool from any of
# these is quarantined wholesale regardless of its body.
REPO_REDFLAG = re.compile(
    r"(?:^|[-_/])(exploit|vuln|vulnerable|malicious|malware|poc|honeypot|"
    r"attack|ctf|challenge|backdoor|injection|insecure|hack)(?:$|[-_/])",
    re.IGNORECASE,
)

# Dangerous sinks. (label, severity, regex). severity: "exec" sinks are
# quarantine-on-taint; "soft" sinks are review-on-taint (commonly intended).
SINKS: list[tuple[str, str, re.Pattern]] = [
    ("subprocess",   "exec", re.compile(r"\b(subprocess\.\w+|os\.system|os\.popen|Popen)\s*\(")),
    ("shell_true",   "exec", re.compile(r"\bshell\s*=\s*True\b")),
    ("eval_exec",    "exec", re.compile(r"\b(eval|exec|compile|__import__)\s*\(")),
    ("getattr_dyn",  "exec", re.compile(r"\bgetattr\s*\(")),
    ("deserialize",  "exec", re.compile(r"\b(pickle\.loads?|yaml\.load|marshal\.loads|dill\.loads)\s*\(")),
    ("sql_execute",  "soft", re.compile(r"\b(execute|executemany|executescript)\s*\(")),
    ("path_io",      "soft", re.compile(r"\b(open|Path)\s*\(|os\.path\.|\.read_text\(|\.write_text\(|\.write_bytes\(")),
    ("network",      "soft", re.compile(r"\b(requests|httpx|aiohttp|urllib)\b|\.get\(\s*[\"']https?://")),
]


def load_json(p: Path):
    return json.loads(p.read_text()) if p.exists() else None


def _param_names(handler: str) -> set[str]:
    """Tool parameters = user-controlled inputs (exclude injected/self/ctx)."""
    injected = {"self", "cls", "ctx", "context"}
    try:
        tree = ast.parse(handler)
    except SyntaxError:
        return set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            names = {arg.arg for arg in (list(a.args) + list(a.kwonlyargs))}
            return names - injected
    return set()


def _danger_call_segments(handler: str) -> list[tuple[str, str]]:
    """Return (sink_kind_hint, source_segment) for risky call nodes, via AST.

    Used for taint: we check whether a tool parameter appears inside the
    *argument* source of a dangerous call, not merely anywhere in the handler.
    """
    out: list[tuple[str, str]] = []
    try:
        tree = ast.parse(handler)
    except SyntaxError:
        return out
    DANGER_FUNCS = {"system", "popen", "Popen", "eval", "exec", "compile",
                    "__import__", "getattr", "loads", "load", "execute",
                    "executemany", "executescript", "open", "run", "call",
                    "check_output", "check_call", "get", "post", "request"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        fname = fn.attr if isinstance(fn, ast.Attribute) else (fn.id if isinstance(fn, ast.Name) else "")
        if fname not in DANGER_FUNCS:
            continue
        seg = ast.get_source_segment(handler, node) or ""
        if seg:
            out.append((fname, seg))
    return out


def screen(handler: str) -> dict:
    params = _param_names(handler)
    sinks_found: list[str] = []
    exec_sink = False
    soft_sink = False
    for label, sev, pat in SINKS:
        if pat.search(handler):
            sinks_found.append(label)
            if sev == "exec":
                exec_sink = True
            else:
                soft_sink = True

    # Taint: does a parameter feed a dangerous call's arguments?
    tainted = False
    tainted_exec = False
    danger_segs = _danger_call_segments(handler)
    word = lambda p, s: re.search(rf"\b{re.escape(p)}\b", s) is not None
    for fname, seg in danger_segs:
        if any(word(p, seg) for p in params):
            tainted = True
            if fname in {"system", "popen", "Popen", "eval", "exec", "compile",
                         "__import__", "getattr", "loads", "load", "run", "call",
                         "check_output", "check_call"}:
                tainted_exec = True
    return {
        "params": sorted(params),
        "sinks": sinks_found,
        "exec_sink": exec_sink,
        "soft_sink": soft_sink,
        "tainted": tainted,
        "tainted_exec": tainted_exec,
    }


def verdict_for(repo: str, scr: dict, license_id: str) -> tuple[str, str]:
    if REPO_REDFLAG.search(repo):
        return "QUARANTINE", "repo name advertises exploit/vuln/demo"
    if (license_id or "").lower() not in PERMISSIVE_LICENSES:
        return "DROP_LICENSE", f"non-redistributable license ({license_id or 'none'})"
    if scr["tainted_exec"]:
        return "QUARANTINE", "tool parameter flows into shell/eval/deserialize sink"
    if scr["exec_sink"]:
        return "REVIEW", "exec-class sink present; taint not proven from a parameter"
    if scr["tainted"] and scr["soft_sink"]:
        return "REVIEW", "parameter flows into sql/path/network sink (often intended)"
    if scr["soft_sink"]:
        return "REVIEW", "soft sink present; confirm no injectable path"
    return "BENIGN", "no dangerous sink detected"


def main() -> int:
    draft = load_json(DRAFT)
    if draft is None:
        print(f"missing {DRAFT}; run the mine first", file=sys.stderr)
        return 1
    manifest = {m["id"]: m for m in (load_json(MANIFEST) or [])}
    licenses = load_json(LICENSES) or {}

    rows: list[dict] = []
    autobenign: list[dict] = []
    counts = {"BENIGN": 0, "REVIEW": 0, "QUARANTINE": 0, "DROP_LICENSE": 0}
    for e in draft:
        av = json.loads(e["attack_vector"])
        m = manifest.get(e["id"], {})
        repo = m.get("repo", "")
        license_id = licenses.get(repo, m.get("license", "?"))
        scr = screen(av["handler"])
        verdict, reason = verdict_for(repo, scr, license_id)
        counts[verdict] += 1
        rec = {
            "id": e["id"],
            "repo": repo,
            "license": licenses.get(repo, m.get("license", "?")),
            "location": f"{m.get('path','?')}:{m.get('lineno','?')}",
            "tool": av["name"],
            "verdict": verdict,
            "reason": reason,
            "sinks": ";".join(scr["sinks"]),
            "tainted": scr["tainted"],
            "tainted_exec": scr["tainted_exec"],
            "params": ";".join(scr["params"]),
        }
        if verdict == "BENIGN":
            autobenign.append(e)
        else:
            rows.append(rec)

    OUT_TRIAGE_JSON.write_text(json.dumps(rows, indent=2) + "\n")
    OUT_AUTOBENIGN.write_text(json.dumps(autobenign, indent=2) + "\n")
    # Worksheet sorted worst-first for human review.
    order = {"QUARANTINE": 0, "REVIEW": 1}
    rows.sort(key=lambda r: (order.get(r["verdict"], 9), r["repo"]))
    with OUT_TRIAGE_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "verdict", "human_decision", "id", "repo", "license", "location",
            "tool", "reason", "sinks", "tainted", "tainted_exec", "params",
        ])
        w.writeheader()
        for r in rows:
            r2 = dict(r)
            r2["human_decision"] = ""  # to be filled: benign | quarantine
            w.writerow(r2)

    print("=== Phase 3 validity-gate triage ===", file=sys.stderr)
    print(f"  total entries     : {len(draft)}", file=sys.stderr)
    print(f"  auto-BENIGN       : {counts['BENIGN']}  (no sink)", file=sys.stderr)
    print(f"  REVIEW            : {counts['REVIEW']}", file=sys.stderr)
    print(f"  QUARANTINE (auto) : {counts['QUARANTINE']}", file=sys.stderr)
    print(f"  DROP_LICENSE      : {counts['DROP_LICENSE']}  (unshippable, not an FP)", file=sys.stderr)
    redflag_repos = sorted({r["repo"] for r in rows
                            if r["verdict"] == "QUARANTINE" and REPO_REDFLAG.search(r["repo"])})
    if redflag_repos:
        print(f"  red-flag repos    : {', '.join(redflag_repos)}", file=sys.stderr)
    print(f"  -> {OUT_TRIAGE_CSV.relative_to(ROOT)}  (human worksheet)", file=sys.stderr)
    print(f"  -> {OUT_AUTOBENIGN.relative_to(ROOT)}", file=sys.stderr)
    print("\nNEXT: human reviews QUARANTINE+REVIEW rows in the CSV, fills "
          "human_decision = benign|quarantine, then apply_validity_gate.py locks "
          "corpus_benign_mined.json (auto-benign + human-approved benign).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
