#!/usr/bin/env python3
"""False-positive-rate (FPR) experiment over the benign control set.

Runs benign tool defs (expected_verdict="allow") through the same 5 adapters as
the recall run, so FPR is directly comparable to recall (PAPER §6.2). A *block*
on a benign tool is a false positive.

Two cohorts, reported separately (PAPER §11):
  * mined     — real tools from public GitHub servers (corpus_benign_mined.json).
                Base-rate FPR on tools that ship in the wild.
  * synthetic — hand-built hard negatives (corpus_benign_synthetic.json). Worst-case
                over-block rate on tripwire-adjacent-but-benign tools.

Outputs under audit/fpr/:
  * fpr.csv         — raw per-run rows
  * fpr-rollup.csv  — per-(entry, scanner) majority verdict
  * fpr.md          — FPR per scanner per cohort, per-server FPR (mined),
                      error + llm_failure buckets

Re-entrant like mutation_survival.py: --resume tops up missing runs.

Usage:
    PYTHONPATH=. python3 scripts/fpr.py [--scanners ...] [--n-llm N]
        [--cohorts mined,synthetic] [--limit N] [--resume] [--summary-only]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from guardbench.adapters.baseline import BaselineAdapter
from guardbench.adapters.cisco_scanner import CiscoStaticAdapter
from guardbench.adapters.cisco_llm import CiscoLLMAdapter
from guardbench.adapters.cisco_hybrid import CiscoHybridAdapter
from guardbench.adapters.snyk_agent_scan import SnykAgentScanAdapter
from guardbench.schemas import Result, TestCase

BENIGN = ROOT / "guardbench" / "corpus" / "benign"
COHORT_FILES = {
    "mined": BENIGN / "corpus_benign_mined.json",
    "synthetic": BENIGN / "corpus_benign_synthetic.json",
}
MINED_MANIFEST = BENIGN / "benign_mined_manifest.json"
# Dual-use offensive-security tools (pentest orchestrators): real, benign-by-
# construction MCP tools whose *purpose* is offensive, so a scanner block is
# defensible on the merits. Kept in the corpus but tagged into their own cohort
# and EXCLUDED from the headline FPR, then reported separately (PAPER §11).
DUAL_USE_IDS_FILE = BENIGN / "benign_dual_use_ids.json"

# Cohorts that count toward the headline benign FPR (clean negatives only).
HEADLINE_COHORTS = ("mined", "synthetic")

OUT_DIR = ROOT / "audit" / "fpr"
OUT_CSV = OUT_DIR / "fpr.csv"
OUT_ROLLUP = OUT_DIR / "fpr-rollup.csv"
OUT_MD = OUT_DIR / "fpr.md"

CSV_FIELDS = [
    "entry_id", "cohort", "repo", "scanner", "run_index",
    "blocked", "latency_ms", "error", "explanation", "timestamp",
]

LLM_BACKED = {"cisco-llm", "cisco-hybrid", "snyk-agent-scan"}


def _make_test_case(entry: dict) -> TestCase:
    keys = set(TestCase.model_fields)
    return TestCase.model_validate({k: v for k, v in entry.items() if k in keys})


def _load_benign(cohorts: list[str]) -> list[tuple[str, str, TestCase]]:
    """Return [(cohort, repo, TestCase), …] for the requested cohorts."""
    repo_of = {}
    if MINED_MANIFEST.exists():
        repo_of = {m["id"]: m.get("repo", "") for m in json.loads(MINED_MANIFEST.read_text())}
    dual_use = set()
    if DUAL_USE_IDS_FILE.exists():
        dual_use = set(json.loads(DUAL_USE_IDS_FILE.read_text()))
    out: list[tuple[str, str, TestCase]] = []
    for cohort in cohorts:
        path = COHORT_FILES[cohort]
        if not path.exists():
            print(f"  [warn] cohort {cohort}: {path} missing — skipped", file=sys.stderr)
            continue
        for e in json.loads(path.read_text()):
            tc = _make_test_case(e)
            if tc.expected_verdict != "allow":
                raise SystemExit(f"{tc.id} in {cohort} is not expected_verdict=allow")
            # Re-tag dual-use offensive tools into their own cohort regardless of
            # which file they live in.
            eff_cohort = "dual_use" if tc.id in dual_use else cohort
            out.append((eff_cohort, repo_of.get(tc.id, ""), tc))
    return out


def _build_adapters(filter_names: set[str] | None) -> list:
    all_adapters = [
        BaselineAdapter(), CiscoStaticAdapter(), CiscoLLMAdapter(),
        CiscoHybridAdapter(), SnykAgentScanAdapter(),
    ]
    if filter_names:
        all_adapters = [a for a in all_adapters if a.name in filter_names]
    ready = []
    for a in all_adapters:
        try:
            a.setup()
            ready.append(a)
            print(f"  [READY ] {a.name}", file=sys.stderr)
        except Exception as exc:
            print(f"  [SKIP  ] {a.name} — {type(exc).__name__}: {exc}", file=sys.stderr)
    return ready


def _evaluate_one(adapter, tc: TestCase, n_runs: int) -> list[Result]:
    results = []
    for _ in range(n_runs):
        try:
            results.append(adapter.evaluate(tc))
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            results.append(Result(
                test_case_id=tc.id, tool_name=adapter.name, blocked=False,
                confidence=0.0, explanation=f"ADAPTER ERROR: {type(exc).__name__}: {exc}",
                latency_ms=0, raw_output={"error": str(exc)},
                timestamp=datetime.now(timezone.utc),
                error=f"{type(exc).__name__}: {exc}",
            ))
    return results


def _row(eid, cohort, repo, scanner, run_index, r: Result) -> dict:
    return {
        "entry_id": eid, "cohort": cohort, "repo": repo, "scanner": scanner,
        "run_index": run_index, "blocked": "Y" if r.blocked else "N",
        "latency_ms": r.latency_ms, "error": r.error or "",
        "explanation": (r.explanation or "")[:200], "timestamp": r.timestamp.isoformat(),
    }


def _existing_counts(csv_path: Path) -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = defaultdict(int)
    if not csv_path.exists():
        return counts
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            counts[(row["entry_id"], row["scanner"])] += 1
    return counts


def _append_rows(csv_path: Path, rows: list[dict], write_header: bool) -> None:
    with csv_path.open("w" if write_header else "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            w.writeheader()
        w.writerows(rows)


def run_experiment(entries, adapters, n_llm, resume, delay_s=0.0):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_header = not (resume and OUT_CSV.exists())
    if write_header and OUT_CSV.exists():
        OUT_CSV.unlink()

    def _expected(name): return n_llm if name in LLM_BACKED else 1
    done_counts = _existing_counts(OUT_CSV) if resume else defaultdict(int)

    total = sum(
        1 for (_c, _r, tc) in entries for a in adapters
        if done_counts.get((tc.id, a.name), 0) < _expected(a.name)
    )
    done = 0
    t_start = time.monotonic()
    print(f"running {total} (entry, scanner) cells", file=sys.stderr)

    first_write = write_header
    for cohort, repo, tc in entries:
        for adapter in adapters:
            expected = _expected(adapter.name)
            have = done_counts.get((tc.id, adapter.name), 0)
            if have >= expected:
                continue
            n_runs = expected - have
            results = _evaluate_one(adapter, tc, n_runs)
            rows = [_row(tc.id, cohort, repo, adapter.name, have + i, r)
                    for i, r in enumerate(results)]
            _append_rows(OUT_CSV, rows, write_header=first_write)
            first_write = False
            done += 1
            elapsed = time.monotonic() - t_start
            rate = done / elapsed if elapsed > 0 else 0
            eta_s = (total - done) / rate if rate > 0 else 0
            n_block = sum(1 for r in results if r.blocked)
            n_err = sum(1 for r in results if r.error)
            print(f"  [{done:>4}/{total}] {tc.id:<48} {adapter.name:<16} "
                  f"runs={n_runs} block={n_block} err={n_err} eta={eta_s/60:.0f}m",
                  file=sys.stderr, flush=True)
            if delay_s > 0:
                time.sleep(delay_s)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_rollup_and_summary(scanners: list[str]) -> None:
    with OUT_CSV.open() as f:
        rows = list(csv.DictReader(f))

    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        grouped[(r["entry_id"], r["scanner"])].append(r)
    cohort_of = {r["entry_id"]: r["cohort"] for r in rows}
    repo_of = {r["entry_id"]: r["repo"] for r in rows}

    rollup_rows = []
    for (eid, scanner), rs in sorted(grouped.items()):
        ok = [r for r in rs if not r["error"]]
        if not ok:
            verdict = "error"
        else:
            b = sum(1 for r in ok if r["blocked"] == "Y")
            verdict = "block" if b * 2 >= len(ok) else "allow"
        latencies = [int(r["latency_ms"]) for r in rs if r["latency_ms"]]
        rollup_rows.append({
            "entry_id": eid, "cohort": cohort_of[eid], "repo": repo_of[eid],
            "scanner": scanner, "n_runs": len(rs),
            "n_blocked": sum(1 for r in rs if r["blocked"] == "Y"),
            "majority_verdict": verdict,
            "mean_latency_ms": round(mean(latencies)) if latencies else 0,
        })
    with OUT_ROLLUP.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rollup_rows[0].keys()))
        w.writeheader()
        w.writerows(rollup_rows)

    idx = {(r["entry_id"], r["scanner"]): r["majority_verdict"] for r in rollup_rows}
    llm_fail = {key: any("llm_failure" in (r["error"] or "") for r in rs)
                for key, rs in grouped.items()}
    entries = sorted({r["entry_id"] for r in rollup_rows})
    cohorts = sorted({cohort_of[e] for e in entries})

    def fpr_cell(scanner, entry_subset):
        verdicts = [idx[(e, scanner)] for e in entry_subset if (e, scanner) in idx]
        n_block = sum(1 for v in verdicts if v == "block")
        n_eval = sum(1 for v in verdicts if v in ("block", "allow"))
        pct = (100 * n_block / n_eval) if n_eval else 0
        return f"{n_block}/{n_eval} ({pct:.1f}%)" if n_eval else "0/0 (—)"

    md: list[str] = []
    md.append("# False-positive-rate (FPR) experiment")
    md.append("")
    md.append(f"Generated {datetime.now(timezone.utc).isoformat()}")
    md.append("")
    md.append(f"- Benign entries: {len(entries)}")
    for c in cohorts:
        md.append(f"  - {c}: {sum(1 for e in entries if cohort_of[e] == c)}")
    md.append(f"- Scanners: {', '.join(scanners)}")
    md.append("")
    md.append("FPR = fraction of *evaluated* benign tools the scanner BLOCKS "
              "(a block on a benign tool is a false positive). Entries whose every "
              "run errored are excluded from the denominator and reported under "
              "\"Errors\" / \"LLM-judge failures\" below — a crash is not an allow.")
    md.append("")

    headline_entries = [e for e in entries if cohort_of[e] in HEADLINE_COHORTS]
    md.append("## FPR by scanner and cohort")
    md.append("")
    md.append("Headline = clean-negative cohorts only (" + ", ".join(HEADLINE_COHORTS) +
              "). The `dual_use` cohort (offensive-security / pentest tools, where a "
              "block is defensible on the merits) is shown for transparency but "
              "EXCLUDED from the headline FPR.")
    md.append("")
    md.append("| scanner | " + " | ".join(cohorts) + " | **headline** |")
    md.append("|---|" + "---|" * (len(cohorts) + 1))
    for s in scanners:
        cells = [fpr_cell(s, [e for e in entries if cohort_of[e] == c]) for c in cohorts]
        cells.append("**" + fpr_cell(s, headline_entries) + "**")
        md.append(f"| `{s}` | " + " | ".join(cells) + " |")
    md.append("")

    # Per-server FPR (mined): a server counts as a false positive if ANY of its
    # tools is blocked (server-level over-block).
    mined = [e for e in entries if cohort_of[e] == "mined"]
    servers = sorted({repo_of[e] for e in mined if repo_of[e]})
    if servers:
        md.append("## Per-server FPR (mined): server blocked if ANY tool blocked")
        md.append("")
        md.append("| scanner | servers-flagged / servers-eval |")
        md.append("|---|---|")
        for s in scanners:
            flagged = 0
            evald = 0
            for srv in servers:
                tools = [e for e in mined if repo_of[e] == srv]
                verdicts = [idx[(e, s)] for e in tools if (e, s) in idx]
                ev = [v for v in verdicts if v in ("block", "allow")]
                if not ev:
                    continue
                evald += 1
                if any(v == "block" for v in ev):
                    flagged += 1
            pct = (100 * flagged / evald) if evald else 0
            md.append(f"| `{s}` | {flagged}/{evald} ({pct:.1f}%) |")
        md.append("")

    md.append("## Errors by scanner and cohort (excluded from FPR)")
    md.append("")
    md.append("| scanner | " + " | ".join(cohorts) + " |")
    md.append("|---|" + "---|" * len(cohorts))
    for s in scanners:
        cells = [str(sum(1 for e in entries if cohort_of[e] == c and idx.get((e, s)) == "error"))
                 for c in cohorts]
        md.append(f"| `{s}` | " + " | ".join(cells) + " |")
    md.append("")

    md.append("## LLM-judge failures by scanner (subset of errors)")
    md.append("")
    md.append("| scanner | count |")
    md.append("|---|---|")
    for s in scanners:
        md.append(f"| `{s}` | {sum(1 for e in entries if llm_fail.get((e, s)))} |")
    md.append("")

    md.append("## False positives (blocked benign tools)")
    md.append("")
    md.append("| entry | cohort | scanner | repo |")
    md.append("|---|---|---|---|")
    fp = 0
    for e in entries:
        for s in scanners:
            if idx.get((e, s)) == "block":
                md.append(f"| `{e}` | {cohort_of[e]} | `{s}` | {repo_of[e]} |")
                fp += 1
    if not fp:
        md.append("| _(none)_ | | | |")
    md.append("")

    OUT_MD.write_text("\n".join(md))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("--scanners", type=str, default=None)
    p.add_argument("--cohorts", type=str, default="mined,synthetic")
    p.add_argument("--n-llm", type=int, default=1)
    p.add_argument("--limit", type=int, default=None, help="first N benign entries (smoke)")
    p.add_argument("--delay", type=float, default=0.0)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--summary-only", action="store_true")
    args = p.parse_args()

    if args.summary_only:
        if not OUT_CSV.exists():
            print(f"no CSV at {OUT_CSV}", file=sys.stderr)
            return 1
        scanners = sorted({r["scanner"] for r in csv.DictReader(OUT_CSV.open())})
        write_rollup_and_summary(scanners)
        print(f"wrote {OUT_ROLLUP.relative_to(ROOT)} + {OUT_MD.relative_to(ROOT)}", file=sys.stderr)
        return 0

    cohorts = [c.strip() for c in args.cohorts.split(",") if c.strip()]
    entries = _load_benign(cohorts)
    if args.limit:
        entries = entries[: args.limit]
    if not entries:
        print("no benign entries loaded", file=sys.stderr)
        return 1
    print(f"loaded {len(entries)} benign entries "
          f"({', '.join(f'{c}={sum(1 for x in entries if x[0]==c)}' for c in cohorts)})",
          file=sys.stderr)

    print("setting up adapters...", file=sys.stderr)
    adapters = _build_adapters(set(args.scanners.split(",")) if args.scanners else None)
    if not adapters:
        print("no adapters ready", file=sys.stderr)
        return 1

    run_experiment(entries, adapters, n_llm=args.n_llm, resume=args.resume, delay_s=args.delay)
    write_rollup_and_summary([a.name for a in adapters])
    print(f"wrote {OUT_CSV.relative_to(ROOT)}, {OUT_ROLLUP.relative_to(ROOT)}, {OUT_MD.relative_to(ROOT)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
