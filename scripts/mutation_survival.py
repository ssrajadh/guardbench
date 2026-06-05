#!/usr/bin/env python3
"""Run the mutation-survival experiment across all 5 adapters.

For each seed in corpus_seeds.json:
    for each form in {original, light_variant, heavy_variant}:
        for each adapter in {baseline, cisco-static, cisco-llm,
                             cisco-hybrid, snyk}:
            evaluate N times, record per-run results

Outputs three artifacts under audit/:

  - mutation-survival.csv       — raw per-run rows
  - mutation-survival-rollup.csv — per-(seed, form, scanner) majority verdict
  - mutation-survival.md         — human-readable summary

Re-entrant. The CSV is appended-to as rows are produced, so a crashed run
can be resumed by setting --resume.

Usage:
    PYTHONPATH=. python3 scripts/mutation_survival.py \
        [--limit N] [--seeds id1,id2,...] [--scanners ...] \
        [--n-llm N] [--resume]
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

CORPUS = ROOT / "guardbench" / "corpus" / "corpus_seeds.json"
LIGHT = ROOT / "guardbench" / "corpus" / "corpus_light.json"
HEAVY = ROOT / "guardbench" / "corpus" / "corpus_heavy.json"
OUT_CSV = ROOT / "audit" / "mutation-survival.csv"
OUT_ROLLUP = ROOT / "audit" / "mutation-survival-rollup.csv"
OUT_MD = ROOT / "audit" / "mutation-survival.md"

CSV_FIELDS = [
    "seed_id", "form", "scanner", "run_index",
    "blocked", "latency_ms", "error", "explanation", "timestamp",
]

# Which adapters get multiple runs (LLM-stochastic). Deterministic ones
# (baseline + cisco-static) always run once.
LLM_BACKED = {"cisco-llm", "cisco-hybrid", "snyk-agent-scan"}


def _make_test_case(entry: dict) -> TestCase:
    keys = set(TestCase.model_fields)
    return TestCase.model_validate({k: v for k, v in entry.items() if k in keys})


def _load_forms() -> dict[str, dict[str, TestCase]]:
    """Return {seed_id: {'orig': tc, 'light': tc, 'heavy': tc}}.

    Originals come from corpus_seeds.json; the LLM-authored light/heavy
    variants come from corpus_light.json / corpus_heavy.json (one file per
    obfuscation level), joined to their seed by parent_id.
    """
    corpus = {e["id"]: e for e in json.loads(CORPUS.read_text())}

    forms: dict[str, dict[str, TestCase]] = defaultdict(dict)
    for sid, entry in corpus.items():
        forms[sid]["orig"] = _make_test_case(entry)

    for form, path in (("light", LIGHT), ("heavy", HEAVY)):
        for v in json.loads(path.read_text()):
            parent = v.get("parent_id")
            if parent is None or parent not in corpus:
                continue
            forms[parent][form] = _make_test_case(v)

    # Filter to seeds that have all three forms.
    complete = {sid: f for sid, f in forms.items() if {"orig", "light", "heavy"} <= set(f)}
    return complete


def _build_adapters(filter_names: set[str] | None) -> list:
    """Instantiate + setup; skip adapters whose creds/binaries are missing."""
    all_adapters = [
        BaselineAdapter(),
        CiscoStaticAdapter(),
        CiscoLLMAdapter(),
        CiscoHybridAdapter(),
        SnykAgentScanAdapter(),
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
    """Run adapter.evaluate n_runs times. Catch exceptions per-run."""
    results = []
    for _ in range(n_runs):
        try:
            results.append(adapter.evaluate(tc))
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            results.append(Result(
                test_case_id=tc.id,
                tool_name=adapter.name,
                blocked=False,
                confidence=0.0,
                explanation=f"ADAPTER ERROR: {type(exc).__name__}: {exc}",
                latency_ms=0,
                raw_output={"error": str(exc)},
                timestamp=datetime.now(timezone.utc),
                error=f"{type(exc).__name__}: {exc}",
            ))
    return results


def _row(seed_id: str, form: str, scanner: str, run_index: int, r: Result) -> dict:
    return {
        "seed_id": seed_id,
        "form": form,
        "scanner": scanner,
        "run_index": run_index,
        "blocked": "Y" if r.blocked else "N",
        "latency_ms": r.latency_ms,
        "error": r.error or "",
        "explanation": (r.explanation or "")[:200],
        "timestamp": r.timestamp.isoformat(),
    }


def _existing_pairs(csv_path: Path) -> set[tuple[str, str, str]]:
    """Read existing CSV (if any) and return done (seed_id, form, scanner) keys."""
    if not csv_path.exists():
        return set()
    done = set()
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            done.add((row["seed_id"], row["form"], row["scanner"]))
    return done


def _append_rows(csv_path: Path, rows: list[dict], write_header: bool) -> None:
    mode = "w" if write_header else "a"
    with csv_path.open(mode, newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if write_header:
            w.writeheader()
        w.writerows(rows)


def run_experiment(
    forms: dict[str, dict[str, TestCase]],
    adapters: list,
    n_llm: int,
    resume: bool,
    delay_s: float = 0.0,
) -> None:
    write_header = not (resume and OUT_CSV.exists())
    if write_header and OUT_CSV.exists():
        OUT_CSV.unlink()  # fresh run; overwrite

    done_pairs = _existing_pairs(OUT_CSV) if resume else set()
    if done_pairs:
        print(f"[resume] skipping {len(done_pairs)} (seed, form, scanner) triples already in CSV",
              file=sys.stderr)

    total = sum(
        1 for sid in forms for form in ("orig", "light", "heavy")
        for a in adapters if (sid, form, a.name) not in done_pairs
    )
    done = 0
    t_start = time.monotonic()
    print(f"running {total} (seed, form, scanner) triples", file=sys.stderr)

    first_write = write_header
    for sid in sorted(forms):
        for form in ("orig", "light", "heavy"):
            tc = forms[sid][form]
            for adapter in adapters:
                if (sid, form, adapter.name) in done_pairs:
                    continue
                n_runs = n_llm if adapter.name in LLM_BACKED else 1
                results = _evaluate_one(adapter, tc, n_runs)
                rows = [_row(sid, form, adapter.name, i, r) for i, r in enumerate(results)]
                _append_rows(OUT_CSV, rows, write_header=first_write)
                first_write = False

                done += 1
                elapsed = time.monotonic() - t_start
                rate = done / elapsed if elapsed > 0 else 0
                eta_s = (total - done) / rate if rate > 0 else 0
                n_block = sum(1 for r in results if r.blocked)
                n_err = sum(1 for r in results if r.error)
                print(
                    f"  [{done:>4}/{total}] {sid:<32} {form:<5} {adapter.name:<16} "
                    f"runs={n_runs} block={n_block} err={n_err} eta={eta_s/60:.0f}m",
                    file=sys.stderr,
                    flush=True,
                )
                if delay_s > 0:
                    time.sleep(delay_s)


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def write_rollup_and_summary(adapters_used: list[str]) -> None:
    """Read mutation-survival.csv, produce rollup CSV + markdown summary."""
    with OUT_CSV.open() as f:
        rows = list(csv.DictReader(f))

    # rollup[(seed, form, scanner)] = list of rows
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for r in rows:
        grouped[(r["seed_id"], r["form"], r["scanner"])].append(r)

    rollup_rows: list[dict] = []
    for (sid, form, scanner), rs in sorted(grouped.items()):
        n_runs = len(rs)
        n_blocked = sum(1 for r in rs if r["blocked"] == "Y")
        latencies = [int(r["latency_ms"]) for r in rs if r["latency_ms"]]
        mean_latency = round(mean(latencies)) if latencies else 0
        # Majority vote ignoring errors. 'block' wins ties (conservative).
        ok = [r for r in rs if not r["error"]]
        if not ok:
            verdict = "error"
        else:
            b = sum(1 for r in ok if r["blocked"] == "Y")
            verdict = "block" if b * 2 >= len(ok) else "allow"
        rollup_rows.append({
            "seed_id": sid, "form": form, "scanner": scanner,
            "n_runs": n_runs, "n_blocked": n_blocked,
            "majority_verdict": verdict, "mean_latency_ms": mean_latency,
        })

    with OUT_ROLLUP.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rollup_rows[0].keys()))
        w.writeheader()
        w.writerows(rollup_rows)

    # ---- markdown ----
    # Index for analysis
    idx: dict[tuple[str, str, str], str] = {
        (r["seed_id"], r["form"], r["scanner"]): r["majority_verdict"]
        for r in rollup_rows
    }
    seed_ids = sorted({r["seed_id"] for r in rollup_rows})
    forms = ("orig", "light", "heavy")
    scanners = adapters_used

    # ---- per-scanner overall block rate (per form) ----
    md: list[str] = []
    md.append("# Mutation-survival experiment")
    md.append("")
    md.append(f"Generated {datetime.now(timezone.utc).isoformat()}")
    md.append("")
    md.append(f"- Seeds: {len(seed_ids)}")
    md.append(f"- Forms per seed: {', '.join(forms)}")
    md.append(f"- Scanners: {', '.join(scanners)}")
    md.append("")

    md.append("## Per-scanner block rate by form")
    md.append("")
    md.append("Fraction of seeds the scanner blocks for each form.")
    md.append("")
    md.append("| scanner | orig | light | heavy |")
    md.append("|---|---|---|---|")
    for s in scanners:
        cells = []
        for form in forms:
            n = sum(1 for sid in seed_ids if idx.get((sid, form, s)) == "block")
            total_n = sum(1 for sid in seed_ids if (sid, form, s) in idx)
            pct = (100 * n / total_n) if total_n else 0
            cells.append(f"{n}/{total_n} ({pct:.0f}%)")
        md.append(f"| `{s}` | " + " | ".join(cells) + " |")
    md.append("")

    # ---- survival vs original ----
    md.append("## Survival vs. original")
    md.append("")
    md.append("For each (seed, scanner) where the scanner blocked the *original*, "
              "did the light/heavy variant also block? Counts only over the subset "
              "where the original was blocked (so a scanner that misses the original "
              "has zero seeds in this view).")
    md.append("")
    md.append("| scanner | seeds-blocked-orig | light-survival | heavy-survival |")
    md.append("|---|---|---|---|")
    for s in scanners:
        seeds_orig_blocked = [sid for sid in seed_ids if idx.get((sid, "orig", s)) == "block"]
        l_survived = sum(1 for sid in seeds_orig_blocked if idx.get((sid, "light", s)) == "block")
        h_survived = sum(1 for sid in seeds_orig_blocked if idx.get((sid, "heavy", s)) == "block")
        if not seeds_orig_blocked:
            md.append(f"| `{s}` | 0 | — | — |")
            continue
        n = len(seeds_orig_blocked)
        md.append(
            f"| `{s}` | {n} | {l_survived}/{n} ({100*l_survived/n:.0f}%) | "
            f"{h_survived}/{n} ({100*h_survived/n:.0f}%) |"
        )
    md.append("")

    # ---- anomalies ----
    md.append("## Anomalies")
    md.append("")
    md.append("### Mutation made it MORE detectable")
    md.append("")
    md.append("Cases where the variant blocked but the original didn't — usually "
              "indicates the mutation introduced a more recognizable pattern (e.g. "
              "`exec(base64.b64decode(...))` triggers a YARA rule the original "
              "subprocess call did not).")
    md.append("")
    md.append("| seed | scanner | orig | light | heavy |")
    md.append("|---|---|---|---|---|")
    anomalies = 0
    for sid in seed_ids:
        for s in scanners:
            o = idx.get((sid, "orig", s))
            l = idx.get((sid, "light", s))
            h = idx.get((sid, "heavy", s))
            if o == "allow" and (l == "block" or h == "block"):
                md.append(f"| `{sid}` | `{s}` | {o} | {l} | {h} |")
                anomalies += 1
    if not anomalies:
        md.append("| _(none)_ | | | | |")
    md.append("")

    md.append("### Mutation broke malice")
    md.append("")
    md.append("Cases where the original blocked but BOTH variants slipped past — "
              "candidate cases for the mutation operator destroying the malicious "
              "signal. (One-variant misses are more commonly a scanner gap.)")
    md.append("")
    md.append("| seed | scanner | orig | light | heavy |")
    md.append("|---|---|---|---|---|")
    broken = 0
    for sid in seed_ids:
        for s in scanners:
            o = idx.get((sid, "orig", s))
            l = idx.get((sid, "light", s))
            h = idx.get((sid, "heavy", s))
            if o == "block" and l != "block" and h != "block":
                md.append(f"| `{sid}` | `{s}` | block | {l} | {h} |")
                broken += 1
    if not broken:
        md.append("| _(none)_ | | | | |")
    md.append("")

    OUT_MD.write_text("\n".join(md))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("--limit", type=int, default=None, help="Only run first N seeds (smoke test)")
    p.add_argument("--seeds", type=str, default=None, help="Comma-separated seed IDs to include")
    p.add_argument("--scanners", type=str, default=None, help="Comma-separated scanner names to include")
    p.add_argument("--n-llm", type=int, default=1, help="Runs per LLM-backed scanner per (seed, form)")
    p.add_argument("--delay", type=float, default=0.0, help="Sleep seconds between triples (for rate-limit friendly runs)")
    p.add_argument("--resume", action="store_true", help="Resume from existing CSV; skip done triples")
    p.add_argument("--summary-only", action="store_true", help="Skip experiment; only regenerate rollup + summary")
    args = p.parse_args()

    forms = _load_forms()
    if args.seeds:
        wanted = set(args.seeds.split(","))
        forms = {sid: f for sid, f in forms.items() if sid in wanted}
    if args.limit:
        forms = dict(list(sorted(forms.items()))[: args.limit])
    if not forms:
        print("no seeds matched — aborting", file=sys.stderr)
        return 1

    print(f"loaded {len(forms)} seeds (each with orig + light + heavy)", file=sys.stderr)

    if args.summary_only:
        if not OUT_CSV.exists():
            print(f"no CSV at {OUT_CSV} — run the experiment first", file=sys.stderr)
            return 1
        # Infer scanners from existing CSV
        scanners = sorted({r["scanner"] for r in csv.DictReader(OUT_CSV.open())})
        write_rollup_and_summary(scanners)
        print(f"wrote {OUT_ROLLUP.relative_to(ROOT)} + {OUT_MD.relative_to(ROOT)}", file=sys.stderr)
        return 0

    filter_names = set(args.scanners.split(",")) if args.scanners else None
    print("setting up adapters...", file=sys.stderr)
    adapters = _build_adapters(filter_names)
    if not adapters:
        print("no adapters ready — set env vars and retry", file=sys.stderr)
        return 1

    run_experiment(forms, adapters, n_llm=args.n_llm, resume=args.resume, delay_s=args.delay)
    write_rollup_and_summary([a.name for a in adapters])
    print(f"wrote {OUT_CSV.relative_to(ROOT)}, {OUT_ROLLUP.relative_to(ROOT)}, {OUT_MD.relative_to(ROOT)}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
