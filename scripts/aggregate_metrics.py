#!/usr/bin/env python3
"""Compute the headline aggregates for PAPER.md Section 8 from a recall rollup.

The mutation-survival harness emits per-(seed, form, scanner) majority verdicts;
this script derives the summary aggregates the paper reports but the harness does
not compute directly:

  * per-CoSAI-category recall (orig form) with support n,
  * equal-weighted MACRO-AVERAGE across categories (gives sparse categories equal
    voice; the support-weighted overall rate is reported alongside),
  * attack-surface breakdown from expected_detection_signal prefixes (§8.3).

Recall is computed on the `orig` form over malicious seeds; error cells are
excluded from denominators (a crash is not an allow), matching the harness.

Usage:
    PYTHONPATH=. python3 scripts/aggregate_metrics.py \
        [--rollup audit/full/e1e2-gptoss-rollup.csv] [--form orig]
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEEDS = ROOT / "guardbench" / "corpus" / "corpus_seeds.json"


def _surface(signal: str) -> str:
    """Map an expected_detection_signal to its attack-surface family (prefix before ':')."""
    head = (signal or "").split(":", 1)[0].strip().lower()
    for key in ("handler", "tool metadata", "metadata", "prompt", "resource",
                "server instructions", "server"):
        if head.startswith(key):
            return {"metadata": "tool metadata", "server": "server instructions"}.get(key, key)
    return head or "(unspecified)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rollup", type=Path, default=ROOT / "audit" / "full" / "e1e2-gptoss-rollup.csv")
    ap.add_argument("--form", default="orig")
    args = ap.parse_args()

    if not args.rollup.exists():
        print(f"missing rollup: {args.rollup}")
        return 1
    seeds = {e["id"]: e for e in json.loads(SEEDS.read_text())}
    rows = [r for r in csv.DictReader(args.rollup.open()) if r["form"] == args.form]
    scanners = sorted({r["scanner"] for r in rows})

    # verdict index
    verdict = {(r["seed_id"], r["scanner"]): r["majority_verdict"] for r in rows}

    print(f"# Aggregates ({args.rollup.name}, form={args.form})\n")
    print("## Per-category recall + macro-average\n")
    header = "| scanner | " + " | ".join(
        f"T{i}" for i in range(1, 13) if any(s["cosai_category"] == f"T{i}" for s in seeds.values())
    ) + " | macro-avg | overall |"
    print(header)
    cats = [f"T{i}" for i in range(1, 13) if any(s["cosai_category"] == f"T{i}" for s in seeds.values())]
    print("|---" * (len(cats) + 3) + "|")
    for sc in scanners:
        cells = []
        per_cat_rates = []
        tot_b = tot_n = 0
        for cat in cats:
            sids = [sid for sid, e in seeds.items() if e["cosai_category"] == cat]
            ev = [verdict.get((sid, sc)) for sid in sids if verdict.get((sid, sc)) in ("block", "allow")]
            nb = sum(1 for v in ev if v == "block")
            cells.append(f"{nb}/{len(ev)}" if ev else "—")
            if ev:
                per_cat_rates.append(nb / len(ev))
                tot_b += nb
                tot_n += len(ev)
        macro = 100 * sum(per_cat_rates) / len(per_cat_rates) if per_cat_rates else 0
        overall = 100 * tot_b / tot_n if tot_n else 0
        print(f"| `{sc}` | " + " | ".join(cells) + f" | **{macro:.1f}%** | {overall:.1f}% ({tot_b}/{tot_n}) |")

    print("\n## Attack-surface recall (§8.3)\n")
    surfaces = sorted({_surface(e.get("expected_detection_signal", "")) for e in seeds.values()})
    print("| scanner | " + " | ".join(surfaces) + " |")
    print("|---" * (len(surfaces) + 1) + "|")
    surf_of = {sid: _surface(e.get("expected_detection_signal", "")) for sid, e in seeds.items()}
    for sc in scanners:
        cells = []
        for surf in surfaces:
            sids = [sid for sid in seeds if surf_of[sid] == surf]
            ev = [verdict.get((sid, sc)) for sid in sids if verdict.get((sid, sc)) in ("block", "allow")]
            nb = sum(1 for v in ev if v == "block")
            cells.append(f"{nb}/{len(ev)}" if ev else "—")
        print(f"| `{sc}` | " + " | ".join(cells) + " |")
    # surface support line
    from collections import Counter
    supp = Counter(surf_of.values())
    print("\nsurface support: " + ", ".join(f"{k}={supp[k]}" for k in surfaces))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
