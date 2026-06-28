#!/usr/bin/env python3
"""Combine recall (malicious) and FPR (benign) rollups into the §8 headline table.

Recall and FPR are prevalence-independent. Precision and F1, however, depend on
the malicious:benign ratio of the corpus (here 54 : 307), so they are reported
TWO ways and clearly labelled:

  * precision/F1 @ corpus prevalence  — counts as-collected (54 malicious orig
    seeds vs 307 benign tools); the ratio is a design choice, so read with care;
  * balanced accuracy = (recall + (1 - FPR)) / 2  and  Youden's J = recall - FPR
    — both prevalence-FREE, the defensible single-number summaries.

Recall is taken on the `orig` form (the un-obfuscated malicious seed), the like-
for-like comparison against benign tools. Error/llm_failure cells are excluded
from both numerators and denominators (a crash is not a block), matching the
harnesses.

Usage:
    PYTHONPATH=. python3 scripts/combined_metrics.py \
        [--recall audit/full/e1e2-gptoss-rollup.csv] \
        [--fpr audit/fpr/fpr-rollup.csv] [--form orig]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNERS = ["baseline", "cisco-static", "cisco-llm", "cisco-hybrid", "snyk-agent-scan"]
HEADLINE_COHORTS = {"mined", "synthetic"}  # dual_use excluded from headline FPR


def _recall(path: Path, form: str) -> dict[str, tuple[int, int]]:
    tp: dict[str, int] = {s: 0 for s in SCANNERS}
    n: dict[str, int] = {s: 0 for s in SCANNERS}
    for r in csv.DictReader(path.open()):
        if r["form"] != form:
            continue
        sc, v = r["scanner"], r["majority_verdict"]
        if v not in ("block", "allow"):  # error / llm_failure excluded
            continue
        n[sc] += 1
        if v == "block":
            tp[sc] += 1
    return {s: (tp[s], n[s]) for s in SCANNERS}


def _fpr(path: Path) -> dict[str, tuple[int, int]]:
    fp: dict[str, int] = {s: 0 for s in SCANNERS}
    n: dict[str, int] = {s: 0 for s in SCANNERS}
    for r in csv.DictReader(path.open()):
        if r["cohort"] not in HEADLINE_COHORTS:
            continue
        sc, v = r["scanner"], r["majority_verdict"]
        if v not in ("block", "allow"):
            continue
        n[sc] += 1
        if v == "block":
            fp[sc] += 1
    return {s: (fp[s], n[s]) for s in SCANNERS}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recall", type=Path, default=ROOT / "audit" / "full" / "e1e2-gptoss-rollup.csv")
    ap.add_argument("--fpr", type=Path, default=ROOT / "audit" / "fpr" / "fpr-rollup.csv")
    ap.add_argument("--form", default="orig")
    args = ap.parse_args()

    rec = _recall(args.recall, args.form)
    fpr = _fpr(args.fpr)

    print(f"# Combined detection metrics (recall form={args.form}, headline benign cohorts)\n")
    print("| scanner | recall (TP/P) | FPR (FP/N) | precision@prev | F1@prev | bal-acc | Youden J |")
    print("|---|---|---|---|---|---|---|")
    for s in SCANNERS:
        tp, P = rec[s]
        fp, N = fpr[s]
        r = tp / P if P else 0.0
        f = fp / N if N else 0.0
        prec = tp / (tp + fp) if (tp + fp) else float("nan")
        f1 = (2 * prec * r / (prec + r)) if (prec == prec and (prec + r)) else 0.0
        bal = (r + (1 - f)) / 2
        j = r - f
        prec_s = f"{prec:.1%}" if prec == prec else "—"
        f1_s = f"{f1:.1%}" if prec == prec else "—"
        print(f"| `{s}` | {r:.1%} ({tp}/{P}) | {f:.1%} ({fp}/{N}) | "
              f"{prec_s} | {f1_s} | {bal:.1%} | {j:+.3f} |")

    print(f"\nprevalence: {rec['snyk-agent-scan'][1]} malicious (orig) : "
          f"{fpr['snyk-agent-scan'][1]} benign")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
