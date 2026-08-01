#!/usr/bin/env python3
"""ROC and B-ROC analysis over the recorded GuardBench verdicts.

Two curves are produced for `snyk-agent-scan`, because it is the only scanner
whose block decision exposes a usable threshold:

  * severity-ordered (a priori) — Snyk grades every finding, and the grade is a
    fixed property of the issue code (verified over 61 observations; see
    scripts/probe_snyk_severity.py). Sweeping the severity floor is therefore an
    ordering chosen by the vendor, not fitted to our data.

  * code-subset envelope (in-sample) — including issue codes one at a time in
    descending measured precision. This traces the best trade-off *available*
    from Snyk's taxonomy, but the ordering is fitted on the same data it is
    evaluated on, so it is an optimistic envelope, not an out-of-sample curve.
    It is reported as such and never used for a headline number.

The B-ROC follows Cardenas & Baras (AAAI 2006): the Bayesian false alarm rate
B_FA = Pr[benign | block] = 1 - PPV is plotted against the detection rate P_D,
with one curve per assumed base rate p. Only concave ROCs map to well-defined
B-ROCs, so the convex hull is taken first.

Usage:  python3 scripts/roc_analysis.py
Writes: figures/roc.pdf, figures/broc.pdf  (+ a LaTeX-ready table on stdout)
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
FIGS = ROOT / "figures"
SEED_CSV = ROOT / "audit" / "full" / "e1e2-gptoss.csv"
FPR_CSV = ROOT / "audit" / "fpr" / "fpr.csv"

# Snyk issue code -> severity, probed 2026-07-22 and stable per code.
# `prompt_injection` is emitted by BOTH E001 (critical) and W001 (low) and the
# recorded run collapsed them to one label, so it is held out of the ordering
# and its effect is reported as a bound instead.
SEVERITY = {
    "untrusted_content_injection": "medium",   # W015
    "sensitive_data_exposure": "medium",       # W017
    "unmapped_W019": "medium",                 # W019
    "untrusted_content_retrieval": "low",      # W016
    "workspace_data_exposure": "low",          # W018
    "destructive_capability": "low",           # W020
}
AMBIGUOUS = "prompt_injection"                 # E001 (critical) or W001 (low)
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def load(path: Path, id_col: str, scanner: str, keep) -> dict[str, list[set]]:
    """entry id -> per-run set of threat categories (error rows dropped)."""
    out: dict[str, list[set]] = defaultdict(list)
    with open(path) as f:
        for r in csv.DictReader(f):
            if r["scanner"] != scanner or r.get("error") or not keep(r):
                continue
            m = re.match(r"threats detected:\s*(.*)", (r["explanation"] or "").strip())
            cats = {c.strip() for c in m.group(1).split(",")} if m else set()
            out[r[id_col]].append(cats)
    return out


def load_verdicts(path: Path, id_col: str, scanner: str, keep) -> dict[str, list[bool]]:
    """entry id -> per-run recorded block verdicts (error rows dropped).

    Read straight from the `blocked` column rather than inferring from the
    explanation text: the Cisco adapter emits a bare "threats detected" with no
    category list when threat_names is empty (cisco_base.py:307), which a
    category-based reading would silently score as an allow.
    """
    out: dict[str, list[bool]] = defaultdict(list)
    with open(path) as f:
        for r in csv.DictReader(f):
            if r["scanner"] != scanner or r.get("error") or not keep(r):
                continue
            out[r[id_col]].append(r["blocked"] == "Y")
    return out


def rate(runs: dict[str, list[set]], blocking: set[str]) -> tuple[int, int]:
    """Majority-vote block count under a policy that blocks on `blocking`."""
    blocked = 0
    for per_run in runs.values():
        hits = [bool(c & blocking) for c in per_run]
        blocked += sum(hits) * 2 > len(hits)
    return blocked, len(runs)


def upper_hull(points: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Upper-left convex hull in ROC space, including (0,0) and (1,1)."""
    pts = sorted(set(points) | {(0.0, 0.0), (1.0, 1.0)})
    hull: list[tuple[float, float]] = []
    for p in pts:
        while len(hull) >= 2:
            (x1, y1), (x2, y2) = hull[-2], hull[-1]
            # drop hull[-1] if it lies below the line hull[-2] -> p
            if (x2 - x1) * (p[1] - y1) - (y2 - y1) * (p[0] - x1) >= 0:
                hull.pop()
            else:
                break
        hull.append(p)
    return hull


def broc(fpr: float, tpr: float, p: float) -> float | None:
    """Bayesian false alarm rate B_FA = Pr[benign|block] = 1 - PPV."""
    denom = p * tpr + (1 - p) * fpr
    return None if denom == 0 else (1 - p) * fpr / denom


def rocch_figure(points: dict[str, tuple[float, float]]) -> None:
    """Provost-Fawcett ROC convex hull over the classifiers-as-points.

    `points` maps label -> (fpr, tpr) in [0,1]. Each configuration is one point
    (the Cisco modes and baseline expose no threshold; Snyk is shown at both its
    default and severity-matched operating points). The hull identifies the
    Pareto-optimal set (a point is usable iff it is a hull vertex, per the
    ROCCH combination rule of Provost & Fawcett, generalized by Barreno,
    Cardenas & Tygar, NeurIPS 2007); points strictly under the hull are
    dominated and are never the best detector at any false-positive rate.
    """
    hull = upper_hull(list(points.values()))
    hull_set = {(round(x, 9), round(y, 9)) for x, y in hull}

    def hull_tpr_at(fpr: float) -> float:
        """TPR of the hull's upper boundary at a given fpr (linear interp)."""
        best = 0.0
        for (x1, y1), (x2, y2) in zip(hull, hull[1:]):
            if x1 <= fpr <= x2 and x2 > x1:
                best = max(best, y1 + (y2 - y1) * (fpr - x1) / (x2 - x1))
        return best

    print("\n=== ROC convex hull (classifiers as points) ===")
    print(f"{'configuration':22s} {'FPR':>7s} {'TPR':>7s}  status")
    dominated = []
    for lbl, (fpr, tpr) in sorted(points.items(), key=lambda kv: kv[1][0]):
        on = (round(fpr, 9), round(tpr, 9)) in hull_set
        gap = hull_tpr_at(fpr) - tpr
        status = "PARETO-OPTIMAL (hull vertex)" if on else f"dominated (−{gap*100:.1f} TPR pts)"
        if not on:
            dominated.append((lbl, gap))
        print(f"{lbl:22s} {fpr:7.1%} {tpr:7.1%}  {status}")
    print(f"\nhull vertices: {[l for l,(f,t) in points.items() if (round(f,9),round(t,9)) in hull_set]}")
    print(f"dominated:     {[l for l,_ in dominated] or 'none'}")

    plt.rcParams.update({"font.size": 7, "axes.linewidth": 0.6})
    fig, ax = plt.subplots(figsize=(3.4, 2.9))
    ax.plot([0, 1], [0, 1], ls=":", c="0.6", lw=0.8, label="chance")
    hx, hy = zip(*hull)
    ax.plot(hx, hy, "-", c="C0", lw=1.3, label="ROC convex hull", zorder=1)
    # Achievable region = between the hull (above) and the chance diagonal
    # (below): randomizing among the classifiers and the trivial (0,0)/(1,1)
    # rules reaches anything down to y=x, but nothing below chance. Filling to
    # y=0 would wrongly shade the un-achievable sub-diagonal triangle.
    ax.fill_between(hx, hy, hx, color="C0", alpha=0.06, zorder=0)
    markers = {"baseline": "o", "cisco-static": "s", "cisco-llm": "D",
               "cisco-hybrid": "^", "snyk (default)": "v", "snyk (med+)": "P"}
    for i, (lbl, (fpr, tpr)) in enumerate(points.items()):
        on = (round(fpr, 9), round(tpr, 9)) in hull_set
        ax.plot(fpr, tpr, marker=markers.get(lbl, "o"), ms=7, ls="none",
                mfc=f"C{i}", mec="k" if on else "0.5",
                mew=1.1 if on else 0.7, zorder=3,
                label=lbl + ("" if on else " (dominated)"))
    ax.set_xlabel("false positive rate  $P_{FA}$")
    ax.set_ylabel("true positive rate  $P_D$")
    ax.set_xlim(-0.03, 1.03)
    ax.set_ylim(-0.03, 1.03)
    ax.legend(fontsize=5.7, loc="lower right", frameon=False)
    fig.tight_layout()
    fig.savefig(FIGS / "rocch.pdf")
    fig.savefig(FIGS / "rocch.png", dpi=220)
    print(f"wrote {FIGS / 'rocch.pdf'} and rocch.png")


def main() -> None:
    ben = load(FPR_CSV, "entry_id", "snyk-agent-scan",
               lambda r: r["cohort"] in ("mined", "synthetic"))
    mal = load(SEED_CSV, "seed_id", "snyk-agent-scan", lambda r: r["form"] == "orig")

    all_cats = set(SEVERITY) | {AMBIGUOUS}

    # ---- severity-ordered sweep (a priori) --------------------------------
    print("=== Snyk, severity-ordered sweep (a priori) ===")
    sev_points = []
    for floor in ("critical", "medium", "low"):
        block = {c for c, s in SEVERITY.items() if RANK[s] >= RANK[floor]}
        rows = []
        for lbl, extra in (("lo", set()), ("hi", {AMBIGUOUS})):
            # the ambiguous label counts only when the floor admits its grade:
            # as E001 (critical) it passes every floor; as W001 (low) only "low"
            bs = block | (extra if (extra and floor != "low") else set())
            if floor == "low":
                bs = block | {AMBIGUOUS}
            tb, tn = rate(mal, bs)
            fb, fn = rate(ben, bs)
            rows.append((tb / tn, fb / fn, tb, tn, fb, fn))
        (tpr, fpr, tb, tn, fb, fn), hi = rows[0], rows[1]
        sev_points.append((fpr, tpr, floor))
        print(f"  severity >= {floor:9s} TPR={tpr:6.1%} ({tb:2d}/{tn})  "
              f"FPR={fpr:6.1%} ({fb:3d}/{fn})  J={tpr - fpr:+.3f}"
              + (f"   [upper bound TPR={hi[0]:.1%} FPR={hi[1]:.1%}]"
                 if abs(hi[0] - tpr) > 1e-9 or abs(hi[1] - fpr) > 1e-9 else ""))

    # ---- code-subset envelope (in-sample) --------------------------------
    bc, mc = defaultdict(int), defaultdict(int)
    for runs, acc in ((ben, bc), (mal, mc)):
        for per_run in runs.values():
            for c in set().union(*per_run) if per_run else set():
                acc[c] += 1
    order = sorted(all_cats, key=lambda c: -(mc[c] / max(1, mc[c] + bc[c])))
    print("\n=== Snyk, code-subset envelope (in-sample ordering) ===")
    env_points, inc = [], set()
    for c in order:
        inc.add(c)
        tb, tn = rate(mal, set(inc))
        fb, fn = rate(ben, set(inc))
        env_points.append((fb / fn, tb / tn))
        print(f"  +{c:30s} TPR={tb / tn:6.1%}  FPR={fb / fn:6.1%}")

    # ---- the other scanners (single operating points) ---------------------
    others = {}
    for sc in ("baseline", "cisco-static", "cisco-llm", "cisco-hybrid"):
        # No exposed threshold on these, so the operating point is the recorded
        # verdict under majority vote.
        b = load_verdicts(FPR_CSV, "entry_id", sc, lambda r: r["cohort"] in ("mined", "synthetic"))
        m = load_verdicts(SEED_CSV, "seed_id", sc, lambda r: r["form"] == "orig")
        tb = sum(1 for v in m.values() if sum(v) * 2 > len(v))
        fb = sum(1 for v in b.values() if sum(v) * 2 > len(v))
        others[sc] = (fb / len(b), tb / len(m))
        print(f"  {sc:14s} TPR={tb / len(m):6.1%}  FPR={fb / len(b):6.1%}")

    FIGS.mkdir(exist_ok=True)
    plt.rcParams.update({"font.size": 7, "axes.linewidth": 0.6})

    # The paper embeds only the ROC convex hull (rocch.pdf, generated below).
    # The per-classifier ROC scatter and the B-ROC curve were dropped in favour
    # of the alarm-precision table; the B-ROC result is reported as that table
    # (alarm precision = 1 - B_FA), printed next.

    # ---- operator-facing numbers ----------------------------------------
    print("\n=== alarm precision (PPV) by deployment base rate ===")
    print(f"{'config':34s}" + "".join(f"{p:>10g}" for p in (0.15, 0.05, 0.01, 0.001)))
    rows = [(f"snyk (severity >= {l})", f, t) for f, t, l in sev_points]
    rows += [(sc, f, t) for sc, (f, t) in others.items() if t > 0 or f > 0]
    for lbl, fpr, tpr in rows:
        cells = ""
        for p in (0.15, 0.05, 0.01, 0.001):
            b = broc(fpr, tpr, p)
            cells += "        --" if b is None else f"{1 - b:>10.1%}"
        print(f"{lbl:34s}{cells}")

    # ---- Figure: ROC convex hull (classifiers as points, per advisor) ----
    sev = {floor: (fpr, tpr) for fpr, tpr, floor in sev_points}
    points = {
        "baseline": others["baseline"],
        "cisco-llm": others["cisco-llm"],
        "cisco-static": others["cisco-static"],
        "cisco-hybrid": others["cisco-hybrid"],
        "snyk (med+)": sev["medium"],
        "snyk (default)": sev["low"],
    }
    rocch_figure(points)


if __name__ == "__main__":
    main()
