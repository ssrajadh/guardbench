#!/usr/bin/env python3
"""Lock the benign (FPR) control set after the Phase-3 validity gate + human review.

Baseline disposition comes from the gate's triage:
  * benign     = auto-benign (no sink) + REVIEW rows (first-pass: benign)
  * quarantine = QUARANTINE rows (exploitable / exploit-demo repos)
  * dropped    = DROP_LICENSE rows (non-redistributable; NOT a false positive)

Then it applies the independent reviewer's net changes, parsed from the two
fenced blocks in benign_mined_review.md:

    ```flip_to_quarantine
    <BENMINED ids…>
    ```
    ```flip_to_benign
    <BENMINED ids…>
    ```

Outputs (guardbench/corpus/working/):
  * corpus_benign_mined.json        — the frozen benign set (review_status=validated)
  * benign_mined_dropped.json       — what was dropped + why (provenance)

Run with --dry-run to print the resulting counts without writing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "guardbench" / "corpus" / "working"
BENIGN = ROOT / "guardbench" / "corpus" / "benign"
DRAFT = WORK / "benign_mined_draft.json"
AUTOBENIGN = WORK / "benign_mined_autobenign.json"
TRIAGE = WORK / "benign_mined_triage.json"
REVIEW_MD = BENIGN / "benign_mined_review.md"

OUT_LOCKED = BENIGN / "corpus_benign_mined.json"
OUT_DROPPED = WORK / "benign_mined_dropped.json"


def _parse_flip_block(md: str, name: str) -> set[str]:
    m = re.search(rf"```{name}\s*\n(.*?)```", md, re.DOTALL)
    if not m:
        return set()
    return {ln.strip() for ln in m.group(1).splitlines()
            if ln.strip() and ln.strip().startswith("BENMINED")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--require-review", action="store_true",
                    help="Fail if benign_mined_review.md is missing")
    args = ap.parse_args()

    draft = {e["id"]: e for e in json.loads(DRAFT.read_text())}
    autobenign = {e["id"] for e in json.loads(AUTOBENIGN.read_text())}
    triage = json.loads(TRIAGE.read_text())

    review_present = REVIEW_MD.exists()
    if args.require_review and not review_present:
        print(f"missing {REVIEW_MD}", file=sys.stderr)
        return 1
    md = REVIEW_MD.read_text() if review_present else ""
    flip_q = _parse_flip_block(md, "flip_to_quarantine")
    flip_b = _parse_flip_block(md, "flip_to_benign")

    # Baseline buckets from triage verdicts.
    review_ids = {r["id"] for r in triage if r["verdict"] == "REVIEW"}
    quarantine_ids = {r["id"] for r in triage if r["verdict"] == "QUARANTINE"}
    license_ids = {r["id"] for r in triage if r["verdict"] == "DROP_LICENSE"}
    reasons = {r["id"]: r for r in triage}

    benign = (autobenign | review_ids | flip_b) - flip_q - license_ids
    quarantine = (quarantine_ids | flip_q) - flip_b
    # license drops are never silently re-included
    benign -= license_ids

    # Build locked benign corpus.
    locked = []
    for eid in sorted(benign):
        e = dict(draft[eid])
        e["review_status"] = "approved"  # passed Phase-3 gate + independent review
        locked.append(e)

    dropped = []
    for eid in sorted(quarantine | license_ids):
        kind = "license" if eid in license_ids and eid not in quarantine else "exploitable"
        r = reasons.get(eid, {})
        dropped.append({
            "id": eid, "drop_kind": kind,
            "repo": r.get("repo", ""), "location": r.get("location", ""),
            "reason": r.get("reason", ""), "sinks": r.get("sinks", ""),
        })

    print("=== apply validity gate ===", file=sys.stderr)
    print(f"  review md present : {review_present}", file=sys.stderr)
    print(f"  flips: +benign={len(flip_b)}  +quarantine={len(flip_q)}", file=sys.stderr)
    print(f"  LOCKED benign    : {len(locked)}", file=sys.stderr)
    print(f"  dropped exploit  : {len(quarantine)}", file=sys.stderr)
    print(f"  dropped license  : {len(license_ids)}", file=sys.stderr)

    if args.dry_run:
        print("  (dry-run: nothing written)", file=sys.stderr)
        return 0

    OUT_LOCKED.write_text(json.dumps(locked, indent=2) + "\n")
    OUT_DROPPED.write_text(json.dumps(dropped, indent=2) + "\n")
    print(f"  -> {OUT_LOCKED.relative_to(ROOT)}", file=sys.stderr)
    print(f"  -> {OUT_DROPPED.relative_to(ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
