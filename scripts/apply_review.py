"""Apply review decisions for the CVE-derived draft batch.

Decisions are declared inline below.  Running this script:
  1. Loads corpus/working/cve_derived_draft.json.
  2. Applies any CoSAI relabels.
  3. Sets review_status to 'approved' or 'reviewed' (rejected) and records
     a labeling note explaining the call.
  4. Writes the updated draft back.
  5. Runs the CLI 'export-for-harness --approved-only' to produce
     corpus/corpus.json (Phase 2-compatible TestCase JSON).

This script is the audit trail: editing it changes the review.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
DRAFT = ROOT / "guardbench/corpus/working/cve_derived_draft.json"
CORPUS = ROOT / "guardbench/corpus/corpus.json"

# --- decisions -------------------------------------------------------------

REJECT: dict[str, str] = {
    "CVEDERIVED-202633032-B":
        "Handler is only a comment pointing back to variant A; no standalone "
        "test value. Variant A already covers the missing-auth pattern.",
    "CVEDERIVED-202633989-B":
        "Mechanical duplicate of variant A — function name swap only, same "
        "parameter shape and same handler pattern. No additional coverage.",
}

# (entry_id -> new_cosai)
RELABEL: dict[str, str] = {
    "CVEDERIVED-20256514-B": "T3",
}

RELABEL_NOTE = {
    "CVEDERIVED-20256514-B":
        "Relabeled T4 -> T3 during review. Variant B is newline-injection into "
        "a written config file — the mechanism is input-validation on a string "
        "that persists to disk. Variant A stays T4 because it models the "
        "supply-chain trust decision of connecting to a remote URL.",
}


def main() -> int:
    entries = json.loads(DRAFT.read_text())
    ids = {e["id"] for e in entries}

    # sanity: every decision id must be in the draft
    for did in (*REJECT, *RELABEL):
        if did not in ids:
            print(f"decision id not in draft: {did}", file=sys.stderr)
            return 1

    approved = 0
    rejected = 0
    relabeled = 0
    for e in entries:
        if e["id"] in RELABEL:
            e["cosai_category"] = RELABEL[e["id"]]
            # prepend relabel note, preserving any generator note
            old = e.get("labeling_notes") or ""
            e["labeling_notes"] = (
                RELABEL_NOTE[e["id"]] + (f" | prior: {old}" if old else "")
            )
            relabeled += 1
        if e["id"] in REJECT:
            e["review_status"] = "reviewed"  # = rejected under our convention
            prior = e.get("labeling_notes") or ""
            e["labeling_notes"] = (
                f"REJECTED during review: {REJECT[e['id']]}"
                + (f" | prior: {prior}" if prior else "")
            )
            rejected += 1
        else:
            if e["review_status"] == "draft":
                e["review_status"] = "approved"
                approved += 1

    DRAFT.write_text(json.dumps(entries, indent=2) + "\n")
    print(f"draft updated: {approved} approved, {rejected} rejected, "
          f"{relabeled} relabeled")

    # Export approved-only to corpus.json via the CLI.
    cmd = [
        sys.executable, "-m", "guardbench.corpus.cli",
        "--corpus", str(DRAFT),
        "export-for-harness",
        "--output", str(CORPUS),
        "--approved-only",
    ]
    subprocess.run(cmd, check=True, cwd=ROOT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
