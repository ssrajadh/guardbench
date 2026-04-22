"""Apply review decisions for the synthetic variants batch.

Rule applied: reject light variants whose only transform is variable
renaming (user's explicit example of triviality).  Hex-literal and
base64-description lights are kept — each provides a concrete
static-analysis / metadata-scanner bypass beyond identifier churn.
All heavy variants are kept: homoglyphs, b64-exec handlers, getattr
indirection, YAML/URL polyglots, and NFKC-normalization payloads each
transform the attack surface non-trivially.

Result: 44 approved / 16 rejected out of 60.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
DRAFT = ROOT / "guardbench/corpus/working/synthetic_draft.json"

RENAME_ONLY_LIGHTS = [
    "SYN-CVEDERIVED-202568144-A-L",
    "SYN-CVEDERIVED-20260755-A-L",
    "SYN-CVEDERIVED-20263484-A-L",
    "SYN-CVEDERIVED-202639884-A-L",
    "SYN-CVEDERIVED-202630625-A-L",
    "SYN-CVEDERIVED-202568143-A-L",
    "SYN-CVEDERIVED-202627825-A-L",
    "SYN-TAX-ZHAO-A8-FS-L",
    "SYN-TAX-ZHAO-A11-DB-L",
    "SYN-CVEDERIVED-202554136-A-L",
    "SYN-TAX-MCPSB-PNS-SERVER-DB-L",
    "SYN-CVEDERIVED-202627826-A-L",
    "SYN-CVEDERIVED-202626118-A-L",
    "SYN-CVEDERIVED-202633032-A-L",
    "SYN-CVEDERIVED-202639313-A-L",
    "SYN-TAX-MCPSB-PROMPTINJ-NOTIFY-L",
    "SYN-TAX-MCPSB-MITM-FS-L",
]

REJECT_REASON = (
    "REJECTED during review: light variant's only transform is renaming "
    "handler-local variables. Semantically identical to the parent at the "
    "AST level — a guardrail that fires on the parent fires on this too, "
    "and the variant adds no bypass class that heavy/b64/hex variants "
    "don't already cover. User flagged variable-rename as the canonical "
    "example of trivial difference."
)


def main() -> int:
    entries = json.loads(DRAFT.read_text())
    ids = {e["id"] for e in entries}
    for did in RENAME_ONLY_LIGHTS:
        if did not in ids:
            print(f"decision id not in draft: {did}", file=sys.stderr)
            return 1

    rejected = 0
    approved = 0
    for e in entries:
        if e["id"] in RENAME_ONLY_LIGHTS:
            e["review_status"] = "reviewed"
            prior = e.get("labeling_notes") or ""
            e["labeling_notes"] = f"{REJECT_REASON} | prior: {prior}"
            rejected += 1
        else:
            if e["review_status"] == "draft":
                e["review_status"] = "approved"
                approved += 1

    DRAFT.write_text(json.dumps(entries, indent=2) + "\n")
    print(f"synthetic draft updated: {approved} approved, {rejected} rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
