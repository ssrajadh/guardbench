"""Cross-corpus consistency relabel pass.

Catches CoSAI drift surfaced by sorting the corpus by category and
reading each block back-to-back. Two patterns of drift were found,
both originating in the taxonomy-derived batch (later in the labeling
session, when the working CoSAI definitions had narrowed):

  1. Zhao A6/A9/A12 (tool/resource/prompt OUTPUT-attack rows) were
     filed as T9 because the attack arrives in tool output. But the
     mechanism is "embed instructions in output that steer the next
     LLM turn" — that is the textbook definition of T2 (indirect
     prompt injection / context manipulation). Nothing leaves the
     trust boundary, so T9 (data exfiltration) is the wrong frame.
     Move the 3 parents + 2 synthetic variants of A6 to T2.

  2. MCPSecBench Slash-Command Overlap (3 entries) was filed as T10
     (auth/transport). The attack is a malicious server that registers
     a colliding tool name and the client routes to the impostor —
     a server-identity / supply-chain trust failure (T4), not an
     authenticated-transport failure. T10 is for MITM, OAuth flows,
     mTLS — channels, not identity-of-counterparty.

Also: three CVE-derived T7/T9 entries carried attack_type='other' as a
stopgap during initial labeling. Their mechanisms are now clear enough
to name precisely.

This file is the audit trail.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
TARGETS = [
    ROOT / "guardbench/corpus/corpus.json",
    ROOT / "guardbench/corpus/working/taxonomy_derived_draft.json",
    ROOT / "guardbench/corpus/working/synthetic_draft.json",
    ROOT / "guardbench/corpus/working/cve_derived_draft.json",
]


# id -> new cosai_category
RELABEL_COSAI: dict[str, str] = {
    # Zhao A6: tool-output instruction injection -> T2
    "TAX-ZHAO-A6-DB": "T2",
    "TAX-ZHAO-A6-FS": "T2",
    "TAX-ZHAO-A6-NOTIFY": "T2",
    "SYN-TAX-ZHAO-A6-DB-L": "T2",
    "SYN-TAX-ZHAO-A6-DB-H": "T2",
    # Zhao A9: resource-output instruction injection -> T2
    "TAX-ZHAO-A9-DB": "T2",
    "TAX-ZHAO-A9-FS": "T2",
    "TAX-ZHAO-A9-NOTIFY": "T2",
    # Zhao A12: prompt-output instruction injection -> T2
    "TAX-ZHAO-A12-DB": "T2",
    "TAX-ZHAO-A12-FS": "T2",
    "TAX-ZHAO-A12-NOTIFY": "T2",
    # Slash-overlap: counterparty identity collision -> T4
    "TAX-MCPSB-SLASHOVERLAP-DB": "T4",
    "TAX-MCPSB-SLASHOVERLAP-FS": "T4",
    "TAX-MCPSB-SLASHOVERLAP-NOTIFY": "T4",
}

RELABEL_COSAI_NOTE: dict[str, str] = {
    "ZHAO_OUTPUT_INJ":
        "Consistency relabel T9 -> T2. Mechanism is hidden directive embedded "
        "in tool/resource/prompt output that steers the next LLM turn — "
        "indirect prompt injection (T2), not data exfiltration (T9). Nothing "
        "crosses the trust boundary outward; the attack is inward into the "
        "LLM's context.",
    "SLASH_OVERLAP":
        "Consistency relabel T10 -> T4. Counterparty identity/name collision "
        "is a supply-chain trust failure (which server did the client end up "
        "talking to?), not an authenticated-transport failure. T10 covers "
        "channel integrity (MITM, mTLS, OAuth flows), not identity-of-server.",
}

ZHAO_GROUP = {
    "TAX-ZHAO-A6-DB", "TAX-ZHAO-A6-FS", "TAX-ZHAO-A6-NOTIFY",
    "SYN-TAX-ZHAO-A6-DB-L", "SYN-TAX-ZHAO-A6-DB-H",
    "TAX-ZHAO-A9-DB", "TAX-ZHAO-A9-FS", "TAX-ZHAO-A9-NOTIFY",
    "TAX-ZHAO-A12-DB", "TAX-ZHAO-A12-FS", "TAX-ZHAO-A12-NOTIFY",
}
SLASH_GROUP = {
    "TAX-MCPSB-SLASHOVERLAP-DB", "TAX-MCPSB-SLASHOVERLAP-FS",
    "TAX-MCPSB-SLASHOVERLAP-NOTIFY",
}


# id -> (new attack_type, why)
RELABEL_ATTACK_TYPE: dict[str, tuple[str, str]] = {
    "CVEDERIVED-202639313-A":
        ("dos_unbounded_buffer",
         "Initial label 'other' was a stopgap. Mechanism is clearly "
         "unbounded readRequestBody buffer growth -> OOM."),
    "SYN-CVEDERIVED-202639313-A-L":
        ("dos_unbounded_buffer", "Inherits parent's specific attack_type."),
    "SYN-CVEDERIVED-202639313-A-H":
        ("dos_unbounded_buffer", "Inherits parent's specific attack_type."),
    "CVEDERIVED-202625536-A":
        ("session_routing_leak",
         "Initial 'other' label was a stopgap. Mechanism: shared transport "
         "routes responses by most-recent response_id, leaking one session's "
         "output to another."),
    "SYN-CVEDERIVED-202625536-A-L":
        ("session_routing_leak", "Inherits parent's specific attack_type."),
    "SYN-CVEDERIVED-202625536-A-H":
        ("session_routing_leak", "Inherits parent's specific attack_type."),
    "CVEDERIVED-202631951-A":
        ("credential_egress",
         "Initial 'other' label was a stopgap. Mechanism: caller-controlled "
         "headers merge into outbound requests, sending the OAuth bearer "
         "token to an attacker-chosen URL."),
    "SYN-CVEDERIVED-202631951-A-L":
        ("credential_egress", "Inherits parent's specific attack_type."),
    "SYN-CVEDERIVED-202631951-A-H":
        ("credential_egress", "Inherits parent's specific attack_type."),
}


def _note_for_cosai(eid: str) -> str:
    if eid in ZHAO_GROUP:
        return RELABEL_COSAI_NOTE["ZHAO_OUTPUT_INJ"]
    if eid in SLASH_GROUP:
        return RELABEL_COSAI_NOTE["SLASH_OVERLAP"]
    raise KeyError(eid)


def main() -> int:
    cosai_changed = at_changed = 0
    for path in TARGETS:
        if not path.exists():
            continue
        entries = json.loads(path.read_text())
        ids = {e["id"] for e in entries}
        # Only complain about decision ids missing from the master corpus.
        if path.name == "corpus.json":
            for did in (*RELABEL_COSAI, *RELABEL_ATTACK_TYPE):
                if did not in ids:
                    print(f"decision id not in {path.name}: {did}", file=sys.stderr)
                    return 1

        for e in entries:
            if e["id"] in RELABEL_COSAI and e["cosai_category"] != RELABEL_COSAI[e["id"]]:
                old = e["cosai_category"]
                new = RELABEL_COSAI[e["id"]]
                e["cosai_category"] = new
                prior = e.get("labeling_notes") or ""
                e["labeling_notes"] = (
                    f"{_note_for_cosai(e['id'])} (was {old}) | prior: {prior}"
                )
                cosai_changed += 1
            if e["id"] in RELABEL_ATTACK_TYPE:
                new_at, why = RELABEL_ATTACK_TYPE[e["id"]]
                if e.get("attack_type") != new_at:
                    e["attack_type"] = new_at
                    prior = e.get("labeling_notes") or ""
                    e["labeling_notes"] = (
                        f"attack_type sharpened to {new_at!r}: {why} | "
                        f"prior: {prior}"
                    )
                    at_changed += 1

        path.write_text(json.dumps(entries, indent=2) + "\n")

    print(f"applied: {cosai_changed} cosai relabels, {at_changed} attack_type sharpenings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
