"""Merge all four working drafts into the master corpus.json.

Master file is CorpusEntry-shaped (retains provenance). TestCase-shaped
harness export is produced separately via cli.py export-for-harness.
"""
from __future__ import annotations

import json
from pathlib import Path

from guardbench.corpus.schema import CorpusEntry

ROOT = Path(__file__).parents[1]
DRAFTS = [
    ROOT / "guardbench/corpus/working/cve_derived_draft.json",
    ROOT / "guardbench/corpus/working/taxonomy_derived_draft.json",
    ROOT / "guardbench/corpus/working/synthetic_draft.json",
    ROOT / "guardbench/corpus/working/benign_draft.json",
]
OUT = ROOT / "guardbench/corpus/corpus.json"


def main() -> None:
    merged: list[dict] = []
    seen: set[str] = set()
    for d in DRAFTS:
        for raw in json.loads(d.read_text()):
            entry = CorpusEntry.model_validate(raw)  # schema check
            if entry.id in seen:
                raise SystemExit(f"duplicate id across drafts: {entry.id}")
            seen.add(entry.id)
            merged.append(entry.model_dump(mode="json"))
    OUT.write_text(json.dumps(merged, indent=2) + "\n")
    print(f"wrote master corpus: {len(merged)} entries -> {OUT}")


if __name__ == "__main__":
    main()
