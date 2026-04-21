"""Corpus loader, validator, and distribution report.

Usage:
    python -m guardbench.corpus.validate <corpus.json>
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

from pydantic import ValidationError

from guardbench.corpus.schema import CorpusEntry

_COSAI = [f"T{i}" for i in range(1, 13)]

# Target distribution per CoSAI category (tune later).
_DEFAULT_TARGETS: dict[str, int] = {t: 10 for t in _COSAI}


def load_corpus(path: Path | str) -> list[CorpusEntry]:
    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a JSON array at top level")
    return [CorpusEntry.model_validate(entry) for entry in raw]


def validate_entries(entries: Iterable[CorpusEntry]) -> list[str]:
    """Return a list of validation errors; empty list means valid."""
    errors: list[str] = []
    seen: set[str] = set()
    ids = {e.id for e in entries}
    for e in entries:
        try:
            CorpusEntry.model_validate(e.model_dump(mode="json"))
        except ValidationError as exc:
            errors.append(f"{e.id}: {exc}")
        if e.id in seen:
            errors.append(f"{e.id}: duplicate id")
        seen.add(e.id)
        if e.parent_id is not None and e.parent_id not in ids:
            errors.append(f"{e.id}: parent_id {e.parent_id!r} not found in corpus")
    return errors


def distribution_report(
    entries: list[CorpusEntry],
    targets: dict[str, int] | None = None,
) -> str:
    targets = targets or _DEFAULT_TARGETS
    lines: list[str] = []
    lines.append(f"Corpus: {len(entries)} entries")
    lines.append("")

    # CoSAI
    cosai = Counter(e.cosai_category for e in entries)
    lines.append("CoSAI category  count  target  gap")
    for cat in _COSAI:
        n, tgt = cosai.get(cat, 0), targets.get(cat, 0)
        gap = tgt - n
        marker = "  OK" if gap <= 0 else f"  needs {gap}"
        lines.append(f"  {cat:<4}          {n:>5}  {tgt:>6}  {marker}")
    lines.append("")

    # Source
    lines.append("Source:")
    for src, n in Counter(e.source for e in entries).most_common():
        lines.append(f"  {src:<20} {n:>4}")
    lines.append("")

    # Obfuscation
    lines.append("Obfuscation level:")
    for lvl, n in Counter(e.obfuscation_level for e in entries).most_common():
        lines.append(f"  {lvl:<10} {n:>4}")
    lines.append("")

    # MITRE
    lines.append("MITRE technique:")
    for mit, n in Counter(e.mitre_technique_id for e in entries).most_common():
        lines.append(f"  {mit:<14} {n:>4}")
    lines.append("")

    # Review status
    lines.append("Review status:")
    for st, n in Counter(e.review_status for e in entries).most_common():
        lines.append(f"  {st:<10} {n:>4}")
    lines.append("")

    # Coverage gaps
    gaps = [c for c in _COSAI if cosai.get(c, 0) < targets.get(c, 0)]
    if gaps:
        lines.append(f"Coverage gaps: {', '.join(gaps)}")
    else:
        lines.append("Coverage gaps: none")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python -m guardbench.corpus.validate <corpus.json>")
        return 2
    entries = load_corpus(argv[0])
    errors = validate_entries(entries)
    if errors:
        print("VALIDATION ERRORS:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(distribution_report(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
