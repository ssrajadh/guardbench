"""CVE catalog for MCP-related vulnerabilities (Jan-Feb 2026 wave).

Loads and validates ``cve_catalog.json``. Each entry is a :class:`CVERecord`
— a real-world CVE affecting an MCP server, client, proxy, or SDK that we
use to derive T1-T12 benchmark test cases.

Usage:
    python -m guardbench.corpus.sources.cve_catalog   # prints report
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable


class RootCause(str, Enum):
    SHELL_INJECTION = "shell_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_BYPASS = "auth_bypass"
    TOOL_POISONING = "tool_poisoning"
    SSRF = "ssrf"
    OTHER = "other"


_COSAI_CATEGORIES = {f"T{i}" for i in range(1, 13)}


@dataclass(frozen=True)
class CVERecord:
    cve_id: str
    affected_component: str
    root_cause: RootCause
    payload_summary: str
    cosai_suggested_category: str
    mitre_suggested_technique: str
    source_url: str
    notes: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["root_cause"] = self.root_cause.value
        return d


_CATALOG_PATH = Path(__file__).with_suffix(".json")


def load_catalog(path: Path | str = _CATALOG_PATH) -> list[CVERecord]:
    raw = json.loads(Path(path).read_text())
    records: list[CVERecord] = []
    for entry in raw:
        records.append(
            CVERecord(
                cve_id=entry["cve_id"],
                affected_component=entry["affected_component"],
                root_cause=RootCause(entry["root_cause"]),
                payload_summary=entry["payload_summary"],
                cosai_suggested_category=entry["cosai_suggested_category"],
                mitre_suggested_technique=entry["mitre_suggested_technique"],
                source_url=entry["source_url"],
                notes=entry.get("notes", ""),
            )
        )
    return records


def validate_catalog(records: Iterable[CVERecord]) -> list[str]:
    """Return a list of validation errors; empty list means valid."""
    errors: list[str] = []
    seen_ids: set[str] = set()
    for r in records:
        if not r.cve_id.startswith("CVE-"):
            errors.append(f"{r.cve_id}: cve_id must start with 'CVE-'")
        if r.cve_id in seen_ids:
            errors.append(f"{r.cve_id}: duplicate cve_id")
        seen_ids.add(r.cve_id)
        if r.cosai_suggested_category not in _COSAI_CATEGORIES:
            errors.append(
                f"{r.cve_id}: cosai_suggested_category "
                f"{r.cosai_suggested_category!r} not in T1..T12"
            )
        if not r.mitre_suggested_technique.startswith("T"):
            errors.append(
                f"{r.cve_id}: mitre_suggested_technique must start with 'T'"
            )
        if not r.source_url.startswith(("http://", "https://")):
            errors.append(f"{r.cve_id}: source_url must be http(s)")
        if not r.payload_summary.strip():
            errors.append(f"{r.cve_id}: payload_summary is empty")
    return errors


def report(records: Iterable[CVERecord]) -> None:
    records = list(records)
    print(f"CVE catalog: {len(records)} entries")
    print()
    print("Counts by root cause:")
    counts = Counter(r.root_cause.value for r in records)
    for cause in RootCause:
        print(f"  {cause.value:18s} {counts.get(cause.value, 0):>3d}")
    print()
    print("Counts by CoSAI category:")
    cosai = Counter(r.cosai_suggested_category for r in records)
    for cat in sorted(cosai, key=lambda x: int(x[1:])):
        print(f"  {cat:4s} {cosai[cat]:>3d}")
    ambiguous = [r for r in records if "AMBIGUOUS" in r.notes]
    if ambiguous:
        print()
        print(f"Ambiguous CoSAI mappings flagged for review: {len(ambiguous)}")
        for r in ambiguous:
            print(f"  {r.cve_id}  ({r.cosai_suggested_category})")


if __name__ == "__main__":
    records = load_catalog()
    errors = validate_catalog(records)
    if errors:
        print("VALIDATION ERRORS:")
        for e in errors:
            print(f"  - {e}")
        raise SystemExit(1)
    report(records)
