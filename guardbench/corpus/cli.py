"""Corpus curation CLI.

Subcommands:
    add                 Append a new entry to a corpus file.
    list                Print a one-line-per-entry summary.
    review              Walk draft entries; prompt to approve/reject.
    stats               Print the distribution report.
    export-for-harness  Emit Phase 2-compatible TestCase JSON (no provenance).

All subcommands take ``--corpus PATH`` pointing at a JSON array file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import IO, Sequence

from pydantic import ValidationError

from guardbench.corpus.schema import CorpusEntry
from guardbench.corpus.validate import distribution_report, load_corpus


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _read(path: Path) -> list[CorpusEntry]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    return load_corpus(path)


def _write(path: Path, entries: list[CorpusEntry]) -> None:
    payload = [e.model_dump(mode="json") for e in entries]
    path.write_text(json.dumps(payload, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_add(args: argparse.Namespace, *, stdout: IO[str]) -> int:
    path = Path(args.corpus)
    entries = _read(path)
    new_data = {
        "id": args.id,
        "cosai_category": args.cosai,
        "mitre_technique_id": args.mitre,
        "attack_vector": args.attack_vector,
        "attack_type": args.attack_type,
        "expected_verdict": args.expected_verdict,
        "source": args.source,
        "obfuscation_level": args.obfuscation,
        "cve_reference": args.cve,
        "created_by": args.created_by,
        "parent_id": args.parent_id,
        "review_status": args.review_status,
        "labeling_notes": args.notes,
    }
    try:
        entry = CorpusEntry.model_validate(new_data)
    except ValidationError as exc:
        print(f"invalid entry: {exc}", file=stdout)
        return 1
    if any(e.id == entry.id for e in entries):
        print(f"duplicate id: {entry.id}", file=stdout)
        return 1
    entries.append(entry)
    _write(path, entries)
    print(f"added {entry.id}", file=stdout)
    return 0


def cmd_list(args: argparse.Namespace, *, stdout: IO[str]) -> int:
    entries = _read(Path(args.corpus))
    for e in entries:
        tag = f"[{e.review_status}]".ljust(10)
        print(
            f"{tag} {e.id:<20} {e.cosai_category:<4} "
            f"{e.source:<18} by={e.created_by}",
            file=stdout,
        )
    return 0


def cmd_stats(args: argparse.Namespace, *, stdout: IO[str]) -> int:
    entries = _read(Path(args.corpus))
    print(distribution_report(entries), file=stdout)
    return 0


def cmd_export(args: argparse.Namespace, *, stdout: IO[str]) -> int:
    entries = _read(Path(args.corpus))
    if args.approved_only:
        entries = [e for e in entries if e.review_status == "approved"]
    out = [e.to_test_case().model_dump(mode="json") for e in entries]
    Path(args.output).write_text(json.dumps(out, indent=2) + "\n")
    print(
        f"exported {len(out)} entries -> {args.output}"
        + (" (approved only)" if args.approved_only else ""),
        file=stdout,
    )
    return 0


def cmd_review(
    args: argparse.Namespace,
    *,
    stdin: IO[str],
    stdout: IO[str],
) -> int:
    """Walk draft entries; each gets approve / reject / skip."""
    path = Path(args.corpus)
    entries = _read(path)
    drafts = [e for e in entries if e.review_status == "draft"]
    if not drafts:
        print("no draft entries", file=stdout)
        return 0
    print(f"{len(drafts)} draft entr{'y' if len(drafts) == 1 else 'ies'}", file=stdout)
    for e in drafts:
        print("", file=stdout)
        print(f"  id: {e.id}", file=stdout)
        print(f"  cosai: {e.cosai_category}   mitre: {e.mitre_technique_id}", file=stdout)
        print(f"  source: {e.source}   obfuscation: {e.obfuscation_level}", file=stdout)
        print(f"  expected_verdict: {e.expected_verdict}", file=stdout)
        print("  attack_vector:", file=stdout)
        for line in e.attack_vector.splitlines() or [""]:
            print(f"    {line}", file=stdout)
        if e.labeling_notes:
            print(f"  notes: {e.labeling_notes}", file=stdout)
        print("  [a]pprove / [r]eject / [s]kip / [q]uit ?", file=stdout, end=" ")
        stdout.flush()
        choice = (stdin.readline() or "").strip().lower()
        if choice == "q":
            break
        if choice == "s" or choice == "":
            continue
        if choice not in {"a", "r"}:
            print(f"  (unknown choice {choice!r}, skipping)", file=stdout)
            continue
        print("  note (blank = keep existing):", file=stdout, end=" ")
        stdout.flush()
        note = (stdin.readline() or "").rstrip("\n")
        if note:
            e.labeling_notes = note
        # "reviewed" means we looked at it and kept it as draft-ish; "approved"
        # means it's ready for the harness.
        e.review_status = "approved" if choice == "a" else "reviewed"
        print(f"  -> {e.review_status}", file=stdout)
    _write(path, entries)
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guardbench-corpus")
    p.add_argument("--corpus", required=True, help="path to corpus JSON file")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("add", help="append a new entry")
    a.add_argument("--id", required=True)
    a.add_argument("--cosai", required=True)
    a.add_argument("--mitre", required=True)
    a.add_argument("--attack-vector", required=True)
    a.add_argument("--attack-type", required=True)
    a.add_argument("--expected-verdict", choices=["block", "allow"], required=True)
    a.add_argument("--source", choices=["cve-derived", "taxonomy-derived", "synthetic"], required=True)
    a.add_argument("--obfuscation", choices=["none", "light", "heavy"], default="none")
    a.add_argument("--cve", default=None)
    a.add_argument("--created-by", choices=["human", "llm_variant", "claude_code"], required=True)
    a.add_argument("--parent-id", default=None)
    a.add_argument("--review-status", choices=["draft", "reviewed", "approved"], default="draft")
    a.add_argument("--notes", default=None)
    a.set_defaults(func=lambda ns: cmd_add(ns, stdout=sys.stdout))

    ls = sub.add_parser("list", help="one-line summary per entry")
    ls.set_defaults(func=lambda ns: cmd_list(ns, stdout=sys.stdout))

    st = sub.add_parser("stats", help="distribution report")
    st.set_defaults(func=lambda ns: cmd_stats(ns, stdout=sys.stdout))

    rv = sub.add_parser("review", help="walk drafts interactively")
    rv.set_defaults(
        func=lambda ns: cmd_review(ns, stdin=sys.stdin, stdout=sys.stdout)
    )

    ex = sub.add_parser("export-for-harness", help="strip provenance -> TestCase JSON")
    ex.add_argument("--output", required=True)
    ex.add_argument("--approved-only", action="store_true")
    ex.set_defaults(func=lambda ns: cmd_export(ns, stdout=sys.stdout))

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
