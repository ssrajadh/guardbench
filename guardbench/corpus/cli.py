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
    from collections import Counter
    from guardbench.corpus.validate import _STRICT_TARGETS
    entries = _read(Path(args.corpus))
    targets = _STRICT_TARGETS if getattr(args, "verbose", False) else None
    print(distribution_report(entries, targets), file=stdout)
    if getattr(args, "verbose", False):
        print("", file=stdout)
        print("Attack type:", file=stdout)
        for at, n in Counter(e.attack_type for e in entries).most_common():
            print(f"  {at:<34} {n:>4}", file=stdout)
        print("", file=stdout)
        print("Expected verdict:", file=stdout)
        for v, n in Counter(e.expected_verdict for e in entries).most_common():
            print(f"  {v:<10} {n:>4}", file=stdout)
        print("", file=stdout)
        print("Created by:", file=stdout)
        for cb, n in Counter(e.created_by for e in entries).most_common():
            print(f"  {cb:<14} {n:>4}", file=stdout)
    return 0


def cmd_export(args: argparse.Namespace, *, stdout: IO[str]) -> int:
    entries = _read(Path(args.corpus))
    if args.approved_only:
        entries = [e for e in entries if e.review_status == "approved"]
    out = [e.to_test_case().model_dump(mode="json") for e in entries]
    payload = json.dumps(out, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(payload)
        print(
            f"exported {len(out)} entries -> {args.output}"
            + (" (approved only)" if args.approved_only else ""),
            file=sys.stderr,
        )
    else:
        stdout.write(payload)
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
    total = len(drafts)
    print(f"{total} draft entr{'y' if total == 1 else 'ies'} to review", file=stdout)
    tally = {"approved": 0, "reviewed": 0, "skipped": 0}
    sep = "─" * 60
    quit_early = False
    for i, e in enumerate(drafts, 1):
        print(f"\n{sep}\n[{i}/{total}] {e.id}", file=stdout)
        print(f"  cosai={e.cosai_category}  mitre={e.mitre_technique_id}  "
              f"verdict={e.expected_verdict}", file=stdout)
        print(f"  source={e.source}  obfuscation={e.obfuscation_level}", file=stdout)
        if e.cve_reference:
            print(f"  cve: {e.cve_reference}", file=stdout)
        if e.parent_id:
            print(f"  parent: {e.parent_id}  (variant)", file=stdout)
        print("  attack_vector:", file=stdout)
        for line in (e.attack_vector.splitlines() or [""]):
            print(f"    │ {line}", file=stdout)
        if e.labeling_notes:
            print(f"  notes: {e.labeling_notes}", file=stdout)
        print("  [a]pprove  [r]eject  [s]kip  [q]uit", file=stdout)
        print("  > ", file=stdout, end="")
        stdout.flush()
        choice = (stdin.readline() or "").strip().lower()
        if choice == "q":
            print("  quit — remaining drafts left untouched", file=stdout)
            quit_early = True
            break
        if choice in ("", "s"):
            tally["skipped"] += 1
            print("  → skipped", file=stdout)
            continue
        if choice not in {"a", "r"}:
            tally["skipped"] += 1
            print(f"  (unknown choice {choice!r}) → skipped", file=stdout)
            continue
        print("  note (blank = keep existing):", file=stdout)
        print("  > ", file=stdout, end="")
        stdout.flush()
        note = (stdin.readline() or "").rstrip("\n")
        if note:
            e.labeling_notes = note
        # "reviewed" = seen but not endorsed; "approved" = ready for harness.
        e.review_status = "approved" if choice == "a" else "reviewed"
        tally[e.review_status] += 1
        print(f"  → {e.review_status}", file=stdout)
    _write(path, entries)
    remaining = total - sum(tally.values()) if quit_early else 0
    print(f"\n{sep}", file=stdout)
    print(
        f"done: {tally['approved']} approved, {tally['reviewed']} rejected, "
        f"{tally['skipped']} skipped"
        + (f", {remaining} left" if remaining else ""),
        file=stdout,
    )
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guardbench-corpus")
    p.add_argument("--corpus", default=None, help="path to corpus JSON file")
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
    st.add_argument("path", nargs="?", default=None, help="corpus JSON (overrides --corpus)")
    st.add_argument("--verbose", "-v", action="store_true",
                    help="include attack-type, verdict, created-by breakdowns and strict targets")
    st.set_defaults(func=lambda ns: cmd_stats(ns, stdout=sys.stdout))

    rv = sub.add_parser("review", help="walk drafts interactively")
    rv.set_defaults(
        func=lambda ns: cmd_review(ns, stdin=sys.stdin, stdout=sys.stdout)
    )

    ex = sub.add_parser("export-for-harness", help="strip provenance -> TestCase JSON")
    ex.add_argument("path", nargs="?", default=None, help="corpus JSON (overrides --corpus)")
    ex.add_argument("--output", default=None,
                    help="write to file (default: stdout)")
    ex.add_argument("--approved-only", action="store_true")
    ex.set_defaults(func=lambda ns: cmd_export(ns, stdout=sys.stdout))

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # positional 'path' on a subcommand overrides --corpus
    pos = getattr(args, "path", None)
    if pos:
        args.corpus = pos
    if not args.corpus:
        print("error: provide corpus path via --corpus or as positional arg",
              file=sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
