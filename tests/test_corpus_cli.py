"""Tests for the corpus CLI, schema, and validator."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from guardbench.corpus import cli
from guardbench.corpus.schema import CorpusEntry
from guardbench.corpus.validate import (
    distribution_report,
    load_corpus,
    validate_entries,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _base_args(corpus: Path) -> list[str]:
    return ["--corpus", str(corpus)]


def _add_args(
    corpus: Path,
    *,
    id: str = "E1",
    cosai: str = "T3",
    mitre: str = "T1059",
    created_by: str = "human",
    review_status: str = "draft",
    parent_id: str | None = None,
    notes: str | None = None,
) -> list[str]:
    args = _base_args(corpus) + [
        "add",
        "--id", id,
        "--cosai", cosai,
        "--mitre", mitre,
        "--attack-vector", "import subprocess; subprocess.call('x', shell=True)",
        "--attack-type", "command_injection",
        "--expected-verdict", "block",
        "--source", "cve-derived",
        "--obfuscation", "none",
        "--created-by", created_by,
        "--review-status", review_status,
    ]
    if parent_id:
        args += ["--parent-id", parent_id]
    if notes:
        args += ["--notes", notes]
    return args


@pytest.fixture()
def corpus_path(tmp_path: Path) -> Path:
    return tmp_path / "corpus.json"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

class TestSchema:
    def test_corpus_entry_defaults(self):
        e = CorpusEntry(
            id="E1",
            cosai_category="T3",
            mitre_technique_id="T1059",
            attack_vector="x",
            attack_type="cmd",
            expected_verdict="block",
            source="synthetic",
            obfuscation_level="none",
            created_by="human",
        )
        assert e.review_status == "draft"
        assert e.parent_id is None
        assert e.created_at is not None

    def test_to_test_case_strips_provenance(self):
        e = CorpusEntry(
            id="E1",
            cosai_category="T3",
            mitre_technique_id="T1059",
            attack_vector="x",
            attack_type="cmd",
            expected_verdict="block",
            source="synthetic",
            obfuscation_level="none",
            created_by="llm_variant",
            parent_id="E0",
            labeling_notes="derived",
        )
        tc = e.to_test_case()
        dumped = tc.model_dump()
        assert "created_by" not in dumped
        assert "parent_id" not in dumped
        assert "review_status" not in dumped
        assert dumped["id"] == "E1"


# ---------------------------------------------------------------------------
# CLI: add / list / stats
# ---------------------------------------------------------------------------

class TestAdd:
    def test_add_creates_file(self, corpus_path, capsys):
        assert cli.main(_add_args(corpus_path)) == 0
        assert corpus_path.exists()
        entries = load_corpus(corpus_path)
        assert len(entries) == 1
        assert entries[0].id == "E1"
        assert "added E1" in capsys.readouterr().out

    def test_add_rejects_duplicate(self, corpus_path, capsys):
        assert cli.main(_add_args(corpus_path)) == 0
        rc = cli.main(_add_args(corpus_path))
        assert rc == 1
        assert "duplicate" in capsys.readouterr().out

    def test_add_rejects_invalid_cosai(self, corpus_path, capsys):
        rc = cli.main(_add_args(corpus_path, cosai="T99"))
        assert rc == 1
        assert "invalid entry" in capsys.readouterr().out


class TestList:
    def test_list_empty(self, corpus_path, capsys):
        assert cli.main(_base_args(corpus_path) + ["list"]) == 0
        assert capsys.readouterr().out == ""

    def test_list_shows_entries(self, corpus_path, capsys):
        cli.main(_add_args(corpus_path, id="E1"))
        cli.main(_add_args(corpus_path, id="E2", review_status="approved"))
        capsys.readouterr()  # drop add output
        cli.main(_base_args(corpus_path) + ["list"])
        out = capsys.readouterr().out
        assert "E1" in out and "E2" in out
        assert "[draft]" in out
        assert "[approved]" in out


class TestStats:
    def test_stats_reports_gaps(self, corpus_path, capsys):
        cli.main(_add_args(corpus_path, id="E1", cosai="T3"))
        capsys.readouterr()
        cli.main(_base_args(corpus_path) + ["stats"])
        out = capsys.readouterr().out
        assert "Corpus: 1 entries" in out
        assert "Coverage gaps:" in out
        assert "T3" in out

    def test_stats_empty_corpus(self, corpus_path, capsys):
        corpus_path.write_text("[]")
        cli.main(_base_args(corpus_path) + ["stats"])
        out = capsys.readouterr().out
        assert "Corpus: 0 entries" in out


# ---------------------------------------------------------------------------
# CLI: review (non-interactive via stdin stub)
# ---------------------------------------------------------------------------

class TestReview:
    def _run_review(self, corpus_path: Path, input_text: str) -> str:
        stdin = io.StringIO(input_text)
        stdout = io.StringIO()
        import argparse
        ns = argparse.Namespace(corpus=str(corpus_path))
        cli.cmd_review(ns, stdin=stdin, stdout=stdout)
        return stdout.getvalue()

    def test_no_drafts(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1", review_status="approved"))
        out = self._run_review(corpus_path, "")
        assert "no draft entries" in out

    def test_approve_then_reject(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1"))
        cli.main(_add_args(corpus_path, id="E2"))
        # E1: approve with note; E2: reject with blank note
        self._run_review(corpus_path, "a\nlooks good\nr\n\n")
        entries = {e.id: e for e in load_corpus(corpus_path)}
        assert entries["E1"].review_status == "approved"
        assert entries["E1"].labeling_notes == "looks good"
        assert entries["E2"].review_status == "reviewed"

    def test_quit_halts_review(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1"))
        cli.main(_add_args(corpus_path, id="E2"))
        self._run_review(corpus_path, "q\n")
        entries = {e.id: e for e in load_corpus(corpus_path)}
        assert entries["E1"].review_status == "draft"
        assert entries["E2"].review_status == "draft"

    def test_skip_leaves_draft(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1"))
        self._run_review(corpus_path, "s\n")
        entries = load_corpus(corpus_path)
        assert entries[0].review_status == "draft"


# ---------------------------------------------------------------------------
# CLI: export-for-harness
# ---------------------------------------------------------------------------

class TestExport:
    def test_export_strips_provenance(self, corpus_path, tmp_path, capsys):
        cli.main(_add_args(corpus_path, id="E1"))
        out_path = tmp_path / "harness.json"
        capsys.readouterr()
        cli.main(_base_args(corpus_path) + ["export-for-harness", "--output", str(out_path)])
        assert out_path.exists()
        payload = json.loads(out_path.read_text())
        assert len(payload) == 1
        assert "created_by" not in payload[0]
        assert "review_status" not in payload[0]
        assert payload[0]["id"] == "E1"
        # success message goes to stderr so piping --output=- keeps stdout clean
        assert "exported 1 entries" in capsys.readouterr().err

    def test_export_approved_only(self, corpus_path, tmp_path, capsys):
        cli.main(_add_args(corpus_path, id="E1", review_status="draft"))
        cli.main(_add_args(corpus_path, id="E2", review_status="approved"))
        out_path = tmp_path / "harness.json"
        capsys.readouterr()
        cli.main(
            _base_args(corpus_path)
            + ["export-for-harness", "--output", str(out_path), "--approved-only"]
        )
        payload = json.loads(out_path.read_text())
        assert [p["id"] for p in payload] == ["E2"]


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class TestValidate:
    def test_duplicate_ids_flagged(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1"))
        raw = json.loads(corpus_path.read_text())
        raw.append(raw[0])
        corpus_path.write_text(json.dumps(raw))
        entries = load_corpus(corpus_path)
        errors = validate_entries(entries)
        assert any("duplicate" in err for err in errors)

    def test_missing_parent_flagged(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1", parent_id="GHOST"))
        entries = load_corpus(corpus_path)
        errors = validate_entries(entries)
        assert any("parent_id" in err and "GHOST" in err for err in errors)

    def test_distribution_mentions_gaps(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1", cosai="T3"))
        entries = load_corpus(corpus_path)
        rep = distribution_report(entries)
        assert "Coverage gaps:" in rep
        assert "T7" in rep  # no T7 entries -> listed as a gap

    def test_valid_corpus_reports_no_errors(self, corpus_path):
        cli.main(_add_args(corpus_path, id="E1"))
        entries = load_corpus(corpus_path)
        assert validate_entries(entries) == []
