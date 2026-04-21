"""Corpus schema: provenance-annotated wrapper around ``TestCase``.

``CorpusEntry`` extends the Phase 2 ``TestCase`` with authoring metadata
needed for curation (who wrote it, when, what it was derived from,
whether it has been reviewed). The harness itself still consumes plain
``TestCase`` objects — call :func:`CorpusEntry.to_test_case` or use
``guardbench.corpus.cli export-for-harness`` to strip provenance.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import Field

from guardbench.schemas import TestCase

CreatedBy = Literal["human", "llm_variant", "claude_code"]
ReviewStatus = Literal["draft", "reviewed", "approved"]


class CorpusEntry(TestCase):
    """A TestCase plus provenance / review metadata."""

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: CreatedBy
    parent_id: Optional[str] = None
    review_status: ReviewStatus = "draft"
    labeling_notes: Optional[str] = None

    def to_test_case(self) -> TestCase:
        """Return a provenance-stripped ``TestCase`` for the harness."""
        return TestCase(**{k: getattr(self, k) for k in TestCase.model_fields})
