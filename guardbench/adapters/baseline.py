"""Baseline adapter that applies no guardrails."""

from datetime import datetime, timezone

from guardbench.adapters.base import ToolAdapter
from guardbench.schemas import Result, TestCase


class BaselineAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "baseline"

    def evaluate(self, test_case: TestCase) -> Result:
        return Result(
            test_case_id=test_case.id,
            tool_name=self.name,
            blocked=False,
            confidence=0.0,
            explanation="no guardrails applied",
            latency_ms=0,
            raw_output={},
            timestamp=datetime.now(timezone.utc),
        )
