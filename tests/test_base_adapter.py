"""Tests for the ToolAdapter abstract base class."""

from datetime import datetime, timezone

import pytest

from guardbench.adapters.base import ToolAdapter
from guardbench.schemas import Result, TestCase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def test_case():
    return TestCase(
        id="TC-001",
        cosai_category="T3",
        mitre_technique_id="T1059.001",
        attack_vector="tool_call injection via prompt",
        attack_type="prompt_injection",
        expected_verdict="block",
        source="cve-derived",
        obfuscation_level="none",
    )


# ---------------------------------------------------------------------------
# MockAdapter
# ---------------------------------------------------------------------------

class MockAdapter(ToolAdapter):
    """Concrete adapter that records calls for testing."""

    def __init__(self):
        self._call_count = 0
        self._setup_called = False

    @property
    def name(self) -> str:
        return "mock-tool"

    def setup(self) -> None:
        self._setup_called = True

    def evaluate(self, test_case: TestCase) -> Result:
        self._call_count += 1
        return Result(
            test_case_id=test_case.id,
            tool_name=self.name,
            blocked=True,
            confidence=0.85,
            explanation=f"call #{self._call_count}",
            latency_ms=50,
            raw_output={"run": self._call_count},
            timestamp=datetime.now(timezone.utc),
        )


# ---------------------------------------------------------------------------
# Tests – abstract interface
# ---------------------------------------------------------------------------

class TestAbstractInterface:
    def test_cannot_instantiate_abstract_class(self):
        with pytest.raises(TypeError):
            ToolAdapter()

    def test_must_implement_name(self, test_case):
        class NoName(ToolAdapter):
            def evaluate(self, test_case):
                ...

        with pytest.raises(TypeError):
            NoName()

    def test_must_implement_evaluate(self):
        class NoEvaluate(ToolAdapter):
            @property
            def name(self) -> str:
                return "no-eval"

        with pytest.raises(TypeError):
            NoEvaluate()


# ---------------------------------------------------------------------------
# Tests – MockAdapter basics
# ---------------------------------------------------------------------------

class TestMockAdapter:
    def test_name(self):
        adapter = MockAdapter()
        assert adapter.name == "mock-tool"

    def test_setup(self):
        adapter = MockAdapter()
        assert adapter._setup_called is False
        adapter.setup()
        assert adapter._setup_called is True

    def test_evaluate_returns_result(self, test_case):
        adapter = MockAdapter()
        result = adapter.evaluate(test_case)
        assert isinstance(result, Result)
        assert result.test_case_id == "TC-001"
        assert result.tool_name == "mock-tool"
        assert result.blocked is True


# ---------------------------------------------------------------------------
# Tests – evaluate_with_retries
# ---------------------------------------------------------------------------

class TestEvaluateWithRetries:
    def test_default_single_run(self, test_case):
        adapter = MockAdapter()
        results = adapter.evaluate_with_retries(test_case)
        assert len(results) == 1
        assert adapter._call_count == 1

    def test_multiple_runs(self, test_case):
        adapter = MockAdapter()
        results = adapter.evaluate_with_retries(test_case, n_runs=5)
        assert len(results) == 5
        assert adapter._call_count == 5

    def test_each_run_is_independent(self, test_case):
        adapter = MockAdapter()
        results = adapter.evaluate_with_retries(test_case, n_runs=3)
        explanations = [r.explanation for r in results]
        assert explanations == ["call #1", "call #2", "call #3"]

    def test_each_result_has_distinct_raw_output(self, test_case):
        adapter = MockAdapter()
        results = adapter.evaluate_with_retries(test_case, n_runs=3)
        run_numbers = [r.raw_output["run"] for r in results]
        assert run_numbers == [1, 2, 3]

    def test_zero_runs_returns_empty(self, test_case):
        adapter = MockAdapter()
        results = adapter.evaluate_with_retries(test_case, n_runs=0)
        assert results == []
        assert adapter._call_count == 0

    def test_all_results_reference_correct_test_case(self, test_case):
        adapter = MockAdapter()
        results = adapter.evaluate_with_retries(test_case, n_runs=4)
        assert all(r.test_case_id == test_case.id for r in results)

    def test_propagates_evaluate_exception(self, test_case):
        class FailingAdapter(ToolAdapter):
            @property
            def name(self) -> str:
                return "fail-tool"

            def evaluate(self, test_case: TestCase) -> Result:
                raise RuntimeError("connection refused")

        adapter = FailingAdapter()
        with pytest.raises(RuntimeError, match="connection refused"):
            adapter.evaluate_with_retries(test_case, n_runs=3)
