"""Tests for the BaselineAdapter."""

import pytest

from guardbench.adapters.baseline import BaselineAdapter
from guardbench.schemas import Result, TestCase

COSAI_CATEGORIES = [f"T{i}" for i in range(1, 13)]


@pytest.fixture()
def adapter():
    return BaselineAdapter()


def _make_test_case(category: str) -> TestCase:
    return TestCase(
        id=f"TC-{category}",
        cosai_category=category,
        mitre_technique_id="T1059.001",
        attack_vector="tool_call injection",
        attack_type="prompt_injection",
        expected_verdict="block",
        source="synthetic",
        obfuscation_level="none",
    )


class TestBaselineAdapter:
    def test_name(self, adapter):
        assert adapter.name == "baseline"

    @pytest.mark.parametrize("category", COSAI_CATEGORIES)
    def test_blocked_is_false(self, adapter, category):
        result = adapter.evaluate(_make_test_case(category))
        assert result.blocked is False

    @pytest.mark.parametrize("category", COSAI_CATEGORIES)
    def test_confidence_is_zero(self, adapter, category):
        result = adapter.evaluate(_make_test_case(category))
        assert result.confidence == 0.0

    @pytest.mark.parametrize("category", COSAI_CATEGORIES)
    def test_explanation(self, adapter, category):
        result = adapter.evaluate(_make_test_case(category))
        assert result.explanation == "no guardrails applied"

    @pytest.mark.parametrize("category", COSAI_CATEGORIES)
    def test_latency_is_zero(self, adapter, category):
        result = adapter.evaluate(_make_test_case(category))
        assert result.latency_ms == 0

    @pytest.mark.parametrize("category", COSAI_CATEGORIES)
    def test_returns_valid_result(self, adapter, category):
        result = adapter.evaluate(_make_test_case(category))
        assert isinstance(result, Result)

    @pytest.mark.parametrize("category", COSAI_CATEGORIES)
    def test_test_case_id_matches(self, adapter, category):
        result = adapter.evaluate(_make_test_case(category))
        assert result.test_case_id == f"TC-{category}"

    @pytest.mark.parametrize("category", COSAI_CATEGORIES)
    def test_tool_name_matches(self, adapter, category):
        result = adapter.evaluate(_make_test_case(category))
        assert result.tool_name == "baseline"

    def test_raw_output_is_empty_dict(self, adapter):
        result = adapter.evaluate(_make_test_case("T1"))
        assert result.raw_output == {}

    def test_timestamp_is_set(self, adapter):
        result = adapter.evaluate(_make_test_case("T1"))
        assert result.timestamp is not None

    def test_evaluate_with_retries(self, adapter):
        results = adapter.evaluate_with_retries(_make_test_case("T5"), n_runs=3)
        assert len(results) == 3
        assert all(r.blocked is False for r in results)
