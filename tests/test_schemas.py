"""Tests for TestCase and Result schema validation."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from guardbench.schemas import Result, TestCase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def valid_test_case_data():
    return {
        "id": "TC-001",
        "cosai_category": "T3",
        "mitre_technique_id": "T1059.001",
        "attack_vector": "tool_call injection via prompt",
        "attack_type": "prompt_injection",
        "expected_verdict": "block",
        "source": "cve-derived",
        "obfuscation_level": "none",
        "cve_reference": "CVE-2024-12345",
    }


@pytest.fixture()
def valid_result_data():
    return {
        "test_case_id": "TC-001",
        "tool_name": "snyk-agent-scan",
        "blocked": True,
        "confidence": 0.95,
        "explanation": "Blocked due to prompt injection pattern",
        "latency_ms": 120,
        "raw_output": {"finding": "injection detected"},
        "timestamp": datetime(2026, 4, 16, 12, 0, 0, tzinfo=timezone.utc),
    }


# ---------------------------------------------------------------------------
# TestCase – valid
# ---------------------------------------------------------------------------

class TestTestCaseValid:
    def test_all_fields(self, valid_test_case_data):
        tc = TestCase(**valid_test_case_data)
        assert tc.id == "TC-001"
        assert tc.cosai_category == "T3"
        assert tc.cve_reference == "CVE-2024-12345"

    def test_cve_reference_optional(self, valid_test_case_data):
        valid_test_case_data.pop("cve_reference")
        tc = TestCase(**valid_test_case_data)
        assert tc.cve_reference is None

    def test_all_cosai_categories(self, valid_test_case_data):
        for i in range(1, 13):
            valid_test_case_data["cosai_category"] = f"T{i}"
            tc = TestCase(**valid_test_case_data)
            assert tc.cosai_category == f"T{i}"

    def test_all_verdicts(self, valid_test_case_data):
        for v in ("block", "allow"):
            valid_test_case_data["expected_verdict"] = v
            assert TestCase(**valid_test_case_data).expected_verdict == v

    def test_all_sources(self, valid_test_case_data):
        for s in ("cve-derived", "taxonomy-derived", "synthetic"):
            valid_test_case_data["source"] = s
            assert TestCase(**valid_test_case_data).source == s

    def test_all_obfuscation_levels(self, valid_test_case_data):
        for lvl in ("none", "light", "heavy"):
            valid_test_case_data["obfuscation_level"] = lvl
            assert TestCase(**valid_test_case_data).obfuscation_level == lvl


# ---------------------------------------------------------------------------
# TestCase – invalid
# ---------------------------------------------------------------------------

class TestTestCaseInvalid:
    def test_invalid_cosai_category(self, valid_test_case_data):
        valid_test_case_data["cosai_category"] = "T99"
        with pytest.raises(ValidationError) as exc_info:
            TestCase(**valid_test_case_data)
        assert "cosai_category" in str(exc_info.value)

    def test_invalid_expected_verdict(self, valid_test_case_data):
        valid_test_case_data["expected_verdict"] = "quarantine"
        with pytest.raises(ValidationError) as exc_info:
            TestCase(**valid_test_case_data)
        assert "expected_verdict" in str(exc_info.value)

    def test_invalid_source(self, valid_test_case_data):
        valid_test_case_data["source"] = "manual"
        with pytest.raises(ValidationError) as exc_info:
            TestCase(**valid_test_case_data)
        assert "source" in str(exc_info.value)

    def test_invalid_obfuscation_level(self, valid_test_case_data):
        valid_test_case_data["obfuscation_level"] = "extreme"
        with pytest.raises(ValidationError) as exc_info:
            TestCase(**valid_test_case_data)
        assert "obfuscation_level" in str(exc_info.value)

    def test_missing_required_id(self, valid_test_case_data):
        valid_test_case_data.pop("id")
        with pytest.raises(ValidationError) as exc_info:
            TestCase(**valid_test_case_data)
        assert "id" in str(exc_info.value)

    def test_missing_required_attack_vector(self, valid_test_case_data):
        valid_test_case_data.pop("attack_vector")
        with pytest.raises(ValidationError) as exc_info:
            TestCase(**valid_test_case_data)
        assert "attack_vector" in str(exc_info.value)

    def test_missing_multiple_required_fields(self, valid_test_case_data):
        valid_test_case_data.pop("cosai_category")
        valid_test_case_data.pop("mitre_technique_id")
        with pytest.raises(ValidationError) as exc_info:
            TestCase(**valid_test_case_data)
        errors = exc_info.value.errors()
        fields = {e["loc"][0] for e in errors}
        assert fields == {"cosai_category", "mitre_technique_id"}


# ---------------------------------------------------------------------------
# Result – valid
# ---------------------------------------------------------------------------

class TestResultValid:
    def test_all_fields(self, valid_result_data):
        r = Result(**valid_result_data)
        assert r.test_case_id == "TC-001"
        assert r.blocked is True
        assert r.confidence == 0.95
        assert r.latency_ms == 120

    def test_confidence_boundaries(self, valid_result_data):
        valid_result_data["confidence"] = 0.0
        assert Result(**valid_result_data).confidence == 0.0

        valid_result_data["confidence"] = 1.0
        assert Result(**valid_result_data).confidence == 1.0

    def test_empty_raw_output(self, valid_result_data):
        valid_result_data["raw_output"] = {}
        assert Result(**valid_result_data).raw_output == {}

    def test_timestamp_from_iso_string(self, valid_result_data):
        valid_result_data["timestamp"] = "2026-04-16T12:00:00Z"
        r = Result(**valid_result_data)
        assert r.timestamp.year == 2026


# ---------------------------------------------------------------------------
# Result – invalid
# ---------------------------------------------------------------------------

class TestResultInvalid:
    def test_confidence_above_one(self, valid_result_data):
        valid_result_data["confidence"] = 1.5
        with pytest.raises(ValidationError) as exc_info:
            Result(**valid_result_data)
        assert "confidence" in str(exc_info.value)

    def test_confidence_below_zero(self, valid_result_data):
        valid_result_data["confidence"] = -0.1
        with pytest.raises(ValidationError) as exc_info:
            Result(**valid_result_data)
        assert "confidence" in str(exc_info.value)

    def test_missing_required_tool_name(self, valid_result_data):
        valid_result_data.pop("tool_name")
        with pytest.raises(ValidationError) as exc_info:
            Result(**valid_result_data)
        assert "tool_name" in str(exc_info.value)

    def test_missing_required_blocked(self, valid_result_data):
        valid_result_data.pop("blocked")
        with pytest.raises(ValidationError) as exc_info:
            Result(**valid_result_data)
        assert "blocked" in str(exc_info.value)

    def test_missing_required_timestamp(self, valid_result_data):
        valid_result_data.pop("timestamp")
        with pytest.raises(ValidationError) as exc_info:
            Result(**valid_result_data)
        assert "timestamp" in str(exc_info.value)

    def test_invalid_timestamp_format(self, valid_result_data):
        valid_result_data["timestamp"] = "not-a-date"
        with pytest.raises(ValidationError) as exc_info:
            Result(**valid_result_data)
        assert "timestamp" in str(exc_info.value)

    def test_missing_multiple_required_fields(self, valid_result_data):
        valid_result_data.pop("test_case_id")
        valid_result_data.pop("explanation")
        valid_result_data.pop("raw_output")
        with pytest.raises(ValidationError) as exc_info:
            Result(**valid_result_data)
        errors = exc_info.value.errors()
        fields = {e["loc"][0] for e in errors}
        assert fields == {"test_case_id", "explanation", "raw_output"}
