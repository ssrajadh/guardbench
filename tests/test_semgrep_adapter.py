"""Integration tests for SemgrepMCPAdapter.

These tests invoke the real semgrep CLI with ``--config auto``.
They are skipped when semgrep is not installed.
"""

import glob
import shutil

import pytest

from guardbench.adapters.semgrep_mcp import SemgrepMCPAdapter, _find_semgrep
from guardbench.schemas import Result, TestCase


def _scanner_available() -> bool:
    try:
        _find_semgrep()
        return True
    except FileNotFoundError:
        return False


_skip_reason = "semgrep not installed"
_requires_semgrep = pytest.mark.skipif(
    not _scanner_available(),
    reason=_skip_reason,
)

# ---------------------------------------------------------------------------
# Payloads – vulnerable (should trigger ERROR-severity findings)
# ---------------------------------------------------------------------------

_VULNERABLE_PAYLOADS = [
    {
        "id": "SG-VULN-001",
        "attack_vector": (
            "import subprocess\n"
            "def run(cmd):\n"
            "    subprocess.call(cmd, shell=True)\n"
        ),
        "attack_type": "command_injection",
    },
    {
        "id": "SG-VULN-002",
        "attack_vector": (
            "const { exec } = require('child_process');\n"
            "function run(cmd) { exec(cmd); }\n"
        ),
        "attack_type": "javascript",
    },
    {
        "id": "SG-VULN-003",
        "attack_vector": (
            "import subprocess\n"
            "def execute(user_input):\n"
            "    subprocess.Popen(user_input, shell=True)\n"
        ),
        "attack_type": "command_injection",
    },
]

# ---------------------------------------------------------------------------
# Payloads – benign (should produce zero or only low-severity findings)
# ---------------------------------------------------------------------------

_BENIGN_PAYLOADS = [
    {
        "id": "SG-BEN-001",
        "attack_vector": (
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
        ),
        "attack_type": "none",
    },
    {
        "id": "SG-BEN-002",
        "attack_vector": (
            "def greet(name: str) -> str:\n"
            "    return f'Hello, {name}!'\n"
        ),
        "attack_type": "none",
    },
]


def _make_test_case(payload: dict) -> TestCase:
    return TestCase(
        id=payload["id"],
        cosai_category="T3",
        mitre_technique_id="T1059.001",
        attack_vector=payload["attack_vector"],
        attack_type=payload["attack_type"],
        expected_verdict="block" if payload["id"].startswith("SG-VULN") else "allow",
        source="synthetic",
        obfuscation_level="none",
    )


# ---------------------------------------------------------------------------
# Setup checks
# ---------------------------------------------------------------------------

class TestSetup:
    def test_setup_succeeds_when_installed(self):
        if not _scanner_available():
            pytest.skip("semgrep not installed")
        adapter = SemgrepMCPAdapter()
        adapter.setup()  # should not raise

    def test_setup_raises_when_missing(self, monkeypatch):
        monkeypatch.setenv("PATH", "")
        adapter = SemgrepMCPAdapter()
        with pytest.raises(FileNotFoundError, match="semgrep"):
            adapter.setup()


# ---------------------------------------------------------------------------
# Integration – vulnerable payloads
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestVulnerablePayloads:
    @_requires_semgrep
    @pytest.mark.parametrize(
        "payload", _VULNERABLE_PAYLOADS, ids=[p["id"] for p in _VULNERABLE_PAYLOADS],
    )
    def test_vulnerable_is_blocked(self, payload):
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        tc = _make_test_case(payload)
        result = adapter.evaluate(tc)

        assert isinstance(result, Result)
        assert result.test_case_id == payload["id"]
        assert result.tool_name == "semgrep"
        assert result.blocked is True, (
            f"Expected blocked=True for {payload['id']}, "
            f"got explanation: {result.explanation}"
        )
        assert result.latency_ms > 0


# ---------------------------------------------------------------------------
# Integration – benign payloads
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestBenignPayloads:
    @_requires_semgrep
    @pytest.mark.parametrize(
        "payload", _BENIGN_PAYLOADS, ids=[p["id"] for p in _BENIGN_PAYLOADS],
    )
    def test_benign_is_allowed(self, payload):
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        tc = _make_test_case(payload)
        result = adapter.evaluate(tc)

        assert isinstance(result, Result)
        assert result.test_case_id == payload["id"]
        assert result.blocked is False, (
            f"Expected blocked=False for {payload['id']}, "
            f"got explanation: {result.explanation}"
        )
        assert result.latency_ms >= 0


# ---------------------------------------------------------------------------
# Temp directory cleanup
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestCleanup:
    @_requires_semgrep
    def test_no_leftover_temp_dirs(self):
        before = set(glob.glob("/tmp/guardbench-*"))
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        tc = _make_test_case(_BENIGN_PAYLOADS[0])
        adapter.evaluate(tc)
        after = set(glob.glob("/tmp/guardbench-*"))
        leftover = after - before
        assert len(leftover) == 0, f"Leftover temp dirs: {leftover}"


# ---------------------------------------------------------------------------
# Result fields
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestResultFields:
    @_requires_semgrep
    def test_latency_populated(self):
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        tc = _make_test_case(_VULNERABLE_PAYLOADS[0])
        result = adapter.evaluate(tc)
        assert result.latency_ms > 0

    @_requires_semgrep
    def test_rule_ids_in_raw_output(self):
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        tc = _make_test_case(_VULNERABLE_PAYLOADS[0])
        result = adapter.evaluate(tc)
        findings = result.raw_output.get("findings", [])
        assert len(findings) > 0
        assert all("rule_id" in f for f in findings)
        assert all("severity" in f for f in findings)

    @_requires_semgrep
    def test_semgrep_version_in_raw_output(self):
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        tc = _make_test_case(_BENIGN_PAYLOADS[0])
        result = adapter.evaluate(tc)
        assert "semgrep_version" in result.raw_output

    @_requires_semgrep
    def test_timestamp_is_set(self):
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        tc = _make_test_case(_BENIGN_PAYLOADS[0])
        result = adapter.evaluate(tc)
        assert result.timestamp is not None


# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestSeverityThresholds:
    @_requires_semgrep
    def test_warning_does_not_block(self):
        """eval() triggers a WARNING-severity finding, which should NOT block."""
        tc = TestCase(
            id="SG-WARN-001",
            cosai_category="T3",
            mitre_technique_id="T1059.001",
            attack_vector="x = eval(input())\n",
            attack_type="code_execution",
            expected_verdict="allow",
            source="synthetic",
            obfuscation_level="none",
        )
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        result = adapter.evaluate(tc)
        # eval triggers WARNING, not ERROR — should not block
        assert result.blocked is False, (
            f"WARNING-only findings should not block, "
            f"got explanation: {result.explanation}"
        )

    @_requires_semgrep
    def test_error_does_block(self):
        """subprocess.call(shell=True) triggers an ERROR finding → block."""
        tc = TestCase(
            id="SG-ERR-001",
            cosai_category="T3",
            mitre_technique_id="T1059.001",
            attack_vector=(
                "import subprocess\n"
                "def run(cmd):\n"
                "    subprocess.call(cmd, shell=True)\n"
            ),
            attack_type="command_injection",
            expected_verdict="block",
            source="synthetic",
            obfuscation_level="none",
        )
        adapter = SemgrepMCPAdapter()
        adapter.setup()
        result = adapter.evaluate(tc)
        assert result.blocked is True


# ---------------------------------------------------------------------------
# Error handling (unit tests – no semgrep binary required)
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Unit tests that mock subprocess — no semgrep binary needed."""

    @staticmethod
    def _make_adapter() -> SemgrepMCPAdapter:
        adapter = SemgrepMCPAdapter()
        adapter._bin = "/usr/bin/false"
        return adapter

    def test_malformed_json_handled(self, monkeypatch):
        adapter = self._make_adapter()
        import subprocess as sp

        def mock_run(*args, **kwargs):
            class FakeResult:
                stdout = "NOT VALID JSON {{{["
                stderr = ""
                returncode = 0
            return FakeResult()

        monkeypatch.setattr(sp, "run", mock_run)

        tc = _make_test_case(_BENIGN_PAYLOADS[0])
        result = adapter.evaluate(tc)
        assert result.blocked is False
        assert "malformed JSON" in result.explanation

    def test_timeout_handled(self, monkeypatch):
        adapter = self._make_adapter()
        import subprocess as sp

        def mock_run(*args, **kwargs):
            raise sp.TimeoutExpired(cmd="semgrep", timeout=60)

        monkeypatch.setattr(sp, "run", mock_run)

        tc = _make_test_case(_BENIGN_PAYLOADS[0])
        result = adapter.evaluate(tc)
        assert result.blocked is False
        assert "timed out" in result.explanation
        assert result.raw_output == {"error": "timeout"}

    def test_empty_output_handled(self, monkeypatch):
        adapter = self._make_adapter()
        import subprocess as sp

        def mock_run(*args, **kwargs):
            class FakeResult:
                stdout = ""
                stderr = "some error"
                returncode = 1
            return FakeResult()

        monkeypatch.setattr(sp, "run", mock_run)

        tc = _make_test_case(_BENIGN_PAYLOADS[0])
        result = adapter.evaluate(tc)
        assert result.blocked is False
        assert "no JSON output" in result.explanation
