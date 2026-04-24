"""Adapter for the Cisco AI Defense MCP Scanner."""

import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone

from guardbench.adapters.base import ToolAdapter
from guardbench.schemas import Result, TestCase

_TIMEOUT_SECONDS = 30

# Severity values the scanner considers unsafe.
_UNSAFE_SEVERITIES = frozenset({"HIGH", "MEDIUM", "CRITICAL"})


def _find_mcp_scanner() -> str:
    """Return the absolute path to ``mcp-scanner``."""
    path = shutil.which("mcp-scanner")
    if path:
        return path
    raise FileNotFoundError(
        "mcp-scanner is not installed. "
        "Install it with: pipx install cisco-ai-mcp-scanner"
    )


class CiscoScannerAdapter(ToolAdapter):
    def __init__(self) -> None:
        self._bin: str = ""

    @property
    def name(self) -> str:
        return "cisco-mcp-scanner"

    def setup(self) -> None:
        self._bin = _find_mcp_scanner()

    def evaluate(self, test_case: TestCase) -> Result:
        if not self._bin:
            self.setup()

        tmpdir = tempfile.mkdtemp(prefix="guardbench-")
        try:
            return self._run(test_case, tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------

    def _run(self, test_case: TestCase, tmpdir: str) -> Result:
        # Use the test case ID in the filename to avoid collisions
        # when multiple evaluations share a /tmp mount.
        tools_path = os.path.join(tmpdir, f"tools-{test_case.id}.json")
        tools_doc = {
            "tools": [
                {
                    "name": f"probe_{test_case.id}",
                    "description": test_case.attack_vector,
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        }
        with open(tools_path, "w") as f:
            json.dump(tools_doc, f)

        cmd = [
            self._bin,
            "--analyzers", "yara",
            "--raw",
            "static",
            "--tools", tools_path,
        ]

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            latency_ms = int((time.monotonic() - t0) * 1000)
            return Result(
                test_case_id=test_case.id,
                tool_name=self.name,
                blocked=False,
                confidence=0.0,
                explanation=f"subprocess timed out after {_TIMEOUT_SECONDS}s",
                latency_ms=latency_ms,
                raw_output={"error": "timeout"},
                timestamp=datetime.now(timezone.utc),
                error="timeout",
            )
        latency_ms = int((time.monotonic() - t0) * 1000)

        stdout = proc.stdout.strip()
        if not stdout:
            return Result(
                test_case_id=test_case.id,
                tool_name=self.name,
                blocked=False,
                confidence=0.0,
                explanation=f"scanner produced no JSON output (exit code {proc.returncode})",
                latency_ms=latency_ms,
                raw_output={
                    "stderr": proc.stderr[-2000:] if proc.stderr else "",
                    "exit_code": proc.returncode,
                },
                timestamp=datetime.now(timezone.utc),
                error=f"no_output_exit_{proc.returncode}",
            )

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return Result(
                test_case_id=test_case.id,
                tool_name=self.name,
                blocked=False,
                confidence=0.0,
                explanation=f"malformed JSON from scanner: {exc}",
                latency_ms=latency_ms,
                raw_output={"stdout_head": stdout[:500]},
                timestamp=datetime.now(timezone.utc),
                error="malformed_json",
            )

        return self._parse(test_case, raw, latency_ms)

    # ------------------------------------------------------------------

    def _parse(self, test_case: TestCase, raw: list, latency_ms: int) -> Result:
        threats: list[dict] = []

        # raw is a list of per-tool result dicts
        for item in raw:
            is_safe = item.get("is_safe", True)
            findings = item.get("findings", {})

            for analyzer_name, details in findings.items():
                severity = details.get("severity", "SAFE")
                if is_safe is False or severity in _UNSAFE_SEVERITIES:
                    threat_names = details.get("threat_names", [])
                    taxonomies = details.get("mcp_taxonomies", [])
                    threats.append({
                        "analyzer": analyzer_name,
                        "severity": severity,
                        "threat_names": threat_names,
                        "threat_summary": details.get("threat_summary", ""),
                        "total_findings": details.get("total_findings", 0),
                        "mcp_taxonomies": taxonomies,
                    })

        blocked = len(threats) > 0
        confidence = 1.0 if blocked else 0.0

        if threats:
            categories = sorted({
                name
                for t in threats
                for name in t["threat_names"]
            })
            explanation = f"threats detected: {', '.join(categories)}" if categories else "threats detected"
        else:
            explanation = "no threats detected"

        return Result(
            test_case_id=test_case.id,
            tool_name=self.name,
            blocked=blocked,
            confidence=confidence,
            explanation=explanation,
            latency_ms=latency_ms,
            raw_output={"threats": threats, "scan_output": raw},
            timestamp=datetime.now(timezone.utc),
        )
