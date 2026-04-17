"""Adapter for Snyk Agent Scan."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from guardbench.adapters.base import ToolAdapter
from guardbench.schemas import Result, TestCase

_STUB_SERVER = str(Path(__file__).with_name("_mcp_stub_server.py"))
_TIMEOUT_SECONDS = 30

# Issue codes emitted by the Snyk analysis backend that indicate threats.
_THREAT_CATEGORIES: dict[str, str] = {
    "E001": "prompt_injection",
    "E002": "tool_poisoning",
    "E003": "tool_shadowing",
    "W001": "prompt_injection",
    "W002": "cross_server",
    "TF001": "toxic_flow",
    "TF002": "toxic_flow",
}


def _find_uvx() -> str:
    """Return the absolute path to ``uvx``, searching common install locations."""
    path = shutil.which("uvx")
    if path:
        return path
    # uv installed via curl may land here
    candidate = Path.home() / "snap" / "code" / "233" / ".local" / "bin" / "uvx"
    if candidate.exists():
        return str(candidate)
    candidate = Path.home() / ".local" / "bin" / "uvx"
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError(
        "uvx is not installed. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    )


class SnykAgentScanAdapter(ToolAdapter):
    def __init__(self) -> None:
        self._uvx: str = ""

    @property
    def name(self) -> str:
        return "snyk-agent-scan"

    def setup(self) -> None:
        self._uvx = _find_uvx()
        if not os.environ.get("SNYK_TOKEN"):
            raise EnvironmentError(
                "SNYK_TOKEN environment variable is not set. "
                "Get a token at https://app.snyk.io/account"
            )

    def evaluate(self, test_case: TestCase) -> Result:
        if not self._uvx:
            self.setup()

        tmpdir = tempfile.mkdtemp(prefix="guardbench-")
        try:
            return self._run(test_case, tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def _run(self, test_case: TestCase, tmpdir: str) -> Result:
        config_path = os.path.join(tmpdir, "mcp.json")
        config = {
            "mcpServers": {
                "guardbench-probe": {
                    "command": sys.executable,
                    "args": [
                        _STUB_SERVER,
                        f"probe_{test_case.id}",
                        test_case.attack_vector,
                    ],
                }
            }
        }
        with open(config_path, "w") as f:
            json.dump(config, f)

        cmd = [
            self._uvx, "snyk-agent-scan@latest",
            "scan", config_path,
            "--json",
            "--server-timeout", "15",
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
                raw_output={"stderr": proc.stderr[-2000:] if proc.stderr else "", "exit_code": proc.returncode},
                timestamp=datetime.now(timezone.utc),
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
            )

        return self._parse(test_case, raw, latency_ms)

    def _parse(self, test_case: TestCase, raw: dict, latency_ms: int) -> Result:
        threats: list[dict] = []

        # raw is {config_path: ScanPathResult_dict, ...}
        for scan_path in raw.values():
            for issue in scan_path.get("issues", []):
                code = issue.get("code", "")
                category = _THREAT_CATEGORIES.get(code)
                if category:
                    threats.append({
                        "code": code,
                        "category": category,
                        "message": issue.get("message", ""),
                        "severity": (issue.get("extra_data") or {}).get("severity"),
                    })

            # Also check labels for high-risk scalar scores
            for server_labels in scan_path.get("labels", []):
                for label in server_labels:
                    if isinstance(label, dict):
                        for key in ("is_public_sink", "destructive", "untrusted_content", "private_data"):
                            score = label.get(key, 0)
                            if isinstance(score, (int, float)) and score >= 2.0:
                                threats.append({
                                    "code": "LABEL",
                                    "category": key,
                                    "message": f"{key} score = {score}",
                                    "severity": "high",
                                })

        blocked = len(threats) > 0
        confidence = 1.0 if blocked else 0.0

        if threats:
            categories = sorted({t["category"] for t in threats})
            explanation = f"threats detected: {', '.join(categories)}"
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
