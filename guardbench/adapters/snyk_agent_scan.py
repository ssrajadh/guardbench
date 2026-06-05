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

from guardbench.adapters.base import ToolAdapter, parse_attack_vector
from guardbench.schemas import Result, TestCase

_STUB_SERVER = str(Path(__file__).with_name("_mcp_stub_server.py"))
_TIMEOUT_SECONDS = 30

# Issue codes emitted by Snyk's analysis backend. The named codes get
# friendly category labels; any other code with prefix E/W/TF still counts
# as a threat (handled below) but is reported under a generic label, so
# new codes Snyk adds in future releases don't go silently uncounted.
_THREAT_CATEGORIES: dict[str, str] = {
    "E001": "prompt_injection",
    "E002": "tool_poisoning",
    "E003": "tool_shadowing",
    "W001": "prompt_injection",
    "W002": "cross_server",
    "W015": "untrusted_content_injection",
    "W016": "untrusted_content_retrieval",
    "W017": "sensitive_data_exposure",
    "W018": "workspace_data_exposure",
    "W020": "destructive_capability",
    "TF001": "toxic_flow",
    "TF002": "toxic_flow",
}


def _categorize(code: str) -> str | None:
    """Map a Snyk issue code to a threat category, or None if not a security finding.

    Recognizes named codes via _THREAT_CATEGORIES; falls back to a generic
    label for any unrecognized E/W/TF-prefixed code so newly-introduced
    issue types don't silently slip through.
    """
    if code in _THREAT_CATEGORIES:
        return _THREAT_CATEGORIES[code]
    if code and code[0] in {"E", "W"} or code.startswith("TF"):
        return f"unmapped_{code}"
    return None


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
        av = parse_attack_vector(test_case.attack_vector, test_case.id)
        av_path = os.path.join(tmpdir, f"av-{test_case.id}.json")
        with open(av_path, "w") as f:
            json.dump(av, f)

        config_path = os.path.join(tmpdir, "mcp.json")
        config = {
            "mcpServers": {
                "guardbench-probe": {
                    "command": sys.executable,
                    "args": [_STUB_SERVER, av_path],
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
            # Without this flag snyk-agent-scan skips stdio servers ("user
            # consent" gate) and silently returns issues=[]. For our
            # benchmark the stub server is trusted (we wrote it).
            "--dangerously-run-mcp-servers",
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
                raw_output={"stderr": proc.stderr[-2000:] if proc.stderr else "", "exit_code": proc.returncode},
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

    def _parse(self, test_case: TestCase, raw: dict, latency_ms: int) -> Result:
        threats: list[dict] = []

        # Detect "scan happened but every server was skipped" — almost always
        # a misconfig (e.g. missing --dangerously-run-mcp-servers). Without
        # this, an unstarted server returns issues=[] which the threat-counter
        # below treats as "no threats detected" — a silent false-allow.
        all_servers = []
        for scan_path in raw.values():
            all_servers.extend(scan_path.get("servers", []))
        failed_servers = [s for s in all_servers if (s.get("error") or {}).get("is_failure")]
        if all_servers and len(failed_servers) == len(all_servers):
            categories = sorted({(s.get("error") or {}).get("category", "?") for s in failed_servers})
            return Result(
                test_case_id=test_case.id,
                tool_name=self.name,
                blocked=False,
                confidence=0.0,
                explanation=f"all servers failed to start: {categories}",
                latency_ms=latency_ms,
                raw_output={"failed_servers": failed_servers, "scan_output": raw},
                timestamp=datetime.now(timezone.utc),
                error=f"all_servers_failed:{','.join(categories)}",
            )

        # raw is {config_path: ScanPathResult_dict, ...}
        for scan_path in raw.values():
            for issue in scan_path.get("issues", []):
                code = issue.get("code", "")
                category = _categorize(code)
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
