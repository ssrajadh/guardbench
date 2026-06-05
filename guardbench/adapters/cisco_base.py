"""Shared base for the Cisco mcp-scanner adapter modes.

Three concrete subclasses live alongside this module:

  * :class:`CiscoStaticAdapter` — ``--analyzers yara`` (offline, free)
  * :class:`CiscoLLMAdapter`    — ``--analyzers llm`` (LiteLLM-backed)
  * :class:`CiscoHybridAdapter` — ``--analyzers yara,llm`` (combined)

The LLM-backed modes read provider config from environment variables that
mcp-scanner consumes directly (see :func:`_llm_env_hint` for the list).
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from typing import Optional

from guardbench.adapters.base import ToolAdapter, parse_attack_vector
from guardbench.schemas import Result, TestCase

import os

# Per-scan subprocess timeout. Default 60s; override via MCP_SCANNER_TIMEOUT for
# slow large-model judges (e.g. 240–300 for a 550B model on the NIM free tier).
_TIMEOUT_SECONDS = int(os.environ.get("MCP_SCANNER_TIMEOUT", "60"))

# Severity values the scanner considers unsafe.
_UNSAFE_SEVERITIES = frozenset({"HIGH", "MEDIUM", "CRITICAL"})

# mcp-scanner LLM provider config env vars. The scanner reads these directly
# via its CONSTANTS module — we don't pass them on the CLI. Documented here
# so the adapter's setup() can raise an informative error early.
_LLM_ENV_VARS = (
    "MCP_SCANNER_LLM_API_KEY",
    "MCP_SCANNER_LLM_MODEL",
    "MCP_SCANNER_LLM_BASE_URL",
)


def _find_mcp_scanner() -> str:
    """Return the absolute path to ``mcp-scanner``."""
    path = shutil.which("mcp-scanner")
    if path:
        return path
    raise FileNotFoundError(
        "mcp-scanner is not installed. "
        "Install it with: pipx install cisco-ai-mcp-scanner"
    )


def _llm_env_hint() -> str:
    """Human-readable hint for required NIM-compatible env vars."""
    return (
        "LLM mode requires these env vars to be set (mcp-scanner reads them via LiteLLM):\n"
        "  MCP_SCANNER_LLM_API_KEY=<your provider key>\n"
        "  MCP_SCANNER_LLM_MODEL=openai/meta/llama-3.3-70b-instruct  # or any LiteLLM model id\n"
        "  MCP_SCANNER_LLM_BASE_URL=https://integrate.api.nvidia.com/v1  # for NIM"
    )


class CiscoBaseAdapter(ToolAdapter):
    """Common subprocess + parse pipeline for all mcp-scanner modes."""

    #: Comma-separated analyzer list passed to ``--analyzers``. Override.
    _analyzers: str = ""

    #: True if this adapter calls an LLM (used for setup-time env checks).
    _uses_llm: bool = False

    def __init__(self) -> None:
        self._bin: str = ""

    @property
    def name(self) -> str:
        raise NotImplementedError

    def setup(self) -> None:
        self._bin = _find_mcp_scanner()
        if self._uses_llm:
            missing = [v for v in _LLM_ENV_VARS if not os.environ.get(v)]
            if missing:
                raise EnvironmentError(
                    f"{self.name}: missing env vars {missing}.\n{_llm_env_hint()}"
                )

    def evaluate(self, test_case: TestCase) -> Result:
        if not self._bin:
            self.setup()

        tmpdir = tempfile.mkdtemp(prefix="guardbench-")
        try:
            return self._run(test_case, tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------

    def _write_inputs(self, av: dict, test_case_id: str, tmpdir: str) -> tuple[list[str], list[str]]:
        """Write tools/prompts/resources JSON files for what attack_vector populates.

        Returns ``(cmd_flags, skipped_components)``. ``cmd_flags`` are the
        ``--tools``/``--prompts``/``--resources`` arguments to append to the
        command; ``skipped_components`` lists attack_vector keys that have
        no static-scan path (currently just ``server`` — the
        ``instructions`` subcommand requires a live server).
        """
        cmd_flags: list[str] = []
        skipped: list[str] = []

        # Always write tools.json — every entry has at minimum a tool def.
        tool = {
            "name": av.get("name", f"probe_{test_case_id}"),
            "description": av.get("description", ""),
            "inputSchema": av.get("inputSchema", {"type": "object", "properties": {}}),
        }
        # Handler isn't part of the canonical MCP tools/list response, but the
        # static_analyzer serializes the whole tool dict (minus description)
        # and scans it. Including handler lets YARA/LLM see the executable body.
        if av.get("handler"):
            tool["handler"] = av["handler"]
        tools_path = os.path.join(tmpdir, f"tools-{test_case_id}.json")
        with open(tools_path, "w") as f:
            json.dump({"tools": [tool]}, f)
        cmd_flags += ["--tools", tools_path]

        # prompts.json — faithful pass-through. mcp-scanner's
        # scan_prompts_file only reads name + description + arguments, NOT
        # template. That blind spot is recorded in results rather than
        # worked around (decision 2026-05-22).
        if av.get("prompt"):
            prompts_path = os.path.join(tmpdir, f"prompts-{test_case_id}.json")
            with open(prompts_path, "w") as f:
                json.dump({"prompts": [av["prompt"]]}, f)
            cmd_flags += ["--prompts", prompts_path]

        # resources.json — use resources/read shape ({contents: [...]}) so
        # the scanner sees the actual text payload, not just metadata.
        if av.get("resource"):
            resources_path = os.path.join(tmpdir, f"resources-{test_case_id}.json")
            with open(resources_path, "w") as f:
                json.dump({"contents": [av["resource"]]}, f)
            cmd_flags += ["--resources", resources_path]

        # server.instructions has no static-scan path in mcp-scanner.
        if av.get("server"):
            skipped.append("server")

        return cmd_flags, skipped

    def _run(self, test_case: TestCase, tmpdir: str) -> Result:
        av = parse_attack_vector(test_case.attack_vector, test_case.id)
        input_flags, skipped = self._write_inputs(av, test_case.id, tmpdir)

        cmd = [
            self._bin,
            "--analyzers", self._analyzers,
            "--raw",
            "static",
            *input_flags,
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

        return self._parse(test_case, raw, latency_ms, skipped)

    # ------------------------------------------------------------------

    def _parse(
        self,
        test_case: TestCase,
        raw,
        latency_ms: int,
        skipped: Optional[list[str]] = None,
    ) -> Result:
        threats: list[dict] = []

        # raw is a list of per-(tool|prompt|resource) result dicts.
        for item in raw if isinstance(raw, list) else []:
            is_safe = item.get("is_safe", True)
            findings = item.get("findings", {})

            # `findings` can be a dict (analyzer_name -> details) or a list
            # depending on mcp-scanner version / scan type. Normalize.
            if isinstance(findings, dict):
                iter_findings = findings.items()
            else:
                iter_findings = [(f.get("analyzer", "?"), f) for f in findings if isinstance(f, dict)]

            for analyzer_name, details in iter_findings:
                severity = details.get("severity", "SAFE")
                if is_safe is False or severity in _UNSAFE_SEVERITIES:
                    threats.append({
                        "analyzer": analyzer_name,
                        "severity": severity,
                        "threat_names": details.get("threat_names", []),
                        "threat_summary": details.get("threat_summary", ""),
                        "total_findings": details.get("total_findings", 0),
                        "mcp_taxonomies": details.get("mcp_taxonomies", []),
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

        raw_output: dict = {"threats": threats, "scan_output": raw}
        if skipped:
            raw_output["skipped_components"] = skipped
            explanation += f" (skipped: {', '.join(skipped)})"

        return Result(
            test_case_id=test_case.id,
            tool_name=self.name,
            blocked=blocked,
            confidence=confidence,
            explanation=explanation,
            latency_ms=latency_ms,
            raw_output=raw_output,
            timestamp=datetime.now(timezone.utc),
        )
