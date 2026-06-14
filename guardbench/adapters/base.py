"""Abstract base class for all tool adapters."""

import json
from abc import ABC, abstractmethod

from guardbench.schemas import Result, TestCase


def parse_attack_vector(av: str, test_case_id: str) -> dict:
    """Parse attack_vector into a tool-def dict.

    Corpus entries store attack_vector as a JSON-encoded MCP tool definition
    with keys {name, description, inputSchema, handler, ?prompt, ?resource,
    ?server}. Older tests pass attack_vector as a plain (non-JSON) string; in
    that case we wrap it as a synthetic tool's description so the adapter still
    has something well-formed to scan.

    A string that *parses* as JSON but is not a usable tool object (a JSON
    array/number, or a dict lacking both ``name`` and ``description``) is a
    malformed corpus entry and raises rather than silently degrading into a
    description-only probe that hides the real payload (audit r4).
    """
    try:
        parsed = json.loads(av)
    except (json.JSONDecodeError, TypeError):
        parsed = None

    if isinstance(parsed, dict):
        if "name" in parsed or "description" in parsed:
            return parsed
        raise ValueError(
            f"attack_vector for {test_case_id} is a JSON object but lacks both "
            f"'name' and 'description' — malformed tool definition"
        )
    if parsed is not None:
        raise ValueError(
            f"attack_vector for {test_case_id} is JSON but not a tool object "
            f"(got {type(parsed).__name__})"
        )

    # Non-JSON plain string: legacy synthetic-tool wrap (intentional).
    return {
        "name": f"probe_{test_case_id}",
        "description": av,
        "inputSchema": {"type": "object", "properties": {}},
    }


class ToolAdapter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this tool adapter."""

    @abstractmethod
    def evaluate(self, test_case: TestCase) -> Result:
        """Run a single test case through the tool and return a Result."""

    def setup(self) -> None:
        """Optional setup hook. Override in subclasses that need initialization."""

    def evaluate_with_retries(self, test_case: TestCase, n_runs: int = 1) -> list[Result]:
        """Call evaluate *n_runs* times and return all results."""
        return [self.evaluate(test_case) for _ in range(n_runs)]
