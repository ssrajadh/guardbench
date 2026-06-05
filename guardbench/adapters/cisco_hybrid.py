"""Cisco mcp-scanner adapter — hybrid (YARA + LLM) mode.

Runs both analyzers and merges findings. Requires the same LLM env vars
as :mod:`cisco_llm`; see that module's docstring for NIM configuration.
"""

from guardbench.adapters.cisco_base import CiscoBaseAdapter


class CiscoHybridAdapter(CiscoBaseAdapter):
    _analyzers = "yara,llm"
    _uses_llm = True

    @property
    def name(self) -> str:
        return "cisco-hybrid"
