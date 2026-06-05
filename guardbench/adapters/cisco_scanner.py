"""Cisco mcp-scanner adapter — static (YARA-only) mode.

This module historically held the only Cisco adapter; it now exposes the
static mode as :class:`CiscoStaticAdapter` and re-exports it under the
legacy name :class:`CiscoScannerAdapter` for back-compat. The two
additional modes live in sibling modules :mod:`cisco_llm` and
:mod:`cisco_hybrid`.
"""

from guardbench.adapters.cisco_base import CiscoBaseAdapter, _find_mcp_scanner

__all__ = ["CiscoStaticAdapter", "CiscoScannerAdapter", "_find_mcp_scanner"]


class CiscoStaticAdapter(CiscoBaseAdapter):
    _analyzers = "yara"
    _uses_llm = False

    @property
    def name(self) -> str:
        return "cisco-static"


# Back-compat alias — older code (phase3 smoke, tests) imports this name.
CiscoScannerAdapter = CiscoStaticAdapter
