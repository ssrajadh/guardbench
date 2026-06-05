"""Cisco mcp-scanner adapter — LLM-only mode.

Runs ``--analyzers llm`` against the static input shape. The LLM provider
is configured via env vars that mcp-scanner reads through LiteLLM:

  MCP_SCANNER_LLM_API_KEY=<provider api key>
  MCP_SCANNER_LLM_MODEL=openai/meta/llama-3.3-70b-instruct
  MCP_SCANNER_LLM_BASE_URL=https://integrate.api.nvidia.com/v1   # for NIM

For NIM specifically, prefix the model id with ``openai/`` so LiteLLM uses
its OpenAI-compatible client against NIM's ``/v1`` endpoint.
"""

from guardbench.adapters.cisco_base import CiscoBaseAdapter


class CiscoLLMAdapter(CiscoBaseAdapter):
    _analyzers = "llm"
    _uses_llm = True

    @property
    def name(self) -> str:
        return "cisco-llm"
