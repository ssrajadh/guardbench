"""Minimal MCP stdio server that exposes a single tool with a given description.

Speaks just enough JSON-RPC to satisfy snyk-agent-scan's inspection phase:
  1. Respond to ``initialize`` with server capabilities.
  2. Respond to ``tools/list`` with one tool whose description is the
     attack_vector under test.
  3. Respond to ``notifications/initialized`` (no reply needed).

Invoked as::

    python -m guardbench.adapters._mcp_stub_server <tool_name> <tool_description>
"""

import json
import sys


def _respond(id_: int, result: dict) -> None:
    msg = json.dumps({"jsonrpc": "2.0", "id": id_, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def main() -> None:
    tool_name = sys.argv[1]
    tool_description = sys.argv[2]

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method", "")
        req_id = req.get("id")

        if method == "initialize":
            _respond(req_id, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "guardbench-stub", "version": "0.1.0"},
                "capabilities": {"tools": {}},
            })
        elif method == "tools/list":
            _respond(req_id, {
                "tools": [
                    {
                        "name": tool_name,
                        "description": tool_description,
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                        },
                    }
                ]
            })
        # notifications (no id) like notifications/initialized — ignore silently


if __name__ == "__main__":
    main()
