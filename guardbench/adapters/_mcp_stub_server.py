"""Minimal MCP stdio server that surfaces a parsed attack_vector dict.

Speaks just enough JSON-RPC to satisfy snyk-agent-scan's inspection phase.
The server advertises capabilities and responds to list/get/read methods
based on which keys the attack_vector dict populates:

  - Always: tools/list (built from name/description/inputSchema/handler)
  - If av['prompt']:   prompts/list, prompts/get
  - If av['resource']: resources/list, resources/read
  - If av['server']:   serverInfo + instructions in initialize result

Invoked as::

    python _mcp_stub_server.py <path-to-attack-vector-json>

The JSON file at <path> must contain a dict shaped like a corpus entry's
parsed attack_vector (the JSON-decoded form of CorpusEntry.attack_vector).
"""

import json
import sys
from pathlib import Path


def _respond(id_, result: dict) -> None:
    msg = json.dumps({"jsonrpc": "2.0", "id": id_, "result": result})
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def _error(id_, code: int, message: str) -> None:
    msg = json.dumps({
        "jsonrpc": "2.0",
        "id": id_,
        "error": {"code": code, "message": message},
    })
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def _capabilities(av: dict) -> dict:
    caps: dict = {"tools": {}}
    if av.get("prompt"):
        caps["prompts"] = {}
    if av.get("resource"):
        caps["resources"] = {}
    return caps


def _server_info(av: dict) -> dict:
    server = av.get("server") or {}
    return {
        "name": server.get("name", "guardbench-stub"),
        "version": server.get("version", "0.1.0"),
    }


def _initialize_result(av: dict) -> dict:
    result = {
        "protocolVersion": "2024-11-05",
        "serverInfo": _server_info(av),
        "capabilities": _capabilities(av),
    }
    server = av.get("server") or {}
    if server.get("instructions"):
        # MCP spec: optional top-level `instructions` field in InitializeResult.
        # snyk-agent-scan and other scanners can flag injection here.
        result["instructions"] = server["instructions"]
    return result


def _tool_entry(av: dict) -> dict:
    return {
        "name": av.get("name", "probe"),
        "description": av.get("description", ""),
        "inputSchema": av.get("inputSchema", {"type": "object", "properties": {}}),
    }


def _prompt_metadata(prompt: dict) -> dict:
    return {
        "name": prompt.get("name", "prompt"),
        "description": prompt.get("description", ""),
        "arguments": prompt.get("arguments", []),
    }


def _prompt_get_result(prompt: dict) -> dict:
    """Build a prompts/get response carrying the template body as a message."""
    template = prompt.get("template", "")
    return {
        "description": prompt.get("description", ""),
        "messages": [
            {
                "role": "user",
                "content": {"type": "text", "text": template},
            }
        ],
    }


def _resource_metadata(resource: dict) -> dict:
    return {
        "uri": resource.get("uri", "resource://unknown"),
        "name": resource.get("name", "resource"),
        "description": resource.get("description", ""),
        "mimeType": resource.get("mimeType", "text/plain"),
    }


def _resource_read_result(resource: dict) -> dict:
    return {
        "contents": [
            {
                "uri": resource.get("uri", "resource://unknown"),
                "mimeType": resource.get("mimeType", "text/plain"),
                "text": resource.get("text", ""),
            }
        ]
    }


def handle(av: dict, req: dict) -> None:
    method = req.get("method", "")
    req_id = req.get("id")

    # Notifications (no id) — never reply, regardless of method.
    if req_id is None:
        return

    if method == "initialize":
        _respond(req_id, _initialize_result(av))
        return

    if method == "tools/list":
        _respond(req_id, {"tools": [_tool_entry(av)]})
        return

    if method == "prompts/list":
        prompts = [_prompt_metadata(av["prompt"])] if av.get("prompt") else []
        _respond(req_id, {"prompts": prompts})
        return

    if method == "prompts/get":
        if av.get("prompt"):
            _respond(req_id, _prompt_get_result(av["prompt"]))
        else:
            _error(req_id, -32601, "no prompt defined")
        return

    if method == "resources/list":
        resources = [_resource_metadata(av["resource"])] if av.get("resource") else []
        _respond(req_id, {"resources": resources})
        return

    if method == "resources/read":
        if av.get("resource"):
            _respond(req_id, _resource_read_result(av["resource"]))
        else:
            _error(req_id, -32601, "no resource defined")
        return

    _error(req_id, -32601, f"method not found: {method}")


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: _mcp_stub_server.py <attack-vector-json-path>\n")
        sys.exit(2)

    av_path = Path(sys.argv[1])
    av = json.loads(av_path.read_text())

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        handle(av, req)


if __name__ == "__main__":
    main()
