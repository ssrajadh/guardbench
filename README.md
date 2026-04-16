# GuardBench

Benchmarking framework for MCP security guardrails.

MS Capstone Project

## Prerequisites

- Python 3.12+
- Docker & Docker Compose

## Setup

```bash
# Clone the repo
git clone <repo-url> && cd guardbench

# Create a virtual environment and install dependencies
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start the local OpenClaw instance
docker compose up -d
```

OpenClaw will be available at `http://localhost:18789`.

## Running tests

```bash
pytest
```

## Security scanning tools

The scanners below are used to evaluate MCP guardrails. Each tool is installed
in isolation (via `uvx` or `pipx`) to avoid dependency conflicts with the
project venv.

### Install uv (provides uvx)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Snyk Agent Scan

```bash
# Runs in a temporary venv via uvx — no permanent install needed
uvx snyk-agent-scan@latest scan --help
```

Pin: `@latest` always pulls the current release. For reproducibility, pin to a
specific version:

```bash
uvx snyk-agent-scan@0.3.2 scan --help   # replace with desired version
```

### Cisco MCP Scanner

```bash
# PyPI package name is cisco-ai-mcp-scanner
pipx install cisco-ai-mcp-scanner
mcp-scanner --help
```

Repository: https://github.com/cisco-ai-defense/mcp-scanner

Pin:

```bash
pipx install cisco-ai-mcp-scanner==4.6.0   # replace with desired version
```

### Semgrep MCP

```bash
pipx install semgrep
semgrep --help
```

Pin:

```bash
pipx install semgrep==1.159.0   # replace with desired version
```

## Project structure

```
guardbench/
  __init__.py
  adapters/       # Scanner adapter implementations (not yet implemented)
  corpus/         # Test corpora and prompt datasets
  runner/         # Orchestration and execution engine
  metrics/        # Scoring and visualization
tests/            # Test suite
docs/             # Documentation
```
