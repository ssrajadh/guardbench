# GuardBench

A benchmark for measuring how well pre-deployment **MCP security scanners** hold up when a
malicious MCP server is given cosmetic, meaning-preserving obfuscation. Each corpus entry is a
static attack-vector artifact (a tool, prompt, resource, or server metadata) with ground-truth
labels; every malicious seed also ships in two obfuscation tiers (`light`, `heavy`). The harness
runs all of it through five scanner configurations and reports detection recall, robustness to
obfuscation, and false-positive rate on benign servers.

## Reproducing the results

### 1. Requirements

- Python **3.12+**
- [`pipx`](https://pipx.pypa.io/) and [`uv`](https://docs.astral.sh/uv/) for the external scanners
- API credentials for the LLM-backed and Snyk scanners (see step 4)

### 2. Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### 3. Install the external scanners

The Cisco and Snyk adapters shell out to external tools:

```bash
pipx install cisco-ai-mcp-scanner   # provides `mcp-scanner` on PATH
curl -LsSf https://astral.sh/uv/install.sh | sh   # provides `uvx`; Snyk is run via `uvx snyk-agent-scan@latest`
```

`baseline` and `cisco-static` need neither credentials nor network, so you can run those two end
to end with no further setup.

### 4. Configure credentials

Copy `.env.example` to `.env`, fill in the values (Snyk token, LLM judge provider/model/base-URL),
and export them — the harness does **not** auto-load `.env`:

```bash
set -a; . .env; set +a
```

`.env.example` documents each variable and the provider trade-offs. `run-config.json` records the
exact judge models, base URLs, `--n-llm`, and scanner env (`MCP_SCANNER_TIMEOUT=300`,
`MCP_SCANNER_LLM_MAX_RETRIES=1`) used for the reported runs.

### 5. Run the experiments

All scripts write to `audit/` (gitignored; runs are re-entrant — add `--resume` to top up a
crashed run).

```bash
# Recall + obfuscation survival (E1/E2), all 5 scanners, N=3 LLM trials
python scripts/mutation_survival.py --n-llm 3

# False-positive rate over the benign control set
python scripts/fpr.py --n-llm 3
```

Smoke-test the wiring first with no credentials:

```bash
python scripts/mutation_survival.py --limit 2 --scanners baseline
```

Useful flags: `--limit N`, `--seeds id1,id2`, `--scanners cisco-static,cisco-hybrid`,
`--summary-only` (regenerate the rollup/summary without re-running scans).

### 6. Compute the headline metrics

These read a run's `-rollup.csv` and print the paper's tables (defaults point at the snapshot
paths in `run-config.json`; pass `--rollup` / `--recall` / `--fpr` to point elsewhere):

```bash
python scripts/aggregate_metrics.py   # per-category + attack-surface recall
python scripts/combined_metrics.py    # recall + FPR + balanced accuracy / Youden's J
```

## Inspecting the corpus & running tests

```bash
# Distribution report for any corpus file
python -m guardbench.corpus.cli stats guardbench/corpus/corpus_seeds.json

# Test suite (integration tests requiring network are skipped by default)
python -m pytest -q
```
