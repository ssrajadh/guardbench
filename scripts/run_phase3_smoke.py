"""Phase 3 smoke run: stratified 20-case sample x 4 adapters.

- 2 cases per CoSAI category (10 categories present), preferring a mix
  of expected verdicts where both exist.
- 5 runs per case for adapters that may invoke an LLM internally
  (Snyk Agent Scan, Cisco AI Defense MCP Scanner); 1 run for
  deterministic adapters (baseline, semgrep).
- Raw Result rows saved to results/phase3_smoke.json.
- Prints a tool x CoSAI summary using per-case majority vote.
- Flags any adapter whose majority verdict is constant across all 20
  cases (likely a wiring bug).
"""

from __future__ import annotations

import json
import sys
import traceback
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from guardbench.adapters.baseline import BaselineAdapter
from guardbench.adapters.semgrep_mcp import SemgrepMCPAdapter  # noqa
from guardbench.adapters.snyk_agent_scan import SnykAgentScanAdapter  # noqa
from guardbench.adapters.cisco_scanner import CiscoScannerAdapter  # noqa
from guardbench.schemas import Result, TestCase

CORPUS = ROOT / "guardbench/corpus/corpus.json"
HARNESS = ROOT / "corpus_harness.json"
OUT = ROOT / "results/phase3_smoke.json"

LLM_LIKE = {"snyk-agent-scan", "cisco-mcp-scanner"}
N_RUNS_LLM = 5


def _stratified_sample(entries: list[dict], per_cat: int = 2) -> list[dict]:
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for e in sorted(entries, key=lambda x: x["id"]):
        by_cat[e["cosai_category"]].append(e)
    sample: list[dict] = []
    for cat, items in sorted(by_cat.items()):
        blocks = [x for x in items if x["expected_verdict"] == "block"]
        allows = [x for x in items if x["expected_verdict"] == "allow"]
        picked: list[dict] = []
        if blocks and allows:
            picked = [blocks[0], allows[0]]
        else:
            picked = (blocks + allows)[:per_cat]
        sample.extend(picked[:per_cat])
    return sample


def _adapters():
    return [
        BaselineAdapter(),
        SemgrepMCPAdapter(),
        SnykAgentScanAdapter(),
        CiscoScannerAdapter(),
    ]


def _to_test_case(d: dict) -> TestCase:
    keys = set(TestCase.model_fields)
    return TestCase.model_validate({k: v for k, v in d.items() if k in keys})


def _run_one(adapter, tc: TestCase, n_runs: int) -> list[Result]:
    try:
        return adapter.evaluate_with_retries(tc, n_runs=n_runs)
    except Exception as exc:
        traceback.print_exc()
        return [
            Result(
                test_case_id=tc.id, tool_name=adapter.name,
                blocked=False, confidence=0.0,
                explanation=f"ADAPTER ERROR: {type(exc).__name__}: {exc}",
                latency_ms=0,
                raw_output={"error": str(exc)},
                timestamp=datetime.now(timezone.utc),
                error=f"{type(exc).__name__}: {exc}",
            )
        ]


def _case_verdict(results: list[Result]) -> tuple[str, int, int, int]:
    """Return (verdict, n_block, n_allow, n_error). Errors exclude from the
    majority vote; a case is 'error' only when all runs errored."""
    errs = [r for r in results if r.error]
    ok = [r for r in results if not r.error]
    if not ok:
        return ("error", 0, 0, len(errs))
    blocks = sum(1 for r in ok if r.blocked)
    allows = len(ok) - blocks
    verdict = "block" if blocks * 2 > len(ok) else "allow"
    return (verdict, blocks, allows, len(errs))


def main() -> int:
    full = json.loads(CORPUS.read_text())
    sample = _stratified_sample(full, per_cat=2)
    print(f"sampled {len(sample)} cases across "
          f"{len({s['cosai_category'] for s in sample})} CoSAI categories")
    for s in sample:
        print(f"  {s['cosai_category']:<3} {s['expected_verdict']:<5} {s['id']}")

    test_cases = [_to_test_case(s) for s in sample]

    all_results: list[dict] = []
    # per_case_majority[(adapter_name, tc_id)] = "block" | "allow"
    majority: dict[tuple[str, str], str] = {}

    skipped_adapters: dict[str, str] = {}
    for adapter in _adapters():
        try:
            adapter.setup()
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            print(f"setup failed for {adapter.name}: {msg} — skipping",
                  file=sys.stderr)
            skipped_adapters[adapter.name] = msg
            # mark every case as error so downstream math doesn't coerce to allow
            for tc in test_cases:
                majority[(adapter.name, tc.id)] = "error"
            continue
        n = N_RUNS_LLM if adapter.name in LLM_LIKE else 1
        print(f"\n=== {adapter.name}  (n_runs={n}) ===", flush=True)
        for tc in test_cases:
            results = _run_one(adapter, tc, n)
            for r in results:
                all_results.append(r.model_dump(mode="json"))
            verdict, nb, na, ne = _case_verdict(results)
            majority[(adapter.name, tc.id)] = verdict
            print(f"  {tc.id:<32} runs={len(results)} "
                  f"block={nb} allow={na} err={ne} -> {verdict}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(all_results, indent=2) + "\n")
    print(f"\nwrote {len(all_results)} raw results -> {OUT}")

    # ----- summary table: tool x CoSAI (block / allow per cell) -----
    cats = sorted({s["cosai_category"] for s in sample})
    tools = [a.name for a in _adapters()]
    print("\nSUMMARY  tool x CoSAI  (cell = block/allow/error by majority verdict)")
    header = f"{'tool':<22} " + " ".join(f"{c:>9}" for c in cats) + f" {'TOTAL':>11}"
    print(header)
    print("-" * len(header))
    constant_verdict_tools: list[tuple[str, str]] = []
    BASELINE_EXPECTED = {"baseline"}  # by design — exclude from constant-flag
    for tool in tools:
        row_block = Counter()
        row_allow = Counter()
        row_error = Counter()
        verdicts_seen = set()
        for s in sample:
            v = majority[(tool, s["id"])]
            verdicts_seen.add(v)
            if v == "block":
                row_block[s["cosai_category"]] += 1
            elif v == "allow":
                row_allow[s["cosai_category"]] += 1
            else:
                row_error[s["cosai_category"]] += 1
        cells = [f"{row_block[c]}/{row_allow[c]}/{row_error[c]}" for c in cats]
        total = (f"{sum(row_block.values())}/"
                 f"{sum(row_allow.values())}/"
                 f"{sum(row_error.values())}")
        print(f"{tool:<22} " + " ".join(f"{c:>9}" for c in cells) + f" {total:>11}")
        # flag constant non-error verdict across full sample (excl. baseline-by-design)
        non_error = verdicts_seen - {"error"}
        if len(non_error) == 1 and len(verdicts_seen) == 1 and tool not in BASELINE_EXPECTED:
            constant_verdict_tools.append((tool, verdicts_seen.pop()))

    print("\nGround truth (expected block/allow per CoSAI):")
    gt_block = Counter()
    gt_allow = Counter()
    for s in sample:
        if s["expected_verdict"] == "block":
            gt_block[s["cosai_category"]] += 1
        else:
            gt_allow[s["cosai_category"]] += 1
    cells = [f"{gt_block[c]}/{gt_allow[c]}/0" for c in cats]
    total = f"{sum(gt_block.values())}/{sum(gt_allow.values())}/0"
    print(f"{'expected':<22} " + " ".join(f"{c:>9}" for c in cells) + f" {total:>11}")

    if skipped_adapters:
        print("\nSkipped adapters (setup failed — not a precision/recall signal):")
        for name, msg in skipped_adapters.items():
            print(f"  - {name}: {msg}")

    if constant_verdict_tools:
        print("\nFLAG — adapters with constant non-error majority verdict across the sample:")
        for tool, v in constant_verdict_tools:
            print(f"  - {tool}: always {v!r}  (likely wiring bug, not real behavior)")
    else:
        print("\nNo adapter returned a constant verdict across the sample "
              "(baseline's always-allow is expected by design and excluded).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
