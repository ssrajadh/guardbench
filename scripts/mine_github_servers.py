#!/usr/bin/env python3
"""Mine real, benign MCP tool definitions from public GitHub servers.

This is the front end of the false-positive-rate (FPR) experiment. It produces
benign (``expected_verdict="allow"``) corpus entries shaped *identically* to the
malicious corpus — a single tool def ``{name, description, inputSchema, handler}``
per entry — so they ride the exact same adapter/stub-server pipeline as the
recall run and the resulting FPR is comparable to recall (see PAPER §6.2, §11).

Scope (locked decisions):
  * Per-tool artifacts through the existing stub pipeline (not live servers).
  * Python FastMCP / MCP-SDK servers first — ``@mcp.tool``-decorated functions
    give clean AST extraction of name / docstring / signature-schema / and a
    *real handler body* (which is what the YARA analyzer reads).
  * Selection by an OBJECTIVE signal (stars + recency), never "servers the
    scanners happen to pass" — the no-tuning principle is symmetric (PAPER §6.3).

Three phases, runnable together or separately:

    # 1+2: search GitHub, clone, extract -> draft JSON
    PYTHONPATH=. python3 scripts/mine_github_servers.py \
        --search "mcp server language:python stars:>20" \
        --max-repos 60 --max-tools-per-repo 3

    # extract only, from repos already cloned under --workdir
    PYTHONPATH=. python3 scripts/mine_github_servers.py --from-clones

    # extract from an explicit repo list (one "owner/name" per line)
    PYTHONPATH=. python3 scripts/mine_github_servers.py --repos-file repos.txt

Outputs (under guardbench/corpus/working/):
  * benign_mined_draft.json    — list of CorpusEntry dicts (review_status=draft)
  * benign_mined_manifest.json — per-entry provenance (repo, commit, path, …)

This produces a *draft*. It does NOT decide benign-ness: real servers ship real
bugs, and a genuinely vulnerable mined tool is a TRUE positive, not a false one.
Phase 3 (validity gate, separate step) screens the draft for live sinks and a
human quarantines anything actually exploitable before it is locked.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from guardbench.corpus.schema import CorpusEntry  # noqa: E402

WORKDIR = ROOT / "guardbench" / "corpus" / "working" / "mined_clones"
OUT_DRAFT = ROOT / "guardbench" / "corpus" / "working" / "benign_mined_draft.json"
OUT_MANIFEST = ROOT / "guardbench" / "corpus" / "benign" / "benign_mined_manifest.json"

# Licenses we may redistribute a derived snippet under. Anything else (GPL
# copyleft, no license, custom) is skipped so the frozen corpus stays clean.
PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"}

# Decorator attribute names that register an MCP tool across the common SDKs:
#   @mcp.tool() / @app.tool / @server.tool(...)  -> "tool"
#   server.add_tool(...)                          -> "add_tool" (rarely a decorator)
TOOL_DECORATOR_ATTRS = {"tool", "add_tool"}

# Params FastMCP/SDK inject rather than take from the caller — excluded from schema.
INJECTED_PARAMS = {"self", "cls", "ctx", "context"}

# Python annotation -> JSON Schema primitive. Unknowns fall back to "string".
_TYPE_MAP = {
    "int": "integer", "float": "number", "str": "string", "bool": "boolean",
    "list": "array", "List": "array", "tuple": "array", "set": "array",
    "dict": "object", "Dict": "object", "bytes": "string",
}

# Lightweight "which detector family is this most likely to trip" heuristic, used
# ONLY to populate the required cosai_category field. It is NOT a threat label —
# every mined entry is benign. Ordered; first hit wins.
_TRIPWIRE_HEURISTIC: list[tuple[str, str, str]] = [
    (r"\bsubprocess\b|\bos\.system\b|\bshell=True\b|\bPopen\b", "T3", "shell_or_subprocess_use"),
    (r"\bimportlib\b|\bgetattr\(|\b__import__\b|\beval\(|\bexec\(", "T3", "dynamic_dispatch_or_eval"),
    (r"\brequests\.|httpx\.|urllib|aiohttp|\.get\(\s*[\"']https?://", "T8", "outbound_network_fetch"),
    (r"\bopen\(|Path\(|os\.path|\.read_text\(|\.write_|glob\(", "T3", "filesystem_path_io"),
    (r"\bbase64\b|b64decode|b64encode", "T3", "base64_transport"),
    (r"\bexecute\(|\bcursor\b|SELECT |INSERT |UPDATE ", "T3", "sql_query"),
    (r"os\.environ|getenv|\bsecret\b|\btoken\b|credential", "T5", "credential_or_env_use"),
]
_DEFAULT_TRIPWIRE = ("T3", "benign_tool")


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

@dataclass
class RepoMeta:
    full_name: str
    url: str
    stars: int = 0
    license: str = ""
    commit: str = ""
    path: Path | None = None


@dataclass
class ExtractedTool:
    name: str
    description: str
    input_schema: dict
    handler: str
    rel_path: str
    lineno: int


@dataclass
class MineStats:
    repos_seen: int = 0
    repos_skipped_license: list[str] = field(default_factory=list)
    repos_no_tools: list[str] = field(default_factory=list)
    tools_extracted: int = 0
    tools_deduped: int = 0


# ---------------------------------------------------------------------------
# Phase 1 — GitHub search + clone (via `gh`)
# ---------------------------------------------------------------------------

def _gh(args: list[str]) -> str:
    """Run a `gh` CLI command, returning stdout. Raises on non-zero exit."""
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def search_repos(query: str, limit: int) -> list[RepoMeta]:
    """Search GitHub repos by an objective signal (the query carries stars/recency).

    Sorted by stars descending. License is read from repo metadata so we can
    drop non-redistributable repos before cloning.
    """
    out = _gh([
        "search", "repos", query,
        "--limit", str(limit),
        "--sort", "stars",
        "--json", "fullName,url,stargazersCount,license",
    ])
    repos: list[RepoMeta] = []
    for r in json.loads(out):
        lic = (r.get("license") or {}).get("key", "") or ""
        # gh returns SPDX-ish keys lowercased (e.g. "mit", "apache-2.0").
        lic_norm = {"mit": "MIT", "apache-2.0": "Apache-2.0", "bsd-2-clause": "BSD-2-Clause",
                    "bsd-3-clause": "BSD-3-Clause", "isc": "ISC", "unlicense": "Unlicense",
                    "0bsd": "0BSD"}.get(lic.lower(), lic)
        repos.append(RepoMeta(
            full_name=r["fullName"], url=r["url"],
            stars=r.get("stargazersCount", 0), license=lic_norm,
        ))
    return repos


def clone_repo(meta: RepoMeta, workdir: Path) -> RepoMeta:
    """Shallow-clone a repo and pin its commit SHA. Idempotent."""
    dest = workdir / meta.full_name.replace("/", "__")
    if not dest.exists():
        subprocess.run(
            ["git", "clone", "--depth", "1", meta.url, str(dest)],
            check=True, capture_output=True, text=True,
        )
    sha = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    meta.path = dest
    meta.commit = sha
    return meta


# ---------------------------------------------------------------------------
# Phase 2 — AST extraction
# ---------------------------------------------------------------------------

def _annotation_to_schema(node: ast.expr | None) -> dict:
    """Map a Python annotation AST node to a minimal JSON-Schema fragment."""
    if node is None:
        return {"type": "string"}
    if isinstance(node, ast.Name):
        return {"type": _TYPE_MAP.get(node.id, "string")}
    if isinstance(node, ast.Subscript):  # list[int], Optional[str], dict[str, X]
        base = node.value
        base_name = base.id if isinstance(base, ast.Name) else getattr(base, "attr", "")
        if base_name in ("Optional", "Union"):
            # Take the first non-None arg's type.
            return _annotation_to_schema(_first_subscript_arg(node))
        return {"type": _TYPE_MAP.get(base_name, "string")}
    if isinstance(node, ast.Constant) and node.value is None:
        return {"type": "string"}
    return {"type": "string"}


def _first_subscript_arg(node: ast.Subscript) -> ast.expr | None:
    sl = node.slice
    if isinstance(sl, ast.Tuple) and sl.elts:
        return sl.elts[0]
    return sl


def _is_injected(arg: ast.arg) -> bool:
    if arg.arg in INJECTED_PARAMS:
        return True
    ann = arg.annotation
    ann_name = ann.id if isinstance(ann, ast.Name) else getattr(ann, "attr", "")
    return ann_name in ("Context", "Request")


def _schema_from_signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    props: dict[str, dict] = {}
    required: list[str] = []
    a = fn.args
    pos = list(a.args) + list(a.kwonlyargs)
    n_pos_defaults = len(a.defaults)
    # defaults align to the tail of a.args
    defaulted = {arg.arg for arg in a.args[len(a.args) - n_pos_defaults:]}
    defaulted |= {arg.arg for arg, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None}
    for arg in pos:
        if _is_injected(arg):
            continue
        props[arg.arg] = _annotation_to_schema(arg.annotation)
        if arg.arg not in defaulted:
            required.append(arg.arg)
    schema: dict = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _tool_decorator(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.expr | None:
    """Return the decorator node if fn is registered as an MCP tool, else None."""
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute) and target.attr in TOOL_DECORATOR_ATTRS:
            return dec
    return None


def _decorator_kwarg(dec: ast.expr, key: str) -> str | None:
    if isinstance(dec, ast.Call):
        for kw in dec.keywords:
            if kw.arg == key and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
    return None


def extract_tools_from_file(path: Path, rel_path: str) -> list[ExtractedTool]:
    try:
        source = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    tools: list[ExtractedTool] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        dec = _tool_decorator(node)
        if dec is None:
            continue
        handler = ast.get_source_segment(source, node) or ""
        if not handler.strip():
            continue
        name = _decorator_kwarg(dec, "name") or node.name
        description = (
            _decorator_kwarg(dec, "description")
            or ast.get_docstring(node)
            or ""
        ).strip()
        tools.append(ExtractedTool(
            name=name,
            description=description,
            input_schema=_schema_from_signature(node),
            handler=handler,
            rel_path=rel_path,
            lineno=node.lineno,
        ))
    return tools


# Path components that mark non-production code (test fixtures, mocks, examples,
# vendored deps). Matched case-insensitively against each path component so
# "Tests", "ContextCoreTests", "tests_integ", "_test_x.py" are all caught — but
# substrings inside real names ("backtesting.py") are not.
_EXCLUDE_DIR_EXACT = {".venv", "venv", "env", "node_modules", "site-packages",
                      "dist", "build", "examples", "example", "samples", "sample",
                      "demo", "demos", "docs", "doc", "fixtures", "fixture",
                      "mocks", "mock", "conftest"}


def _is_excluded_path(py: Path, root: Path) -> bool:
    for part in py.relative_to(root).parts:
        pl = part.lower()
        stem = pl[:-3] if pl.endswith(".py") else pl
        if pl in _EXCLUDE_DIR_EXACT:
            return True
        if pl == "test" or pl == "tests" or pl.endswith("tests") or pl.endswith("_test"):
            return True
        if stem.startswith(("test_", "_test", "tests_", "mock_", "mock", "conftest")):
            return True
    return False


def extract_repo(meta: RepoMeta, max_tools: int) -> list[ExtractedTool]:
    assert meta.path is not None
    found: list[ExtractedTool] = []
    seen: set[tuple[str, str]] = set()  # (name, handler) dedup within repo
    for py in sorted(meta.path.rglob("*.py")):
        if _is_excluded_path(py, meta.path):
            continue
        for tool in extract_tools_from_file(py, str(py.relative_to(meta.path))):
            key = (tool.name, tool.handler)
            if key in seen:
                continue
            seen.add(key)
            found.append(tool)
            if len(found) >= max_tools:
                return found
    return found


# ---------------------------------------------------------------------------
# Entry assembly
# ---------------------------------------------------------------------------

def _classify_tripwire(handler: str) -> tuple[str, str]:
    for pattern, cosai, attack_type in _TRIPWIRE_HEURISTIC:
        if re.search(pattern, handler):
            return cosai, attack_type
    return _DEFAULT_TRIPWIRE


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").upper()


def build_entry(meta: RepoMeta, tool: ExtractedTool, now: datetime) -> tuple[dict, dict]:
    cosai, attack_type = _classify_tripwire(tool.handler)
    entry_id = f"BENMINED-{_slug(meta.full_name)}-{_slug(tool.name)}"
    attack_vector = json.dumps({
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "handler": tool.handler,
    }, indent=2)
    notes = (
        f"mined_benign from {meta.full_name}@{meta.commit[:10]} "
        f"({meta.rel_path if hasattr(meta, 'rel_path') else tool.rel_path}:{tool.lineno}); "
        f"license={meta.license}; stars={meta.stars}. "
        f"cosai_category is the NEAREST TRIPWIRE FAMILY (likely-to-fire detector), "
        f"NOT a threat label — this entry is benign and pending the Phase-3 validity gate."
    )
    entry = CorpusEntry(
        id=entry_id,
        cosai_category=cosai,
        mitre_technique_id="N/A (benign)",
        attack_vector=attack_vector,
        attack_type=attack_type,
        expected_verdict="allow",
        source="mined",
        obfuscation_level="none",
        cve_reference=None,
        expected_detection_signal=None,
        created_at=now,
        created_by="claude_code",
        parent_id=None,
        review_status="draft",
        labeling_notes=notes,
    )
    manifest = {
        "id": entry_id,
        "repo": meta.full_name,
        "url": meta.url,
        "commit": meta.commit,
        "license": meta.license,
        "stars": meta.stars,
        "path": tool.rel_path,
        "lineno": tool.lineno,
        "tool_name": tool.name,
    }
    return entry.model_dump(mode="json"), manifest


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _repos_from_clones(workdir: Path) -> list[RepoMeta]:
    repos: list[RepoMeta] = []
    if not workdir.exists():
        return repos
    for d in sorted(p for p in workdir.iterdir() if p.is_dir()):
        full = d.name.replace("__", "/")
        try:
            sha = subprocess.run(
                ["git", "-C", str(d), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
        except Exception:
            sha = ""
        repos.append(RepoMeta(full_name=full, url=f"https://github.com/{full}",
                              commit=sha, path=d, license="(local)"))
    return repos


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--search", type=str, default=None,
                   help='GitHub repo search query, e.g. "mcp server language:python stars:>20"')
    p.add_argument("--repos-file", type=str, default=None,
                   help="File with one owner/name per line (skips search)")
    p.add_argument("--from-clones", action="store_true",
                   help="Skip search/clone; extract from repos already under --workdir")
    p.add_argument("--max-repos", type=int, default=60)
    p.add_argument("--max-tools-per-repo", type=int, default=3)
    p.add_argument("--workdir", type=Path, default=WORKDIR)
    p.add_argument("--out", type=Path, default=OUT_DRAFT)
    p.add_argument("--allow-any-license", action="store_true",
                   help="Do not filter by license (NOT for the released corpus)")
    args = p.parse_args()

    args.workdir.mkdir(parents=True, exist_ok=True)
    stats = MineStats()

    # ---- resolve repo set -------------------------------------------------
    if args.from_clones:
        repos = _repos_from_clones(args.workdir)
    elif args.repos_file:
        names = [ln.strip() for ln in Path(args.repos_file).read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]
        repos = [RepoMeta(full_name=n, url=f"https://github.com/{n}") for n in names[:args.max_repos]]
    elif args.search:
        print(f"[search] {args.search!r} (limit {args.max_repos})", file=sys.stderr)
        repos = search_repos(args.search, args.max_repos)
    else:
        p.error("provide one of --search, --repos-file, or --from-clones")

    print(f"[repos] {len(repos)} candidate(s)", file=sys.stderr)

    # ---- clone + extract --------------------------------------------------
    entries: list[dict] = []
    manifest: list[dict] = []
    now = datetime.now(timezone.utc)

    for meta in repos:
        stats.repos_seen += 1
        if not args.from_clones and not args.allow_any_license:
            if meta.license and meta.license not in PERMISSIVE_LICENSES:
                stats.repos_skipped_license.append(f"{meta.full_name} ({meta.license or 'none'})")
                print(f"  [skip lic] {meta.full_name} ({meta.license or 'none'})", file=sys.stderr)
                continue
        try:
            if not args.from_clones:
                meta = clone_repo(meta, args.workdir)
        except subprocess.CalledProcessError as exc:
            print(f"  [clone fail] {meta.full_name}: {exc.stderr.strip()[:120]}", file=sys.stderr)
            continue

        tools = extract_repo(meta, args.max_tools_per_repo)
        if not tools:
            stats.repos_no_tools.append(meta.full_name)
            print(f"  [no tools] {meta.full_name}", file=sys.stderr)
            continue
        for tool in tools:
            entry, man = build_entry(meta, tool, now)
            entries.append(entry)
            manifest.append(man)
            stats.tools_extracted += 1
        print(f"  [ok] {meta.full_name}: {len(tools)} tool(s)", file=sys.stderr)

    # ---- dedup across repos (identical name+handler) ----------------------
    seen: set[tuple[str, str]] = set()
    used_ids: set[str] = set()
    deduped_entries, deduped_manifest = [], []
    for e, m in zip(entries, manifest):
        av = json.loads(e["attack_vector"])
        key = (av["name"], av["handler"])
        if key in seen:
            stats.tools_deduped += 1
            continue
        seen.add(key)
        # Guarantee unique ids: two distinct tools sharing name+repo (different
        # handlers) would otherwise collide and silently collapse downstream.
        if e["id"] in used_ids:
            n = 2
            while f"{e['id']}-{n}" in used_ids:
                n += 1
            e["id"] = m["id"] = f"{e['id']}-{n}"
        used_ids.add(e["id"])
        deduped_entries.append(e)
        deduped_manifest.append(m)

    args.out.write_text(json.dumps(deduped_entries, indent=2) + "\n")
    OUT_MANIFEST.write_text(json.dumps(deduped_manifest, indent=2) + "\n")

    # ---- report -----------------------------------------------------------
    print("\n=== mine summary ===", file=sys.stderr)
    print(f"  repos seen           : {stats.repos_seen}", file=sys.stderr)
    print(f"  skipped (license)    : {len(stats.repos_skipped_license)}", file=sys.stderr)
    print(f"  repos with no tools  : {len(stats.repos_no_tools)}", file=sys.stderr)
    print(f"  tools extracted      : {stats.tools_extracted}", file=sys.stderr)
    print(f"  deduped (dropped)    : {stats.tools_deduped}", file=sys.stderr)
    print(f"  benign entries       : {len(deduped_entries)}", file=sys.stderr)
    print(f"  -> {args.out.relative_to(ROOT)}", file=sys.stderr)
    print(f"  -> {OUT_MANIFEST.relative_to(ROOT)}", file=sys.stderr)
    print("\nNEXT: Phase 3 validity gate — screen the draft for live sinks and "
          "quarantine anything actually exploitable before locking "
          "(a real vuln is a TRUE positive, not an FP).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
