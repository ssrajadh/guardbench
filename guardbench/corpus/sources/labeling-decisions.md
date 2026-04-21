# CVE catalog labeling decisions

Rationale for every non-obvious call made while labeling `cve_catalog.json`.
Future reviewers: if you disagree, edit the entry *and* append a dated note
here so the audit trail survives.

## Dropped entries

- **CVE-2025-59536** (Claude Code project-level hooks). Dropped because the
  hook mechanism is a Claude Code feature, not part of the MCP protocol or
  any MCP server/client/proxy. Including it would inflate the catalog with
  a vuln class the benchmark can't attribute to an MCP guardrail.

All other entries were retained: each names a concrete MCP component
(server, client, SDK, proxy, or MCP integration) and the payload_summary
is specific enough to render into a TestCase.

## Resolved ambiguous labels

### CVE-2026-23744 — MCPJam Inspector
- **Decision:** `root_cause=auth_bypass`, `cosai_suggested_category=T6`.
- **Why:** The proximate cause is "critical endpoint bound to 0.0.0.0 with
  no authN middleware." The RCE is the *impact*; the auth bypass is the
  *cause*. T6 (insecure defaults) is preferred over T3 because no input
  validation would have saved this — the endpoint shouldn't exist
  unauthenticated.

### CVE-2026-25536 — MCP TypeScript SDK cross-client leak
- **Decision:** `root_cause=other`, `cosai_suggested_category=T9`.
- **Why:** Session/response-routing defects don't cleanly fit any of the
  five named root causes (not injection, not traversal, not auth, not
  poisoning, not SSRF). Kept as `other`. T9 (data exfiltration) is
  unambiguous on the impact side: one tenant reads another's responses.

### CVE-2026-30625 — Upsonic task-creation RCE
- **Decision:** `root_cause=shell_injection`, `cosai_suggested_category=T3`.
- **Why:** T3 (input validation) wins over T6 (insecure design) because
  the benchmark can exercise this with a single malicious task payload —
  that's the definition of a T3 test case. The T6 framing ("maybe the
  whole feature shouldn't exist") is not testable from a guardrail
  perspective.

### CVE-2026-35402 — Neo4j mcp-neo4j-cypher
- **Decision:** `root_cause=ssrf`, `cosai_suggested_category=T5`.
- **Why:** The CVE describes dual impact (SSRF + data modification) but
  the guardrail-relevant surface is the SSRF: an MCP guardrail can inspect
  outbound URLs, it cannot meaningfully police Cypher write semantics.
  T5 (output/egress controls) matches what a defender can actually block.

### CVE-2026-21852 — Claude Code enableAllProjectMcpServers
- **Decision:** `root_cause=auth_bypass`, `cosai_suggested_category=T4`.
- **Why:** The flag short-circuits the user-consent step (an auth control),
  but the exploitation vector is a committed `.mcp.json` in a shared repo,
  which is textbook supply-chain (T4). T4 > T6 because the benchmark
  should test whether guardrails detect *malicious project configs*, not
  whether the IDE's default is safe.

## Draft-batch review (2026-04-21, `cve_derived_draft.json`)

Walked all 40 generated draft entries against the CVE catalog and the
attack_vector each entry embodies. Recording non-trivial decisions here.

### Rejected entries

- **CVEDERIVED-202633032-B** (`list_sites`, nginx-ui MCPwn): handler body
  is only a comment pointing back to variant A (`rewrite_nginx_config`).
  A reviewer reading this in isolation can't judge the vulnerability;
  there's no novel test content beyond what A already provides.
- **CVEDERIVED-202633989-B** (`record_screen`, mobile-mcp): mechanical
  duplicate of variant A (`capture_screen`) — identical parameter shape
  and identical handler pattern with only the function name changed.
  Adds zero coverage.

### Relabeled entries

- **CVEDERIVED-20256514-B**: T4 → **T3**. The parent CVE (mcp-remote) is
  catalogued as T4 because its *threat model* is "a malicious remote
  server operator compromises the client." Variant A (`connect_remote_mcp`)
  correctly models that: the mechanism is shell injection, but the
  guardrail should decide whether to *trust the URL source* — T4. Variant
  B (`add_remote_server_config`) is different: its mechanism is newline
  injection into a persisted config file written from user input. That's
  a straightforward T3 (input-validation-on-persistence) test case,
  independent of supply-chain trust. Splitting the label per-variant
  captures the two distinct guardrail surfaces the CVE actually presents.

### Kept-as-generated with explicit justification

- **CVEDERIVED-20256514-A** stays T4 despite the handler being shell
  injection. At the code level it's T3; at the guardrail level the
  interesting question is "should the agent have trusted this URL at
  all" — that's T4. Prefer the question a guardrail can actually answer.
- **CVEDERIVED-202625536-A** stays T9. The attack_vector is a
  descriptive-comment handler (session-routing flaw, no concrete payload).
  This is the right shape for this CVE class — there is no "one input"
  that triggers the cross-client leak; it's emergent across requests.
  Noted so future reviewers don't strip it for being "too abstract."

## General labeling heuristics (applied across the catalog)

1. **Prefer the label a guardrail can act on.** If both T3 and T6 fit,
   pick T3 — a guardrail can inspect input, it can't rewrite an API.
2. **Root cause = proximate mechanism, not ultimate impact.** A missing
   authN check that leads to RCE is `auth_bypass`, not `shell_injection`.
3. **MITRE techniques are suggestive, not authoritative.** We map to the
   most specific sub-technique we're confident about; ambiguous cases get
   the parent technique (e.g., T1059 over T1059.004).
4. **CVEs from before 2026-01-01** are included only when explicitly
   referenced as foundational in the Jan-Feb 2026 "30 CVEs in 60 Days"
   writeup (CVE-2025-49596, CVE-2025-6514, CVE-2025-54136, plus the
   three Anthropic mcp-server-git CVEs disclosed in Jan 2026 under 2025
   numbers).
