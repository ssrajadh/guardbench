# Taxonomy mapping: CoSAI ↔ MCPSecBench ↔ Zhao et al.

Cross-walks CoSAI T1–T12 against the MCPSecBench 17-attack taxonomy
(arXiv:2508.13220) and the Zhao et al. 12-category component taxonomy
(arXiv:2509.24272). Used to drive test-case generation: any CoSAI row
with a non-empty **Gaps** column needs synthetic cases because neither
academic taxonomy covers it end-to-end.

CoSAI categories (working definitions used here):
T1 direct prompt injection · T2 indirect prompt injection / context
manipulation · T3 input-validation failures in tool arguments · T4
supply chain / component integrity · T5 egress / SSRF · T6 insecure
design & defaults · T7 denial of service · T8 model/training-data
poisoning · T9 data exfiltration · T10 authN/session failures · T11
logging & monitoring gaps · T12 secrets & secure configuration.

## Table 1 — CoSAI rows

| CoSAI | MCPSecBench types | Zhao et al. categories | Gaps (needs synthetic) |
|---|---|---|---|
| T1 Direct prompt injection | Prompt Injection | — | Zhao omits user-origin injection; synthesize direct-injection probes against MCP hosts. |
| T2 Indirect prompt injection | Indirect Prompt Injection; Tool Shadowing; Tool Poisoning; Confused AI¹ | A1 Server Metadata Poisoning; A4 Tool Metadata Poisoning; A7 Resource Metadata Poisoning; A10 Prompt Metadata Poisoning; A6/A9/A12 Output Attacks² | — |
| T3 Input validation | Sandbox Escape; Vulnerable Server³; Vulnerable Client³ | A5 Tool Logic Attack; A8 Resource Logic Attack; A11 Prompt Logic Attack | — |
| T4 Supply chain | Rug Pull; Package Name Squatting (tool); Package Name Squatting (server) | A2 Server Configuration Abuse⁴; A3 Initialization Logic Attack | Neither paper covers *dependency-level* squatting (e.g., typosquatted npm deps inside an MCP server) — synthesize. |
| T5 Egress / SSRF | Data Exfiltration⁵ | A6 Tool Output Attack⁵; A9 Resource Output Attack⁵ | Classic server-side SSRF (fetching URLs the attacker supplies) is underrepresented — synthesize from CVE-2026-26118 / CVE-2026-27826. |
| T6 Insecure design & defaults | Schema Inconsistencies; Configuration Drift | A2 Server Configuration Abuse | — |
| T7 Denial of service | — | — | **Major gap.** Only CVE-2026-39313 touches this. Synthesize unbounded-body, unbounded-recursion, and tool-flood cases. |
| T8 Model / training-data poisoning | — | — | **Out of scope for both papers.** MCP is runtime-only; if we want coverage, synthesize prompt-library poisoning cases at the corpus level. |
| T9 Data exfiltration | Data Exfiltration; Tool Shadowing⁶ | A6 Tool Output Attack; A9 Resource Output Attack; A12 Prompt Output Attack | — |
| T10 AuthN / session failures | MCP Rebinding; Man-in-the-Middle; Slash Command Overlap⁷ | A2 Server Configuration Abuse⁴ | Token-replay and stale-session attacks against streamable-HTTP transports — synthesize. |
| T11 Logging & monitoring gaps | — | — | **Gap in both taxonomies.** Synthesize cases where a guardrail silently fails (e.g., tool invocation with no audit event). |
| T12 Secrets & secure configuration | Configuration Drift | A2 Server Configuration Abuse | Synthesize credential-in-env-var leakage and OAuth token mis-scoping cases (CVE-2026-31951 is the seed). |

## Table 2 — reverse direction (each attack → best-fit CoSAI)

### MCPSecBench (17)

| Attack type | Surface | Best-fit CoSAI |
|---|---|---|
| Prompt Injection | User interaction | T1 |
| Confused AI (tool misuse via adversarial chat) | User interaction | T2¹ |
| Schema Inconsistencies | Client | T6 |
| Slash Command Overlap | Client | T10⁷ |
| Vulnerable Client | Client | T3³ |
| MCP Rebinding | Transport | T10 |
| Man-in-the-Middle | Transport | T10 |
| Tool Shadowing Attack | Server | T2 (primary) / T9 (impact) |
| Data Exfiltration (via metadata) | Server | T9 |
| Package Name Squatting (tool) | Server | T4 |
| Indirect Prompt Injection | Server | T2 |
| Package Name Squatting (server) | Server | T4 |
| Configuration Drift | Server | T6 (primary) / T12 (when secrets-relevant) |
| Sandbox Escape | Server | T3 |
| Tool Poisoning | Server | T2 (attack surface) / T4 (if package-level)⁸ |
| Vulnerable Server | Server | T3³ |
| Rug Pull Attack | Server | T4 |

### Zhao et al. (12)

| Category | Component | Best-fit CoSAI |
|---|---|---|
| A1 Server Metadata Poisoning | Server | T2 |
| A2 Server Configuration Abuse | Server | T6 (primary) / T4⁴ / T10⁴ / T12⁴ — split per instance |
| A3 Initialization Logic Attack | Server | T4 |
| A4 Tool Metadata Poisoning | Tool | T2 |
| A5 Tool Logic Attack | Tool | T3 |
| A6 Tool Output Attack | Tool | T9 (primary) / T5⁵ (when channel abuse) |
| A7 Resource Metadata Poisoning | Resource | T2 |
| A8 Resource Logic Attack | Resource | T3 |
| A9 Resource Output Attack | Resource | T9 / T5⁵ |
| A10 Prompt Metadata Poisoning | Prompt | T2 |
| A11 Prompt Logic Attack | Prompt | T3 |
| A12 Prompt Output Attack | Prompt | T9 |

## Footnotes

¹ **Confused AI → T2.** MCPSecBench classes this under the user-interaction
surface, but the mechanism is *adversarial conversation manipulating tool
selection* — which is indirect injection routed through the agent loop,
not a direct injection into a filter. T2 fits; T1 would be wrong.

² **Output attacks double-count under T2 and T9.** A fabricated tool
return that *steers the next LLM turn* is T2; one that *leaks data the
user shouldn't see* is T9. Real attacks chain both — listed under T2 in
Table 1 because that's the attack vector, with T9 as the impact.

³ **"Vulnerable Server / Client" → T3.** Both are catch-all MCPSecBench
buckets for implementation bugs. The overwhelming majority of cataloged
CVEs in this class are input-validation flaws (shell/arg injection, path
traversal), so T3 is the right default. Specific CVEs that are auth or
config bugs should be re-tagged case-by-case.

⁴ **A2 Server Configuration Abuse is overloaded.** Zhao lumps launch
parameters, connection URLs, and persistence mechanisms into one
category. Map per-instance: malicious launch command → T4; unauth'd
URL → T10; env-var secrets exposure → T12; "the default is dangerous"
→ T6. Table 2 lists T6 as the headline call because it's the most
common manifestation.

⁵ **Tool/Resource Output Attacks → T5 only when channel-abuse.** If the
output contains a URL the agent is induced to fetch (turning the output
into an SSRF primitive), it's T5. If it just returns false data to the
user/LLM, it's T9.

⁶ **Tool Shadowing is T2 at the vector and T9 at the impact.** Listed
under both CoSAI rows in Table 1 deliberately — the shadowing is how
you get in, the exfiltration is what you get out.

⁷ **Slash Command Overlap → T10.** Arguably T6 (insecure design: the
client allows namespace collisions). Chose T10 because the exploitable
consequence is *an unauthorized tool runs as if the user authorized it*
— i.e., a session/authN authority-confusion flaw. T6 is the design root
cause; T10 is what a guardrail would actually detect.

⁸ **Tool Poisoning splits between T2 and T4.** If the poisoned tool
arrives via a legitimate install (rug pull, typosquat), T4. If it
arrives via a metadata edit on an already-installed tool, T2. The
MCPSecBench definition covers both; we route by install-time vs
runtime.
