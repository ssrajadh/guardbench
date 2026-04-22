"""Hard-review pass over the benign draft.

Per-entry question: 'Would I ship this in a real codebase?'  Four entries
fail that test and are rejected.  A handful more are reclassified to the
CoSAI detector family that would actually fire on the pattern — giving
coverage across 6 CoSAI categories (T2, T3, T4, T5, T7, T12) instead of
the original 4.

Audit trail lives in the REJECT / RELABEL tables below.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
DRAFT = ROOT / "guardbench/corpus/working/benign_draft.json"


REJECT: dict[str, str] = {
    "BEN-META-K8S-SA-TOKEN":
        "Tool returns the raw service-account token to the caller. In an MCP "
        "context the caller is a model/agent — handing it a bearer token is a "
        "credential exfiltration primitive, not a benign internal-metadata "
        "fetch. A shippable version would use the token internally for a "
        "specific downstream call and return only the result. As written I "
        "would not ship this; a reviewer would correctly block it.",

    "BEN-EVAL-REPORT-TEMPLATE":
        "Labelled 'sandboxed eval' but the handler uses jinja2.Environment, "
        "which is NOT sandboxed. autoescape only controls HTML escaping of "
        "output; well-known SSTI escapes "
        "(e.g. {{ self.__init__.__globals__ }}) still reach builtins. The "
        "sandbox-shaped version would use jinja2.sandbox.SandboxedEnvironment. "
        "As written this is a genuine RCE, not a false-positive stress test.",

    "BEN-HTMLCOMMENT-MD-SOURCE":
        "doc_id is interpolated into an HTML comment with no validation. A "
        "doc_id containing '-->' (or the UTF-8 variant) closes the comment "
        "early, letting caller-supplied text reach the rendered DOM — "
        "classic comment-breakout XSS. Shipping this unguarded would be a "
        "real bug, not a look-alike.",

    "BEN-REGEX-WORKSPACE-GREP":
        "subprocess.run(['rg', '--fixed-strings', pattern, root]) — a pattern "
        "starting with '-' is interpreted as a flag by rg (e.g. --files, "
        "--pre=CMD). The shippable version inserts '--' before pattern or "
        "uses '-e pattern'. As written this is argv-injection, not a "
        "correctly-scoped benign.",
}


# Reclassify entries to the CoSAI family whose scanner would actually fire.
# Widens surviving coverage from 4 to 6 CoSAI categories.
RELABEL: dict[str, tuple[str, str]] = {
    # env-var credential reads: secrets-management detectors are T12, not T9.
    "BEN-ENV-DB-CONNECT":
        ("T12", "Env-var credential reads are the canonical target of "
                "secret-management scanners (T12). T9 framed this as "
                "exfiltration impact, but the firing detector family is T12."),
    "BEN-ENV-SLACK-POST":
        ("T12", "Same reasoning: bearer-token read from env is a T12 "
                "secret-lifecycle signal, not a T9 exfil pattern."),
    "BEN-ENV-S3-UPLOAD":
        ("T12", "boto3 default credential chain consumes AWS_* env vars — "
                "the scanner surface is T12 secret management."),

    # dynamic entry-point loading and signed-artifact extraction are supply-
    # chain concerns; the firing detector family is T4.
    "BEN-DYNIMPORT-EXPORTER":
        ("T4", "importlib.metadata.entry_points loads code declared by "
               "installed packages — the scanner heuristic here is supply-"
               "chain / plugin-provenance (T4), not runtime code-exec (T3)."),
    "BEN-ARCHIVE-RELEASE-ARTIFACT":
        ("T4", "Signed-release verification is the textbook T4 control. "
               "The pattern the scanner sees is 'gpg.verify + extract' — "
               "a supply-chain integrity surface, not generic archive "
               "extraction."),

    # regex-with-timeout addresses ReDoS, which is T7 (application exhaustion).
    "BEN-REGEX-EVENT-FILTER":
        ("T7", "Restricted-DSL regex with an engine timeout is specifically "
               "the mitigation for catastrophic backtracking (ReDoS). The "
               "scanner family is T7 application DoS, not T3 injection."),
}


def main() -> int:
    entries = json.loads(DRAFT.read_text())
    ids = {e["id"] for e in entries}
    for did in (*REJECT, *RELABEL):
        if did not in ids:
            print(f"decision id not in draft: {did}", file=sys.stderr)
            return 1

    approved = rejected = relabeled = 0
    for e in entries:
        if e["id"] in RELABEL:
            new_cat, note = RELABEL[e["id"]]
            e["cosai_category"] = new_cat
            e["labeling_notes"] = f"relabel_note: {note} | {e['labeling_notes']}"
            relabeled += 1
        if e["id"] in REJECT:
            e["review_status"] = "reviewed"
            e["labeling_notes"] = (
                f"REJECTED during hard review: {REJECT[e['id']]} | "
                f"prior: {e['labeling_notes']}"
            )
            rejected += 1
        else:
            if e["review_status"] == "draft":
                e["review_status"] = "approved"
                approved += 1

    DRAFT.write_text(json.dumps(entries, indent=2) + "\n")
    print(f"benign draft updated: {approved} approved, {rejected} rejected, "
          f"{relabeled} relabeled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
