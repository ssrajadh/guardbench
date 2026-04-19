"""Archive every source_url in cve_catalog.json via the Wayback Machine.

Uses the Wayback "Save Page Now" endpoint:
    https://web.archive.org/save/<url>

Writes the resulting archive URL (from the ``Content-Location`` header, or
a reconstructed ``https://web.archive.org/web/<ts>/<url>`` if SPN2 is used)
back into a sibling file ``cve_catalog.archived.json`` so the original
catalog stays pristine and the archive mapping lives next to it.

Re-running is safe: already-archived URLs are re-saved (Wayback dedupes on
its side within a short window) and the output file is rewritten.

Usage:
    python -m guardbench.corpus.sources.archive_sources
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from guardbench.corpus.sources.cve_catalog import load_catalog

_SPN_ENDPOINT = "https://web.archive.org/save/"
_TIMEOUT_S = 60
_SLEEP_BETWEEN_REQUESTS_S = 6  # be polite; SPN rate-limits aggressively
_OUT_PATH = Path(__file__).parent / "cve_catalog.archived.json"


def archive_url(url: str) -> str | None:
    """Submit ``url`` to Wayback's Save Page Now; return the archived URL."""
    req = urllib.request.Request(
        _SPN_ENDPOINT + url,
        headers={"User-Agent": "guardbench-archiver/0.1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            content_location = resp.headers.get("Content-Location")
            if content_location:
                return "https://web.archive.org" + content_location
            final = resp.geturl()
            if "/web/" in final:
                return final
            return None
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"  ! failed: {exc}")
        return None


def main() -> None:
    records = load_catalog()
    out: list[dict] = []
    for i, r in enumerate(records, 1):
        print(f"[{i}/{len(records)}] {r.cve_id}  {r.source_url}")
        archived = archive_url(r.source_url)
        if archived:
            print(f"           -> {archived}")
        else:
            print("           -> (no archive URL returned)")
        entry = r.to_dict()
        entry["archived_url"] = archived
        entry["archived_at"] = int(time.time())
        out.append(entry)
        time.sleep(_SLEEP_BETWEEN_REQUESTS_S)

    _OUT_PATH.write_text(json.dumps(out, indent=2) + "\n")
    n_ok = sum(1 for e in out if e["archived_url"])
    print()
    print(f"Wrote {_OUT_PATH}  ({n_ok}/{len(out)} archived)")


if __name__ == "__main__":
    main()
