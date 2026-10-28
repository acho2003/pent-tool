#!/usr/bin/env python3
"""Refresh the embedded Next.js advisory snapshot from GitHub's advisory database.

Usage: runtime/update-nextjs-advisories.py [downloaded.json]

Without an argument the public GitHub advisories API is queried for the npm
package "next" (no credentials are sent). Review the diff of
internal/scanner/nextjs_advisories.json before committing, and bump
nextjsAdvisoriesVersion when it changes so stored plans are re-fingerprinted.
"""
import datetime
import json
import sys
import urllib.request
from pathlib import Path

API = "https://api.github.com/advisories?ecosystem=npm&affects=next&per_page=100"
OUT = Path(__file__).resolve().parent.parent / "internal" / "scanner" / "nextjs_advisories.json"


def fetch():
    advisories, url = [], API
    while url:
        request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            advisories.extend(json.load(response))
            url = None
            for part in response.headers.get("Link", "").split(","):
                if 'rel="next"' in part:
                    url = part[part.index("<") + 1:part.index(">")]
    return advisories


def main():
    raw = json.loads(Path(sys.argv[1]).read_text()) if len(sys.argv) > 1 else fetch()
    entries = []
    for advisory in raw:
        if advisory.get("withdrawn_at"):
            continue
        ranges = []
        for vulnerability in advisory.get("vulnerabilities") or []:
            package = vulnerability.get("package") or {}
            if package.get("ecosystem") != "npm" or package.get("name") != "next":
                continue
            ranges.append({"range": vulnerability["vulnerable_version_range"], "patched": vulnerability.get("first_patched_version") or ""})
        if not ranges:
            continue
        entries.append({
            "ghsa_id": advisory["ghsa_id"],
            "cve_id": advisory.get("cve_id") or "",
            "severity": advisory.get("severity") or "unknown",
            "summary": advisory.get("summary") or "",
            "url": advisory.get("html_url") or "",
            "cwes": [c["cwe_id"] for c in advisory.get("cwes") or [] if c.get("cwe_id")],
            "published": (advisory.get("published_at") or "")[:10],
            "ranges": ranges,
        })
    entries.sort(key=lambda e: (e["published"], e["ghsa_id"]), reverse=True)
    snapshot = {"source": API, "retrieved": datetime.date.today().isoformat(), "advisories": entries}
    OUT.write_text(json.dumps(snapshot, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {len(entries)} advisories to {OUT}")


if __name__ == "__main__":
    main()
