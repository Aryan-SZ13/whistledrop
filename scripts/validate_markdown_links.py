#!/usr/bin/env python3
"""
WhistleDrop First-Party Markdown Link Validator
Scans all first-party markdown files in the repository (excluding node_modules,
.venv, .git, and generated caches) and validates that all relative link targets
and embedded images exist on disk.
"""

import os
from pathlib import Path
import re
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
EXCLUDE_DIRS = {".venv", "node_modules", ".git", "dist", ".pytest_cache", ".tempmediaStorage"}


def scan_markdown_links() -> int:
    md_files = []
    for p in BASE_DIR.rglob("*.md"):
        if any(ex in p.parts for ex in EXCLUDE_DIRS):
            continue
        md_files.append(p)

    broken_links = []
    total_links = 0

    print("=" * 80)
    print("WHISTLEDROP FIRST-PARTY MARKDOWN LINK VALIDATION")
    print("=" * 80)

    for md in sorted(md_files):
        rel_md = md.relative_to(BASE_DIR)
        text = md.read_text(encoding="utf-8")
        # Match markdown links: [text](path) or ![alt](path)
        # Excludes external URLs (http/https), mailto, anchor-only links, and protocol schemes
        matches = re.findall(
            r"!?\[.*?\]\((?!https?://|mailto:|#|conversation:)(.*?)\)", text
        )

        file_links = 0
        for m in matches:
            clean = m.strip().split("#")[0].split("?")[0]
            if not clean:
                continue
            file_links += 1
            total_links += 1
            target = (md.parent / clean).resolve()
            if not target.exists():
                broken_links.append((str(rel_md), m, str(target)))

        print(f"  [OK] {rel_md} ({file_links} relative links verified)")

    print("-" * 80)
    print(f"Total markdown files scanned: {len(md_files)}")
    print(f"Total relative links checked:  {total_links}")

    if broken_links:
        print("\n[FAIL] Broken links detected:")
        for source, link, target in broken_links:
            print(f"  - In {source}: '{link}' -> resolved to missing: {target}")
        print("=" * 80)
        return 1

    print("\n[PASS] All first-party relative links and image paths are valid.")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(scan_markdown_links())
