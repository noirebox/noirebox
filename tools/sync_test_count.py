#!/usr/bin/env python3
"""One number, one command: sync the published test count everywhere.

The test count drifted three times in ten days (119 → 126 → 173 → …) because
it was hand-copied across seven documents. This script makes the count a
generated artifact: it asks pytest how many tests exist and patches the
known spots. Run it before any release and after any test addition —
`python tools/sync_test_count.py`.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (file, old, new) patterns; {n} is the collected test count.
SPOTS = [
    ("README.md", r"\b\d+ tests: cryptography", "{n} tests: cryptography"),
    ("README.fr.md", r"\b\d+ tests : cryptographie", "{n} tests : cryptographie"),
    ("CONTRIBUTING.md", r"\(\d+ tests\)", "({n} tests)"),
    ("docs/index.html", r"<strong>\d+</strong><span>tests green</span>",
     "<strong>{n}</strong><span>tests green</span>"),
    ("docs/index.html", r'<td class="m-val">\d+ green</td>', '<td class="m-val">{n} green</td>'),
    ("docs/fr.html", r"<strong>\d+</strong><span>tests verts</span>",
     "<strong>{n}</strong><span>tests verts</span>"),
    ("docs/fr.html", r'<td class="m-val">\d+ verts</td>', '<td class="m-val">{n} verts</td>'),
]


def collected_count() -> int:
    out = subprocess.run(
        [str(ROOT / ".venv/bin/pytest"), "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    match = re.search(r"(\d+) tests collected", out)
    if not match:
        sys.exit("could not parse pytest --collect-only output")
    return int(match.group(1))


def main() -> int:
    n = collected_count()
    changed = []
    for relpath, pattern, replacement in SPOTS:
        path = ROOT / relpath
        text = path.read_text(encoding="utf-8")
        new_text, count = re.subn(pattern, replacement.format(n=n), text)
        if count and new_text != text:
            path.write_text(new_text, encoding="utf-8")
            changed.append(f"{relpath}: {count} spot(s)")
    print(f"pytest collected: {n}")
    print("\n".join(changed) or "nothing to update — every spot already carries the count")
    return 0


if __name__ == "__main__":
    sys.exit(main())
