"""Shallow-clones every repo listed in scoreboard/targets.txt, runs the
STATIC scanner only (never executes target code), and writes the results
to SCOREBOARD.md at the repo root. Run by .github/workflows/scoreboard.yml
on a weekly schedule.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcp_sentinel.scanner.static import scan_path

TARGETS_FILE = ROOT / "scoreboard" / "targets.txt"
OUTPUT_FILE = ROOT / "SCOREBOARD.md"


def _load_targets() -> list[tuple[str, str]]:
    targets = []
    for line in TARGETS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        url, name = line.split(maxsplit=1)
        targets.append((url, name))
    return targets


def _clone(url: str, dest: Path) -> bool:
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    return proc.returncode == 0


def main():
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for url, name in _load_targets():
            dest = Path(tmp) / name
            if not _clone(url, dest):
                rows.append((name, url, None, "clone failed"))
                continue
            result = scan_path(str(dest))
            rows.append((name, url, result, None))

    lines = [
        "# mcp-sentinel scoreboard",
        "",
        ("Auto-generated weekly by `.github/workflows/scoreboard.yml` — "
         "static scan only, target code is never executed. "
         "Nominate a server by adding it to `scoreboard/targets.txt`."),
        "",
        "| Server | Grade | Risk score | Critical | High | Medium | Low |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, url, result, error in rows:
        if error:
            lines.append(f"| [{name}]({url}) | — | — | — | — | — | {error} |")
            continue
        c = result.counts()
        lines.append(
            f"| [{name}]({url}) | {result.grade} | {result.risk_score}/100 "
            f"| {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} |"
        )

    OUTPUT_FILE.write_text("\n".join(lines) + "\n")
    print(f"Wrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
