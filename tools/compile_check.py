#!/usr/bin/env python3
"""Compile every rules/**/*.yar file with yara-python; fail loudly on any syntax error."""
import sys
from pathlib import Path

import yara

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"


def main() -> int:
    rule_files = sorted(RULES_DIR.rglob("*.yar"))
    if not rule_files:
        print(f"No .yar files found under {RULES_DIR}")
        return 0

    failures = []
    for path in rule_files:
        rel = path.relative_to(ROOT)
        try:
            yara.compile(filepath=str(path))
        except yara.Error as exc:
            failures.append(f"{rel}: {exc}")
        else:
            print(f"OK   {rel}")

    if failures:
        print("\nCOMPILE FAILURES:")
        for f in failures:
            print(f"FAIL {f}")
        return 1

    print(f"\n{len(rule_files)} file(s) compiled cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
