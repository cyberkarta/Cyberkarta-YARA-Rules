#!/usr/bin/env python3
"""Lint rules/**/*.yar for required meta fields, naming convention, and
repo-wide duplicate rule names (YARA rule names are only unique per-file at
compile time, not across files, so this is NOT caught by compile_check.py)."""
import re
import sys
from pathlib import Path

import plyara

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"

REQUIRED_META = ["author", "date", "description", "reference", "license"]
NAME_PATTERN = re.compile(r"^(MAL|HKTL|WEBSHELL|SUSP|PUA)_[A-Za-z0-9_]+$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def meta_dict(rule: dict) -> dict:
    """plyara represents metadata as a list of single-key dicts; flatten it."""
    out = {}
    for entry in rule.get("metadata", []):
        for k, v in entry.items():
            out[k] = v
    return out


def main() -> int:
    rule_files = sorted(RULES_DIR.rglob("*.yar"))
    if not rule_files:
        print(f"No .yar files found under {RULES_DIR}")
        return 0

    errors = []
    seen_names = {}  # rule_name -> file it was first seen in

    for path in rule_files:
        rel = path.relative_to(ROOT)
        parser = plyara.Plyara()
        try:
            rules = parser.parse_string(path.read_text(encoding="utf-8"))
        except Exception as exc:  # plyara raises various lark/parser errors
            errors.append(f"{rel}: failed to parse for lint — {exc}")
            continue

        for rule in rules:
            name = rule.get("rule_name", "<unnamed>")
            where = f"{rel}:{name}"

            if name in seen_names:
                errors.append(
                    f"{where}: duplicate rule name, also defined in {seen_names[name]}"
                )
            else:
                seen_names[name] = str(rel)

            if not NAME_PATTERN.match(name):
                errors.append(
                    f"{where}: name doesn't match "
                    f"<CLASSIFIER>_<Platform>_<Description>_<Date> convention "
                    f"(classifier must be one of MAL/HKTL/WEBSHELL/SUSP/PUA)"
                )

            meta = meta_dict(rule)
            for field in REQUIRED_META:
                if not meta.get(field):
                    errors.append(f"{where}: missing required meta field '{field}'")

            if "date" in meta and not DATE_PATTERN.match(str(meta["date"])):
                errors.append(
                    f"{where}: meta.date '{meta['date']}' is not in YYYY-MM-DD format"
                )

            if meta.get("license") not in (None, "DRL-1.1"):
                errors.append(
                    f"{where}: meta.license is '{meta.get('license')}', expected 'DRL-1.1'"
                )

    if errors:
        print("LINT FAILURES:")
        for e in errors:
            print(f"FAIL {e}")
        return 1

    total_rules = len(seen_names)
    print(f"{len(rule_files)} file(s), {total_rules} rule(s) — all checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
