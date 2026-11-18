# Contributing

This repo is internal-contribution-only for now: anyone can read it, but only team
members merge changes. Opening to public PRs is a later decision.

## Workflow

Same flow as the sibling repo `Cyberkarta-Wazuh-Rule`:

1. `git checkout main && git pull origin main`
2. `git checkout -b feat/rule-<short-description>`
3. Add/edit files under `rules/<category>/` only. `tools/` and `.github/` changes get
   their own PR, don't mix them with rule additions.
4. Validate locally before pushing (see below).
5. Commit using **Conventional Commits**: `<type>(<scope>): <description>`
   - types: `feat`, `fix`, `docs`, `refactor`, `chore`, `test`
   - scopes: `rules`, `tools`, `ci`
   - example: `feat(rules): add MAL_Linux_ExampleRansomware_20261118`
6. Push and open a PR into `main`. CI runs the same two checks described below.

## Sourcing new rules

Rules must be **original** — written from the team's own analysis of a real sample, not
copied from another project. Two legitimate ways to get there:

- **Manual analysis**: static/dynamic analysis you did yourself, a unique string/opcode
  pattern/structural characteristic you identified.
- **Our internal dynamic-analysis sandbox** (details intentionally not published here —
  ask internally if you need access): detonate a sample, derive a rule from its actual
  runtime behavior/dropped artifacts/unpacked payload. Tooling there can draft a
  candidate rule automatically from string analysis — **treat any auto-generated draft
  as a starting point to review and rewrite, never copy-paste as final.** Review every
  string it picks individually: auto-generated drafts can include environment-specific
  artifacts (e.g. a path containing the analysis VM's own username) or common runtime
  library strings that aren't actually malware-specific, both of which cause false
  positives or false negatives if shipped unreviewed.

Either way: **always test for false positives** before submitting — run the rule against
a folder of known-clean files (e.g. `/usr/bin/` on a clean box) and confirm zero matches,
and note what you tested against in the PR description.

## Required rule format

Naming: `<CLASSIFIER>_<Platform>_<Description>_<YYYYMMDD>`, classifier one of `MAL`
(malware), `HKTL` (hacktool), `WEBSHELL`, `SUSP` (suspicious, lower confidence), `PUA`
(potentially unwanted). Example: `MAL_Windows_CobaltStrikeBeaconConfig_20261118`.

Required `meta:` fields (enforced by `tools/lint_meta.py`):

| Field | Required | Notes |
|---|---|---|
| `author` | always | `"Cyberkarta"` or `"Cyberkarta - <name>"` |
| `date` | always | `YYYY-MM-DD`, date the rule was written |
| `description` | always | what it detects and why — specific, not generic |
| `reference` | always | sandbox task ID, internal analysis note, or a public writeup URL |
| `license` | always | `"DRL-1.1"` |
| `hash` | when a sample exists | SHA256 of at least one sample this rule was validated against |

Condition structure (per the [YARA Style Guide](https://neo23x0.github.io/YARA-Style-Guide/)):
magic bytes/filesize checks first, then string logic, then any `not 1 of ($fp*)`
false-positive exclusions last.

## Validating locally before you push

```bash
pip install yara-python plyara   # one-time
python tools/compile_check.py    # fails loudly on any syntax error, file:line reported
python tools/lint_meta.py        # fails on missing meta fields, bad naming, duplicate names
```

Both scripts exit non-zero on any failure — the same two checks run in CI
(`.github/workflows/validate.yml`) on every PR.
