# Cyberkarta YARA Rules

Open-source YARA detection rules, written and maintained by the Cyberkarta team.

## Scope

Every rule in this repository is **original work, written by the team from real
analysis** — not copied or aggregated from other organizations' rule sets. We read other
public projects (Yara-Rules/rules, Neo23x0/signature-base, etc.) for naming/style
inspiration, but we don't vendor their content in. If a rule here looks similar to one
elsewhere, it was independently derived from our own sample analysis, not copied.

Rules are organized by category under `rules/<category>/`. The category taxonomy isn't
fixed in advance — it grows as real rules get added.

## License

**[Detection Rule License (DRL) 1.1](LICENSE).** In short: you can use, modify,
redistribute, and even sell these rules commercially, with no copyleft obligation on your
own code. The one condition: if your product *displays* detection results to users, it
must surface the rule author's name. Full legal text in [LICENSE](LICENSE).

## Rule format

Rules follow [Neo23x0's YARA Style Guide](https://neo23x0.github.io/YARA-Style-Guide/)
naming and metadata conventions. Every rule must include:

```yara
rule MAL_Linux_ExampleRuleName_20261118
{
    meta:
        author      = "Cyberkarta"
        date        = "2026-11-18"
        description = "Detects <specific behavior/characteristic>, observed in <context>"
        reference   = "internal sandbox analysis, task <id>" // or a public writeup URL
        license     = "DRL-1.1"
        hash        = "<sha256 of a sample this rule was built from, if applicable>"

    strings:
        $s1 = "..."

    condition:
        $s1
}
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full required-field list, naming
convention, and how rules get validated before merge.

## CI

Every pull request runs:
- **Compile check** (`tools/compile_check.py`) — every `rules/**/*.yar` file must compile
  cleanly via `yara-python`.
- **Metadata/naming lint** (`tools/lint_meta.py`) — required `meta:` fields present,
  naming convention followed, no duplicate rule names repo-wide (YARA only enforces
  uniqueness per-file at compile time, not across files, so this catches a real gap).

VirusTotal YARA-CI (automated false-positive testing against a goodware corpus) is a
planned future addition, not yet wired up.

## Contributing

This repo is open source and public to read. **Contribution (merging changes) is
internal-to-the-team only for now** — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
branch/PR workflow. Opening up to public pull requests is a decision for later, once our
own conventions have proven out.
