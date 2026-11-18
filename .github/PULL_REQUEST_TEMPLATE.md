## What

<!-- Which rule(s), what do they detect -->

## Checklist

- [ ] Rule is original (team's own analysis — see CONTRIBUTING.md "Sourcing new rules")
- [ ] Naming follows `<CLASSIFIER>_<Platform>_<Description>_<YYYYMMDD>`
- [ ] All required `meta:` fields present (`author`, `date`, `description`, `reference`, `license`)
- [ ] Ran `python tools/compile_check.py` locally — passes
- [ ] Ran `python tools/lint_meta.py` locally — passes
- [ ] Tested against a clean-file corpus for false positives — describe what below
- [ ] If built from a real sample: SHA256 included in `meta.hash`, and the sample/source noted in `meta.reference`

## False-positive test

<!-- What did you test against, and what was the result? e.g. "yara -w rule.yar /usr/bin/ — 0 matches" -->
