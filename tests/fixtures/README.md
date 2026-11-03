# Fixture suite

Every behaviour ASTrix claims is pinned by a directory here, not by a test
function. `../tdd_remediation_test.rs` discovers them, so adding a CVE means
adding a directory.

## Layout

```text
tests/fixtures/<language>/[pending/]<case>/
  fixture.toml     what the engine must report
  input.<ext>      the vulnerable source
  expected.<ext>   the source after remediation
```

`<ext>` is the language's primary extension (`py`, `js`, …), taken from
`LanguageId::primary_extension`. `pending/` is a convention for readability —
what actually makes a fixture pending is `status` in its manifest.

## Manifest schema

```toml
name = "yaml.load with no Loader argument"   # required: one line, human-readable
language = "python"                          # required: LanguageId::as_str
status = "implemented"                       # required: implemented | pending
rule = "astrix.python.unsafe-yaml-load"      # required when expected_findings > 0
cves = ["CVE-2017-18342"]                    # optional: every one must be cited
cwes = ["CWE-327"]                           # optional: CWE-<digits>
severity = "critical"                        # optional: low|medium|high|critical
expected_findings = 1                        # required
expected_confidence = "certain"              # required when expected_findings > 0
expect_patch = true                          # required
notes = """                                  # required: why this fixture exists
Prose explaining what the case covers and what makes the rewrite safe.
"""
```

Unknown keys are rejected, so a typo in a manifest fails the suite rather than
being silently ignored.

### Consistency rules the harness enforces

* `status` is `implemented` or `pending`.
* `expected_findings > 0` requires both `rule` and `expected_confidence`.
* `expected_findings == 0` forbids `expect_patch`.
* `expect_patch` must agree with whether `expected.*` actually differs from
  `input.*`.
* `notes` cannot be empty — a fixture that does not say why it exists is a
  fixture nobody can maintain.
* `input.*` must parse cleanly. A fixture input is valid source that happens to
  be vulnerable, never broken source.

## Red and green

`status = "implemented"` fixtures run on every `cargo test`.

`status = "pending"` fixtures describe rules that have not been written yet.
Their assertions live in an `#[ignore]`d test:

```bash
cargo test --test tdd_remediation_test -- --ignored
```

That command is **expected to fail** — it is the red half of the TDD loop. The
always-on `pending_fixtures_name_a_rule_that_is_not_registered_yet` fails if
someone registers a pending rule without promoting its fixture, so the backlog
cannot go stale.

Promoting a fixture is a one-line change: `status = "pending"` becomes
`status = "implemented"`.

## Suite-wide properties

Beyond the per-fixture manifest, the harness asserts across every implemented
fixture that:

* remediation produces **exactly** `expected.*`, byte for byte;
* the resulting patch is accepted by the zero-breakage gate;
* remediation is **idempotent** — a second pass finds nothing left to fix;
* remediation is **reproducible** — two identical runs agree completely;
* `analyze` never mutates its input.

## Kinds of fixture to ship with a rule

A rule is not done until it has all three, where they apply:

| Kind | Proves |
|---|---|
| positive | the vulnerability is found and fixed exactly |
| negative | already-safe code is left byte-for-byte alone |
| uncertainty | an unprovable match is reported but **not** rewritten |

The negative fixture is the one that matters most: a tool that rewrites safe
code is a breakage, not a remediation.

## Current contents

| Fixture | Status | Covers |
|---|---|---|
| `python/cve-2017-18342-missing-loader` | implemented | the CVE default: `load` with no `Loader` |
| `python/cve-2017-18342-unsafe-loader-kwarg` | implemented | an explicitly unsafe `Loader=` |
| `python/cve-2017-18342-aliased-import` | implemented | `import yaml as y` still proves the receiver |
| `python/cve-2017-18342-several-call-sites` | implemented | three findings merged into one pass |
| `python/safe-load-is-left-alone` | implemented | negative control |
| `python/unproven-receiver-is-deferred` | implemented | tentative match reported, not rewritten |
| `python/pending/weak-hash-md5` | pending | CWE-327 weak digest |
| `python/pending/subprocess-shell-true` | pending | CWE-78 shell injection |
| `javascript/pending/eval-of-json` | pending | CWE-95, and the first second-language fixture |
