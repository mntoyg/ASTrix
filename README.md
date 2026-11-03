# ASTrix

**Autonomous Code Remediator & AST Refactorer Engine**
Rust · tree-sitter · OmniBase Official

ASTrix finds security vulnerabilities (CVEs) in source code and fixes them by
rewriting the syntax tree, under a **zero-breakage policy**: a patch ships only
if it can be shown to preserve observable behaviour.

```rust
use astrix::Engine;
use astrix_core::{LanguageId, SourceFile};

let source = SourceFile::new(
    "app.py",
    LanguageId::Python,
    "import yaml\ncfg = yaml.load(raw)\n",
);

let outcome = Engine::new().remediate(&source)?;

assert_eq!(outcome.findings.len(), 1);
assert_eq!(
    outcome.patch.unwrap().rewritten,
    "import yaml\ncfg = yaml.safe_load(raw)\n",
);
```

---

## What "zero breakage" means here

It is not a review step. It is ten invariants with enforcement points in the
code:

* A **malformed file is never rewritten** — if the parser had to guess, span
  arithmetic cannot be trusted.
* **Spans are always original-buffer coordinates.** `SourceFile` is immutable
  and a script is applied in one forward pass, so no edit sees another edit's
  output.
* **Rules describe, they never mutate.** A rule returns an `EditScript`; only
  the rewriter produces text, and only after validating bounds, character
  boundaries and overlap.
* **Overlapping edits are an error**, never a silent drop. Dropping one rule's
  edit would ship a patch that remediates less than it reports.
* **An unattended fix needs both** an `Automatic` rule and a `Certain` match. A
  rule allowed to act alone still never acts on a guess.
* **A patch is a proposal.** Nothing is written to disk until a gate accepts it.
* **"Not verified" is never reported as "safe."** The gate has three verdicts —
  `Accepted`, `Rejected`, `Inconclusive`.
* **Isolation strength is stated, never implied.** Every report carries the
  `IsolationLevel` its evidence came from.
* **Identical input yields a byte-identical patch and digest**, whatever order
  the rules ran in.

The full list, with enforcement points, is in
[`.claude/HANDOFF_PROTOCOL.md`](.claude/HANDOFF_PROTOCOL.md) §4.3.

---

## Crates

| Crate | Responsibility |
|---|---|
| [`astrix`](src/lib.rs) | the façade — wires the pipeline, exposes `Engine` |
| [`astrix-core`](crates/astrix-core) | contracts and value types. No parser, no I/O |
| [`astrix-parser`](crates/astrix-parser) | tree-sitter backends; the only crate that names `tree_sitter` |
| [`astrix-rules`](crates/astrix-rules) | CVE knowledge: rules and the registry |
| [`astrix-rewriter`](crates/astrix-rewriter) | deterministic span splicing |
| [`astrix-sandbox`](crates/astrix-sandbox) | the zero-breakage gate |

Three traits in `astrix-core` carry the whole design:

| Trait | Question it answers |
|---|---|
| `AstVisitor` | how is a tree traversed, deterministically? |
| `RemediationRule` | is this node vulnerable, and what is the smallest fix? |
| `AstMutator` | how does an edit script become new text, reproducibly? |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Pipeline

```text
SourceFile ─parse─▶ SyntaxTree ─rules─▶ [Finding + EditScript]
                         │                        │
                  require_well_formed        normalized
                         │                        ▼
                         ✗                      Patch ─gate─▶ Accepted
                   MalformedSyntax                           / Rejected
                                                             / Inconclusive
```

---

## Languages

| Language | Feature | State |
|---|---|---|
| Python | `lang-python` | grammar linked, 1 rule |
| JavaScript | `lang-javascript` | grammar linked, fixture only |

Adding a language is three edits: an optional grammar dependency, a `lang-*`
feature, and one arm in `astrix_parser::grammar::load`. Every rule written
against `AstNode` picks it up for free.

---

## Rules

| Rule | CVE / CWE | Severity | Autofix |
|---|---|---|---|
| `astrix.python.unsafe-yaml-load` | CVE-2017-18342 / CWE-502 | critical | automatic |

Backlog, as pending fixtures: `weak-hash-md5` (CWE-327),
`subprocess-shell-true` (CWE-78), `eval-of-json` (CWE-95).

---

## Development

```bash
cargo test --workspace
```

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

```bash
cargo fmt --all --check
```

The red half of the TDD loop — pending fixtures, **expected to fail**:

```bash
cargo test --workspace -- --ignored
```

Behaviour is pinned by fixture directories, not by test functions:

```text
tests/fixtures/<language>/[pending/]<case>/
  fixture.toml  input.<ext>  expected.<ext>
```

Adding a CVE means adding a directory. See
[`tests/fixtures/README.md`](tests/fixtures/README.md).

---

## Agent protocol

ASTrix is built by two agents with separated authority: Claude Code owns the
contracts, Codex owns implementations inside a task. The trajectory rules,
context isolation guidelines and frozen contracts are in
[`.claude/HANDOFF_PROTOCOL.md`](.claude/HANDOFF_PROTOCOL.md).

---

## Status

Day 1 foundation. 105 tests green, zero warnings under pedantic clippy, one
test intentionally red (the pending-fixture backlog). Known gaps are listed
explicitly in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §9 — among them
AST-shape verification, import lowering, isolation above `ProcessOnly`, and the
absence of a CLI.

## License

MIT — see [LICENSE](LICENSE).
