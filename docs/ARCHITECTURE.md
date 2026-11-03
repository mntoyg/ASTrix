# ASTrix Architecture

**ASTrix** — Autonomous Code Remediator & AST Refactorer Engine
OmniBase Official · Rust + tree-sitter

ASTrix finds security vulnerabilities in source code and fixes them by
rewriting the syntax tree, under a **zero-breakage policy**: a patch ships only
if it can be shown to preserve observable behaviour.

---

## 1. The problem this shape solves

Most autofix tools fail in one of three ways:

1. **Regex rewriting** — fast, and wrong as soon as the pattern appears in a
   string, a comment, or a different scope.
2. **Whole-file reformatting** — the fix is correct but the diff is
   unreviewable, so nobody merges it.
3. **Optimistic application** — the fix is applied and *then* someone finds out
   it changed behaviour.

ASTrix answers each with a structural decision, not a heuristic:

| Failure | Answer |
|---|---|
| regex false positives | matching happens on AST nodes with proven receivers |
| unreviewable diffs | an edit is the smallest span that fixes the issue |
| optimistic application | a patch is a proposal until a gate accepts it |

---

## 2. Crate layout

```text
astrix                     the façade — wires the pipeline, exposes Engine
│
├── astrix-core            contracts and value types. No parser, no I/O.
│                          Depends only on thiserror.
├── astrix-parser          tree-sitter backends. The only crate that names
│                          tree_sitter. One grammar per lang-* feature.
├── astrix-rules           CVE knowledge: rules and the registry.
│                          No filesystem, no processes.
├── astrix-rewriter        byte splicing. Knows spans, not CVEs.
└── astrix-sandbox         the zero-breakage gate. No grammars.
```

Dependencies point one way:

```text
          ┌─────────────────── astrix ───────────────────┐
          │           │             │            │       │
    astrix-parser  astrix-rules  astrix-    astrix-sandbox
          │           │          rewriter        │
          └───────────┴──────────────┴───────────┘
                             │
                        astrix-core
                             │
                        thiserror
```

### Why these five

The split is by *what would have to change*, not by what the code does:

* A new **grammar** should touch one crate → `astrix-parser`.
* A new **CVE** should touch one crate → `astrix-rules`.
* A change to how **text is produced** is a correctness-critical, CVE-agnostic
  concern → `astrix-rewriter`, where it can be tested exhaustively on spans
  alone.
* A change to how **safety is proven** must not be reachable from rule code →
  `astrix-sandbox`.
* Everything shared is a contract, not an implementation → `astrix-core`.

---

## 3. The three contracts

`astrix-core` defines three traits. Everything else is an implementation of one
of them.

### `AstVisitor` — traversal

```rust
pub trait AstVisitor<'tree> {
    type Node: AstNode<'tree>;
    type Output;
    fn enter(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> VisitFlow;
    fn leave(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>);
    fn finish(self, status: WalkStatus) -> Self::Output;
}
```

Visitors never recurse themselves. `astrix_core::walk` drives them from an
explicit stack, which buys two things: a fixed traversal order (pre-order,
children left to right), and immunity to stack exhaustion on deep trees.
A fixed order is what makes a rule's findings — and therefore the resulting
patch — reproducible.

`VisitFlow` has three values, not two: `Continue`, `SkipSubtree` (prune
children, still fire `leave`), and `Stop` (abort the walk).

### `RemediationRule` — CVE pattern matching

```rust
pub trait RemediationRule<'tree> {
    type Node: AstNode<'tree>;
    fn metadata(&self) -> &RuleMetadata;
    fn detect(&self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> Option<Finding>;
    fn remediate(
        &self,
        ctx: &VisitContext<'_, 'tree, Self::Node>,
        finding: &Finding,
    ) -> Result<EditScript>;
}
```

Detection and remediation are separate methods so a `DetectOnly` rule, or a
report-only run, never synthesises code it will not use.

`remediate` returns an `EditScript` and nothing else. A rule cannot produce
text, cannot touch the filesystem, and cannot see other rules' plans. That
restriction is what lets the engine validate, order, merge and reject every
proposed change before a byte moves.

**Confidence and autofix are orthogonal.** `AutofixPolicy` is a property of the
rule — *may this kind of rewrite ever run unattended?* `Confidence` is a
property of one match — *is this node really the pattern?* An unattended fix
needs both (`Remediation::is_unattended`), so a rule that is allowed to act
alone still never acts on a guess.

### `AstMutator` — deterministic rewriting

```rust
pub trait AstMutator {
    fn apply(&self, source: &SourceFile, script: &EditScript) -> Result<Patch>;
    fn apply_all(&self, source: &SourceFile, scripts: &[EditScript]) -> Result<Patch>;
}
```

The contract, enforced by `SpanRewriter`:

1. Every span is interpreted against the **input** buffer. The script is
   applied in one forward pass, so no edit can see another edit's output.
2. Out-of-bounds spans, spans that split a UTF-8 character, overlapping edits,
   and unresolved import requirements are errors. A rejected script produces no
   text at all.
3. The same `(source, script)` pair always yields the same buffer and the same
   SHA-256 digest, whatever order the rules ran in.

`AstNode` sits underneath all three as the backend-agnostic node view, so a
rule compiles against *nodes*, never against a grammar.

---

## 4. Pipeline

```text
          SourceFile  (immutable, language-tagged, line-indexed)
               │
   astrix-parser │  TreeSitterBackend::parse
               ▼
          SyntaxTree ──── require_well_formed ──✗──▶ MalformedSyntax
               │                                     (Z1: never rewrite a
               │                                      file the parser guessed at)
   astrix-rules │  RuleRegistry::remediate — one walk, every rule
               ▼
     [Finding + EditScript]
               │
               ├── Automatic + Certain ──────────┐
               └── anything else ──▶ deferred    │
                                                 ▼
   astrix-rewriter                      EditScript::normalized
                                        (sort, dedupe, reject overlap)
                                                 │
                                                 ▼
                                               Patch
                                     (original + rewritten + digest,
                                      in memory, nothing written)
                                                 │
   astrix-sandbox                        ZeroBreakageGate::verify
                                                 │
                           ┌─────────────────────┼─────────────────────┐
                           ▼                     ▼                     ▼
                       Accepted              Rejected            Inconclusive
                    (may be committed)    (discard patch)     (NOT a pass — the
                                                               gate could not
                                                               run a check)
```

### Stages

1. **Parse.** `SourceFile` is immutable and carries a precomputed line index,
   so byte↔row/column conversion is cheap and spans stay valid for the whole
   run. A tree with `ERROR` or `MISSING` nodes is refused outright.
2. **Scan.** `RuleRegistry` walks the tree once, offering each node to every
   rule whose metadata declares its language and its node kind. Findings are
   sorted into canonical order before they are returned.
3. **Plan.** Detection and planning share one traversal, so a rule always plans
   against the node it matched.
4. **Rewrite.** Scripts are merged, normalized and applied in one validated
   pass.
5. **Verify.** A gate runs the static checks, then the project's own tests, and
   returns the evidence.

---

## 5. Zero-breakage policy

The policy is carried by ten invariants, not by a review step. They are listed
with their enforcement point in
[`.claude/HANDOFF_PROTOCOL.md` §4.3](../.claude/HANDOFF_PROTOCOL.md).

Three of them deserve the extra words:

### Three verdicts, not two

`Verdict::Inconclusive` exists so that *"I could not verify this"* is never
reported as *"this is safe"*. A static-only gate asked for a test-suite check
returns `Inconclusive`, not `Accepted`. Collapsing those two facts is how a
zero-breakage policy quietly stops being one.

### Isolation is stated, never implied

Every `VerificationReport` carries the `IsolationLevel` its evidence was
gathered at — `None`, `ProcessOnly`, `WorkingTreeCopy` or `Container`. An
accepted patch therefore says how strong the proof behind it is, instead of
letting the reader assume the strongest.

### Static checks run first

`CommandGate` runs the in-memory checks before it stages anything on disk.
A patch known to be wrong is never written to the working tree — staging is the
only step in the gate with side effects, and it is guarded by an RAII restore
that fires on panic and on early return. The gate also refuses to stage over a
file whose content is not the buffer the patch was computed from.

---

## 6. Multi-language design

Nothing above `astrix-parser` knows a grammar exists.

```rust
// astrix-parser/src/grammar.rs — the entire language surface
pub fn load(language: LanguageId) -> Result<Language> {
    match language {
        #[cfg(feature = "lang-python")]
        LanguageId::Python => Ok(tree_sitter_python::LANGUAGE.into()),
        #[cfg(feature = "lang-javascript")]
        LanguageId::JavaScript => Ok(tree_sitter_javascript::LANGUAGE.into()),
        other => Err(AstrixError::UnsupportedLanguage(other)),
    }
}
```

Adding a language is three edits: an optional dependency, a `lang-*` feature,
and one arm here. `TsNode` already implements `AstNode`, so every rule written
against `AstNode` picks the new grammar up for free, and a deployment links
only the grammars it scans.

`LanguageId` is `#[non_exhaustive]`, so adding a language is a non-breaking
change for downstream matches.

`astrix-sandbox` stays grammar-free by taking a `SyntaxCheck` rather than a
parser; the façade supplies `astrix::syntax_check`, and a test supplies a stub.

---

## 7. TDD fixture suite

Behaviour is pinned by directories, not by test functions.

```text
tests/fixtures/<language>/[pending/]<case>/
  fixture.toml     what the engine must report
  input.<ext>      the vulnerable source
  expected.<ext>   the source after remediation
```

`tests/tdd_remediation_test.rs` discovers them. Adding a CVE means adding a
directory; no test function changes.

`status` in the manifest is the red/green marker:

* `implemented` — runs on every `cargo test`.
* `pending` — the fixture describes a rule nobody has written. Its assertions
  live in an `#[ignore]`d test, runnable with `cargo test -- --ignored`, and
  `pending_fixtures_name_a_rule_that_is_not_registered_yet` fails loudly if the
  rule ships without its fixture being promoted.

Alongside the per-fixture assertions, the harness enforces properties across
the whole suite: every input must parse cleanly, every patch must be accepted
by the gate, remediation must be idempotent and byte-for-byte reproducible, and
analysis must never mutate its input.

See [`tests/fixtures/README.md`](../tests/fixtures/README.md) for the manifest
schema.

---

## 8. Worked example

`astrix.python.unsafe-yaml-load` (CVE-2017-18342) shows every layer doing its
own job.

**Input**

```python
import yaml

def load_config(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.load(handle.read())
```

**Detect.** The rule declares `node_kinds = ["call"]`, so it only sees call
nodes. On each one it checks that `function` is an `attribute`, that
`attribute` is `load`, and that there is no safe `Loader=`. Then it walks to
the module root and looks for an import binding the receiver to `yaml` —
`import yaml` or `import yaml as y`. The import is what makes the finding
`Certain`; without one, the receiver might be any object with a `load` method
and the finding is `Tentative`.

**Plan.** One edit, replacing the four bytes of `load` with `safe_load`. Not
the call, not the receiver, not the argument list — the smallest span that
fixes the issue.

**Rewrite.** `SpanRewriter` validates the span, splices it, and digests the
result.

**Verify.** `StaticGate` confirms the displaced text was really `load`, that
something changed, and that the result still parses. `CommandGate` then stages
the candidate and runs the project's own tests.

**Output**

```python
import yaml

def load_config(path):
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle.read())
```

**Why this is safe.** `safe_load` and `load` agree on every document that uses
only standard YAML tags — which is every document that is not an exploit
attempt. They differ exactly where the vulnerability lives: a document carrying
a Python object tag. A project that legitimately depends on that behaviour
fails its own suite under the patch, and the gate rejects it rather than
shipping it. That is why this rule can be `Automatic` without the policy
becoming a guess.

---

## 9. Current state

| Component | State |
|---|---|
| `astrix-core` contracts | complete for Day 1; frozen |
| `astrix-parser` | Python and JavaScript grammars linked |
| `astrix-rules` | registry + `astrix.python.unsafe-yaml-load` |
| `astrix-rewriter` | complete |
| `astrix-sandbox` | `StaticGate`, `CommandGate` (`ProcessOnly` isolation) |
| fixtures | 6 implemented, 3 pending |
| gate | `fmt` clean, `clippy -D warnings` with pedantic clean, 105 tests green |

### Known gaps, deliberately left

* **`CheckKind::AstShapeStable`** is declared and always reported as skipped.
  Proving the rewritten tree differs from the original *only* inside edited
  spans needs a tree-diff; until it exists, the check honestly reports
  `Inconclusive` rather than quietly passing.
* **`ImportRequirement`** is modelled but not lowered into edits. The rewriter
  refuses a script that still declares one, so a rule that needs a new import
  fails loudly instead of emitting code that no longer resolves.
* **Isolation above `ProcessOnly`** — `WorkingTreeCopy` and `Container` are
  declared in `IsolationLevel` but no gate implements them yet.
* **No CLI.** The engine is a library; `astrix` exposes `Engine` and nothing
  else.
* **`CommandGate` timeout** is enforced by polling `try_wait`, and kills only
  the direct child. A test runner that spawns its own children can outlive the
  kill.
