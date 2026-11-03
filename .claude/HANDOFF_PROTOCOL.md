# ASTrix Handoff Protocol

**Status:** v1 — authoritative for Day 1 onward
**Parties:** Claude Code (*Architect*) ⇄ Codex (*Executioner*)
**Scope:** every change to this repository

This document is the contract between the two agents that build ASTrix. It
exists because the failure mode of a two-agent pipeline is not bad code — it is
*drift*: the Executioner solving a slightly different problem than the one the
Architect specified, and nobody noticing until the invariants are gone.

---

## 1. Roles and authority

| | Architect (Claude Code) | Executioner (Codex) |
|---|---|---|
| Owns | the contracts, the invariants, the crate boundaries | the implementation inside one task |
| Writes | `astrix-core`, trait signatures, `docs/`, this file, fixture manifests | rule bodies, backend bodies, test bodies |
| May add | a trait, a crate, a lint, a fixture | a rule, a grammar arm, a check, a test |
| May **not** | leave a task underspecified | change a trait signature, a crate boundary, or an invariant |
| Decides | *what* must be true | *how* to make it true |

**The authority rule.** If an assigned task cannot be completed without
changing something in the Architect's column, the Executioner stops and
escalates (§6). It does not "fix" the contract in passing. A task that needs a
contract change was mis-specified, and that is the Architect's defect to repair.

---

## 2. Trajectory rules

A **trajectory** is one unit of delegated work: one task, one branch, one
verified outcome. Trajectories are the only way work enters the repository.

### 2.1 Lifecycle

```text
SPEC ──▶ ACCEPT ──▶ RED ──▶ GREEN ──▶ PROVE ──▶ HAND BACK
 │         │         │        │          │           │
 │         │         │        │          │           └─ Architect reviews
 │         │         │        │          └───────────── full gate, output pasted
 │         │         │        └──────────────────────── minimum code to pass
 │         │         └───────────────────────────────── failing test, committed
 │         └─────────────────────────────────────────── restate scope, or escalate
 └───────────────────────────────────────────────────── Architect writes TASK block
```

### 2.2 Hard rules

1. **One trajectory, one concern.** A trajectory that touches two crates for
   two unrelated reasons is two trajectories. Split it before starting.
2. **Red before green.** The first commit of a trajectory adds a *failing*
   test. If the test passes on the first run, the test is wrong — it is not
   testing the behaviour being added.
3. **No scope widening.** A defect noticed outside the task boundary is
   reported in the hand-back, not fixed. Drive-by fixes make a review
   impossible to scope.
4. **No silent narrowing.** If part of the task turns out to be blocked,
   finish everything else and say exactly what was left and why. Deciding to
   ship less is the Architect's call.
5. **Green means green.** A trajectory is complete only when §5 passes with
   the output pasted into the hand-back. "Should pass" is not a result.
6. **Deterministic by construction.** Any change that makes output depend on
   iteration order, hash order, timestamps, locale or thread scheduling is
   rejected on sight. See §4.3.
7. **Fixtures are the spec.** Behaviour is pinned by a directory under
   `tests/fixtures/`, never by a test function the Executioner wrote to match
   its own implementation.

### 2.3 TASK block

Every trajectory starts with this, written by the Architect:

```markdown
## TASK <id>
**Goal:**        one sentence, observable from outside the code
**Crate(s):**    exactly which crates may be touched
**Files:**       the files expected to change; anything else needs escalation
**Contracts:**   trait signatures this task consumes — frozen for its duration
**Fixture(s):**  tests/fixtures/<path> — the acceptance criteria
**Done when:**   the literal commands that must pass
**Out of scope:** the adjacent things that look in scope but are not
```

A task without a fixture or without "Done when" is not a task. The Executioner
rejects it back to the Architect rather than guessing.

---

## 3. Context isolation

Two agents sharing one unbounded context is how invariants get re-litigated
every session. Context is therefore partitioned.

### 3.1 What each party reads

| Artifact | Architect | Executioner |
|---|---|---|
| `docs/ARCHITECTURE.md` | writes | reads, must not edit |
| `.claude/HANDOFF_PROTOCOL.md` | writes | reads, must not edit |
| `crates/astrix-core/src/**` | writes | **reads only** |
| the assigned crate's `src/**` | reviews | writes |
| `tests/fixtures/**/fixture.toml` | writes | **reads only** |
| `tests/fixtures/**/input.*`, `expected.*` | writes | reads only |
| `tests/tdd_remediation_test.rs` | writes | reads only |
| the other party's reasoning, notes, scratch files | — | — |

### 3.2 Isolation rules

1. **The repository is the only channel.** Nothing that matters lives in a
   conversation. If a decision changes behaviour, it lands in `docs/`, in a
   doc comment, or in a fixture manifest — in the same commit.
2. **No transcript archaeology.** The Executioner does not need, and does not
   get, the Architect's deliberation. The TASK block is complete by
   construction or it is defective.
3. **Fresh context per trajectory.** Each trajectory starts from the
   repository plus its TASK block. Carrying context between trajectories is
   how task N+1 inherits task N's wrong assumption.
4. **Read the whole file before editing it.** Never patch from a grep hit.
5. **Scratch stays out.** Intermediate scripts and exploratory output never
   enter the repository. `/target` and `.astrix-cache` are gitignored; nothing
   else temporary gets committed.
6. **Quote, do not paraphrase, a contract.** When a hand-back refers to a
   trait or an invariant, it quotes the signature. Paraphrase is where drift
   starts.

---

## 4. Architectural contracts

These are the invariants the engine is built on. They are not style
preferences; breaking one silently converts ASTrix from a remediation tool into
a code-corruption tool.

### 4.1 Frozen contracts

The three traits in `astrix-core` are **frozen**. Their signatures change only
by an Architect-authored trajectory that updates this document in the same
commit.

```rust
pub trait AstVisitor<'tree> {
    type Node: AstNode<'tree>;
    type Output;
    fn enter(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> VisitFlow;
    fn leave(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>);
    fn finish(self, status: WalkStatus) -> Self::Output;
}

pub trait RemediationRule<'tree> {
    type Node: AstNode<'tree>;
    fn metadata(&self) -> &RuleMetadata;
    fn supports(&self, language: LanguageId) -> bool;
    fn detect(&self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> Option<Finding>;
    fn remediate(
        &self,
        ctx: &VisitContext<'_, 'tree, Self::Node>,
        finding: &Finding,
    ) -> Result<EditScript>;
}

pub trait AstMutator {
    fn apply(&self, source: &SourceFile, script: &EditScript) -> Result<Patch>;
    fn apply_all(&self, source: &SourceFile, scripts: &[EditScript]) -> Result<Patch>;
}
```

### 4.2 Layering

Dependencies point one way. A `use` statement that violates this is rejected
without further review.

```text
astrix (façade)
  ├── astrix-parser ──┐
  ├── astrix-rules ───┤
  ├── astrix-rewriter ┼──▶ astrix-core   (depends on thiserror and nothing else)
  └── astrix-sandbox ─┘
```

* `astrix-core` depends on no other ASTrix crate, and on no parser.
* Only `astrix-parser` may name `tree_sitter`. A `tree_sitter` import anywhere
  else is a layering violation.
* `astrix-rules` never touches the filesystem and never spawns a process.
* `astrix-sandbox` never links a grammar; it takes a `SyntaxCheck` instead.
* `astrix-rewriter` knows bytes and spans, and nothing about CVEs.

### 4.3 The zero-breakage invariants

| # | Invariant | Enforced by |
|---|---|---|
| Z1 | A malformed file is never rewritten | `SyntaxTree::require_well_formed` |
| Z2 | Spans are always original-buffer coordinates | `SourceFile` is immutable; `Edit.span` is documented as original-buffer |
| Z3 | Rules describe, they never mutate | `remediate` returns `EditScript`; only `AstMutator` produces text |
| Z4 | Overlapping edits are an error, never a silent drop | `EditScript::normalized` |
| Z5 | Out-of-bounds and non-character-boundary spans are refused | `SourceFile::validate_span` |
| Z6 | An unattended fix needs an `Automatic` rule **and** a `Certain` match | `Remediation::is_unattended` |
| Z7 | A patch is a proposal; nothing is written until a gate accepts it | `Patch` holds both buffers; `Engine` never writes |
| Z8 | "Not verified" is never reported as "safe" | `Verdict::Inconclusive` |
| Z9 | Isolation strength is stated, never implied | `VerificationReport::isolation` |
| Z10 | Identical input yields a byte-identical patch and digest | `EditScript::normalized` + SHA-256 digest |

A trajectory that weakens any of Z1–Z10 is rejected regardless of what it
enables.

### 4.4 Extension points

Growth happens at these seams and nowhere else:

* **New language** → optional grammar dependency + `lang-*` feature + one arm
  in `astrix_parser::grammar::load`. Nothing else changes.
* **New rule** → implement `RemediationRule` in `astrix-rules/src/<language>/`,
  register it in that language's `register_all`, add a fixture directory.
* **New verification** → add a `CheckKind` and a gate. Never weaken an
  existing check to make a patch pass.
* **New backend** → implement `SyntaxBackend` and `AstNode`. Rules are
  unaffected.

### 4.5 Rule authoring requirements

Every rule must:

1. Fill in `RuleMetadata::equivalence_argument` — prose stating *why* the
   rewrite preserves observable behaviour, and naming the one case where it
   does not. An `Automatic` rule with an empty argument fails
   `every_automatic_rule_states_why_its_rewrite_preserves_behaviour`.
2. Narrow `node_kinds` to the kinds it can possibly match.
3. Return `Confidence::Certain` only when the AST alone proves the match.
   An import that proves a receiver is certain; a bare name that *looks* right
   is `Tentative`.
4. Produce the **smallest** edit that fixes the issue. Replace the attribute,
   not the call. Replace the loader, not the argument list. Minimal spans are
   what keep patches reviewable and merges clean.
5. Ship a positive fixture, a negative fixture (safe code that must not be
   touched), and an uncertainty fixture where one applies.

---

## 5. Verification gate

A trajectory is done when all of these pass, with output pasted into the
hand-back:

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

```bash
cargo test --workspace
```

```bash
cargo test --workspace -- --ignored
```

The last command is **expected to fail** while pending fixtures exist. The
hand-back states which pending fixtures failed and confirms the list is
unchanged from before the trajectory, unless the trajectory promoted one.

Additional rules:

* Zero warnings. Not "only pedantic warnings". Zero.
* A new `allow` attribute needs a one-line justification in the same commit.
* Never add `#[ignore]` to a test to make the suite pass. `#[ignore]` is
  reserved for pending fixtures and carries a `red:` reason string.

---

## 6. Escalation

Stop and hand back immediately, without writing code, when:

* the task cannot be done without changing a frozen contract (§4.1);
* the task cannot be done without breaking a layering rule (§4.2);
* making the fixture pass would weaken Z1–Z10 (§4.3);
* the fixture and the TASK block disagree;
* the "Done when" commands do not actually prove the goal;
* a rewrite that would pass the tests is still observably different from the
  original — a passing suite is evidence, not proof.

Escalation format:

```markdown
## ESCALATION <task id>
**Blocked on:** the contract, layer or invariant in the way
**Why:** two sentences, no more
**Needs:** the specific decision required
**Done anyway:** the parts of the task that are complete and committed
```

Escalating is the correct outcome, not a failure. A silently reinterpreted task
costs more than a blocked one.

---

## 7. Hand-back

```markdown
## HAND BACK <task id>
**Goal:**        restated in one sentence
**Changed:**     file list, with one line each on what and why
**Fixtures:**    added / promoted / unchanged
**Contracts:**   "unchanged" — or an escalation, never a silent edit
**Invariants:**  which of Z1–Z10 this touches, and how each still holds
**Gate:**        the four commands from §5, with their real output
**Pending:**     which pending fixtures still fail
**Noticed:**     out-of-scope defects seen but deliberately not fixed
```

---

## 8. Commit convention

```text
<crate>: <imperative summary under 60 chars>

Why this change is needed, and which invariant or fixture it serves.
Notes on anything a reviewer would otherwise have to reverse-engineer.

Task: <task id>
```

One trajectory may be several commits, but the red test is its own commit, so
the red→green transition is visible in the history.
