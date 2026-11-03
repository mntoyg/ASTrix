//! Deterministic source-span rewriting: the [`AstMutator`] contract.

use std::path::PathBuf;

use crate::error::{AstrixError, Result};
use crate::language::LanguageId;
use crate::rule::RuleId;
use crate::source::SourceFile;
use crate::span::ByteSpan;

/// Why one edit exists, carried through to the final patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditProvenance {
    /// Rule that requested the edit.
    pub rule_id: RuleId,
    /// Short operator-facing reason, for example `yaml.load is unsafe`.
    pub rationale: String,
}

impl EditProvenance {
    /// Records that `rule_id` requested an edit for `rationale`.
    pub fn new(rule_id: RuleId, rationale: impl Into<String>) -> Self {
        Self { rule_id, rationale: rationale.into() }
    }
}

/// A single span replacement expressed against the **original** buffer.
///
/// Every edit in a script is anchored to the untouched source, never to an
/// intermediate state. That invariant is what lets the mutator apply a whole
/// script in one pass without any rule needing to know about the others.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// Bytes to replace, in original-buffer coordinates.
    pub span: ByteSpan,
    /// Text to put in their place; empty means deletion.
    pub replacement: String,
    /// Who asked for the edit, and why.
    pub provenance: EditProvenance,
}

impl Edit {
    /// Replaces `span` with `replacement`.
    pub fn replace(
        span: ByteSpan,
        replacement: impl Into<String>,
        provenance: EditProvenance,
    ) -> Self {
        Self { span, replacement: replacement.into(), provenance }
    }

    /// Inserts `text` at `offset` without removing anything.
    pub fn insert(offset: usize, text: impl Into<String>, provenance: EditProvenance) -> Self {
        Self { span: ByteSpan::empty_at(offset), replacement: text.into(), provenance }
    }

    /// Deletes `span`.
    pub fn delete(span: ByteSpan, provenance: EditProvenance) -> Self {
        Self { span, replacement: String::new(), provenance }
    }

    /// Returns `true` when applying this edit would leave the buffer unchanged.
    pub fn is_noop(&self, source: &SourceFile) -> bool {
        source.try_slice(self.span) == Some(self.replacement.as_str())
    }
}

/// A module import the remediated code needs in order to compile or run.
///
/// Rules declare requirements instead of synthesising import statements
/// themselves, because where an import belongs is a language concern. The
/// language backend resolves each requirement into a concrete edit, or reports
/// that the import is already satisfied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImportRequirement {
    /// Module path, for example `secrets` or `defusedxml.ElementTree`.
    pub module: String,
    /// Specific symbol to import from the module, if not the module itself.
    pub symbol: Option<String>,
    /// Local alias to bind the import to.
    pub alias: Option<String>,
}

impl ImportRequirement {
    /// Requires the whole module.
    pub fn module(module: impl Into<String>) -> Self {
        Self { module: module.into(), symbol: None, alias: None }
    }

    /// Requires `symbol` from `module`.
    pub fn symbol(module: impl Into<String>, symbol: impl Into<String>) -> Self {
        Self { module: module.into(), symbol: Some(symbol.into()), alias: None }
    }

    /// Binds the import to a local alias.
    pub fn aliased_as(mut self, alias: impl Into<String>) -> Self {
        self.alias = Some(alias.into());
        self
    }
}

/// A validated, ordered set of edits plus the imports they depend on.
///
/// An `EditScript` is the only thing a rule hands back, and the only thing a
/// mutator accepts. Construct one freely, then call
/// [`EditScript::normalized`] to get the canonical, conflict-free form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EditScript {
    edits: Vec<Edit>,
    requirements: Vec<ImportRequirement>,
}

impl EditScript {
    /// Creates an empty script.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a script holding exactly one edit.
    pub fn single(edit: Edit) -> Self {
        Self { edits: vec![edit], requirements: Vec::new() }
    }

    /// Adds an edit.
    pub fn push(&mut self, edit: Edit) -> &mut Self {
        self.edits.push(edit);
        self
    }

    /// Adds an edit, builder style.
    pub fn with_edit(mut self, edit: Edit) -> Self {
        self.edits.push(edit);
        self
    }

    /// Declares an import the remediated code needs.
    pub fn require_import(mut self, requirement: ImportRequirement) -> Self {
        self.requirements.push(requirement);
        self
    }

    /// The edits, in the order they were added or normalized into.
    pub fn edits(&self) -> &[Edit] {
        &self.edits
    }

    /// The declared import requirements.
    pub fn requirements(&self) -> &[ImportRequirement] {
        &self.requirements
    }

    /// Number of edits.
    pub fn len(&self) -> usize {
        self.edits.len()
    }

    /// Returns `true` when the script contains no edits.
    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    /// Merges `other` into `self` without validating the result.
    pub fn merge(&mut self, other: Self) -> &mut Self {
        self.edits.extend(other.edits);
        self.requirements.extend(other.requirements);
        self
    }

    /// Returns the canonical form of this script.
    ///
    /// Edits are sorted by span — insertions sort before the replacement they
    /// precede — duplicate import requirements are collapsed, and overlapping
    /// edits are rejected. Two scripts with the same edits in a different
    /// order normalize to byte-identical results, which is what makes a
    /// remediation run reproducible.
    ///
    /// # Errors
    ///
    /// Returns [`AstrixError::OverlappingEdits`] when two edits claim the same
    /// bytes, since no single-pass rewrite can honour both.
    pub fn normalized(mut self) -> Result<Self> {
        self.edits.sort_by(|left, right| {
            left.span.cmp(&right.span).then_with(|| left.replacement.cmp(&right.replacement))
        });

        for window in self.edits.windows(2) {
            let (left, right) = (&window[0], &window[1]);
            if left.span.overlaps(right.span) {
                return Err(AstrixError::OverlappingEdits { left: left.span, right: right.span });
            }
        }

        self.requirements.sort();
        self.requirements.dedup();
        Ok(self)
    }
}

/// One edit as it was actually applied, with the text it displaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEdit {
    /// Span in the original buffer.
    pub span: ByteSpan,
    /// Text that used to occupy the span.
    pub original_text: String,
    /// Text that replaced it.
    pub replacement: String,
    /// Rule that requested the edit.
    pub rule_id: RuleId,
}

/// The result of applying an edit script: a candidate rewrite, not a committed one.
///
/// A `Patch` is an in-memory proposal. Nothing is written to disk until the
/// zero-breakage gate accepts it, so the original buffer is always recoverable
/// from the patch itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// File the patch applies to.
    pub path: PathBuf,
    /// Language of the file.
    pub language: LanguageId,
    /// Buffer before the rewrite.
    pub original: String,
    /// Buffer after the rewrite.
    pub rewritten: String,
    /// Edits that were applied, in canonical order.
    pub applied: Vec<AppliedEdit>,
    /// Content digest of `rewritten`, used to prove two runs agree.
    pub digest: String,
}

impl Patch {
    /// Returns `true` when the rewrite changed nothing.
    pub fn is_noop(&self) -> bool {
        self.original == self.rewritten
    }

    /// The rewritten buffer as a re-parsable [`SourceFile`].
    pub fn candidate_source(&self) -> SourceFile {
        SourceFile::new(self.path.clone(), self.language, self.rewritten.clone())
    }

    /// Rules that contributed at least one edit, in canonical order.
    pub fn contributing_rules(&self) -> Vec<&RuleId> {
        let mut rules: Vec<&RuleId> = self.applied.iter().map(|edit| &edit.rule_id).collect();
        rules.sort();
        rules.dedup();
        rules
    }
}

/// Applies edit scripts to a source buffer, deterministically.
///
/// The contract an implementation must honour:
///
/// 1. **Original-buffer coordinates.** Every span is interpreted against the
///    input buffer, never against a partially rewritten one.
/// 2. **Determinism.** The same `(source, script)` pair always produces the
///    same `rewritten` text and the same digest.
/// 3. **Validate before writing.** Out-of-bounds spans, spans that split a
///    UTF-8 character, and overlapping edits are errors, not best-effort
///    rewrites.
/// 4. **No side effects.** The source buffer is left untouched and nothing is
///    written to disk; the caller decides what to do with the [`Patch`].
pub trait AstMutator {
    /// Applies `script` to `source` and returns the candidate patch.
    fn apply(&self, source: &SourceFile, script: &EditScript) -> Result<Patch>;

    /// Merges several scripts and applies them in one pass.
    ///
    /// # Errors
    ///
    /// Returns [`AstrixError::OverlappingEdits`] when two rules want the same
    /// bytes. Rejecting is deliberate: silently dropping one rule's edit would
    /// ship a patch that remediates less than it reports.
    fn apply_all(&self, source: &SourceFile, scripts: &[EditScript]) -> Result<Patch> {
        let mut merged = EditScript::new();
        for script in scripts {
            merged.merge(script.clone());
        }
        self.apply(source, &merged.normalized()?)
    }
}

#[cfg(test)]
mod tests {
    use super::{Edit, EditProvenance, EditScript, ImportRequirement};
    use crate::error::AstrixError;
    use crate::rule::RuleId;
    use crate::span::ByteSpan;

    fn provenance() -> EditProvenance {
        EditProvenance::new(RuleId::new("astrix.test.rule"), "test")
    }

    #[test]
    fn normalization_sorts_edits_by_span() {
        let script = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(20, 24), "b", provenance()))
            .with_edit(Edit::replace(ByteSpan::new(4, 8), "a", provenance()))
            .normalized()
            .expect("non-overlapping edits normalize");

        let spans: Vec<ByteSpan> = script.edits().iter().map(|edit| edit.span).collect();
        assert_eq!(spans, vec![ByteSpan::new(4, 8), ByteSpan::new(20, 24)]);
    }

    #[test]
    fn normalization_is_order_independent() {
        let forward = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(0, 4), "x", provenance()))
            .with_edit(Edit::replace(ByteSpan::new(9, 12), "y", provenance()))
            .normalized()
            .expect("normalizes");
        let reversed = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(9, 12), "y", provenance()))
            .with_edit(Edit::replace(ByteSpan::new(0, 4), "x", provenance()))
            .normalized()
            .expect("normalizes");

        assert_eq!(forward, reversed);
    }

    #[test]
    fn overlapping_edits_are_rejected() {
        let error = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(0, 10), "x", provenance()))
            .with_edit(Edit::replace(ByteSpan::new(5, 15), "y", provenance()))
            .normalized()
            .expect_err("overlapping edits must not normalize");

        assert!(matches!(error, AstrixError::OverlappingEdits { .. }));
    }

    #[test]
    fn insertions_may_sit_on_a_replacement_boundary() {
        let script = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(5, 10), "x", provenance()))
            .with_edit(Edit::insert(5, "import secrets\n", provenance()))
            .normalized()
            .expect("an insertion at a boundary is not a conflict");

        assert_eq!(script.len(), 2);
        assert!(script.edits()[0].span.is_empty());
    }

    #[test]
    fn duplicate_import_requirements_collapse() {
        let script = EditScript::new()
            .require_import(ImportRequirement::module("secrets"))
            .require_import(ImportRequirement::module("secrets"))
            .require_import(ImportRequirement::symbol("os", "urandom"))
            .normalized()
            .expect("normalizes");

        assert_eq!(script.requirements().len(), 2);
    }
}
