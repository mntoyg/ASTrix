//! Deterministic source-span rewriting for ASTrix.
//!
//! This crate holds the one implementation of [`astrix_core::AstMutator`] that
//! the engine uses, [`SpanRewriter`]. It is deliberately dumb: it knows about
//! bytes, spans and ordering, and nothing about CVEs, grammars or languages.
//! All the judgement lives in the rules; all the mechanical safety lives here.
//!
//! # Guarantees
//!
//! * **Original-buffer coordinates.** Spans are resolved against the input
//!   buffer only. A script is applied in one forward pass, so no edit can see
//!   another edit's output.
//! * **Validate, then write.** Out-of-bounds spans, spans that split a UTF-8
//!   character, overlapping edits and unresolved imports are errors. A
//!   rejected script produces no text at all.
//! * **Byte-identical reruns.** The same `(source, script)` pair always yields
//!   the same `rewritten` buffer and the same SHA-256 digest, whatever order
//!   the rules happened to run in.
//!
//! # Example
//!
//! ```
//! use astrix_core::{
//!     AstMutator, ByteSpan, Edit, EditProvenance, EditScript, LanguageId, RuleId, SourceFile,
//! };
//! use astrix_rewriter::SpanRewriter;
//!
//! let source = SourceFile::new("app.py", LanguageId::Python, "cfg = yaml.load(raw)\n");
//! let provenance = EditProvenance::new(RuleId::new("astrix.python.unsafe-yaml-load"), "unsafe");
//! let script = EditScript::single(Edit::replace(ByteSpan::new(6, 15), "yaml.safe_load", provenance));
//!
//! let patch = SpanRewriter::new().apply(&source, &script)?;
//!
//! assert_eq!(patch.rewritten, "cfg = yaml.safe_load(raw)\n");
//! assert_eq!(patch.applied.len(), 1);
//! # Ok::<(), astrix_core::AstrixError>(())
//! ```

use astrix_core::{AppliedEdit, AstMutator, AstrixError, EditScript, Patch, Result, SourceFile};
use sha2::{Digest, Sha256};

/// Applies edit scripts by splicing byte spans, in one validated pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpanRewriter {
    _private: (),
}

impl SpanRewriter {
    /// Creates a rewriter.
    pub fn new() -> Self {
        Self::default()
    }
}

/// SHA-256 digest of `text`, lowercase hex.
///
/// Two ASTrix runs that agree on a patch agree on this value, which is what
/// makes a remediation auditable after the fact.
pub fn digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher.finalize().iter().fold(String::with_capacity(64), |mut acc, byte| {
        use core::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

impl AstMutator for SpanRewriter {
    fn apply(&self, source: &SourceFile, script: &EditScript) -> Result<Patch> {
        let script = script.clone().normalized()?;

        if let Some(requirement) = script.requirements().first() {
            return Err(AstrixError::UnresolvedImport { module: requirement.module.clone() });
        }

        for edit in script.edits() {
            source.validate_span(edit.span)?;
        }

        let original = source.text();
        let mut rewritten = String::with_capacity(original.len());
        let mut applied = Vec::with_capacity(script.len());
        let mut cursor = 0_usize;

        for edit in script.edits() {
            rewritten.push_str(&original[cursor..edit.span.start]);
            rewritten.push_str(&edit.replacement);

            applied.push(AppliedEdit {
                span: edit.span,
                original_text: source.slice(edit.span).to_owned(),
                replacement: edit.replacement.clone(),
                rule_id: edit.provenance.rule_id.clone(),
            });

            cursor = edit.span.end;
        }
        rewritten.push_str(&original[cursor..]);

        Ok(Patch {
            path: source.path().to_path_buf(),
            language: source.language(),
            original: original.to_owned(),
            digest: digest(&rewritten),
            rewritten,
            applied,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{digest, SpanRewriter};
    use astrix_core::{
        AstMutator, AstrixError, ByteSpan, Edit, EditProvenance, EditScript, ImportRequirement,
        LanguageId, RuleId, SourceFile,
    };

    fn provenance(rule: &str) -> EditProvenance {
        EditProvenance::new(RuleId::new(rule), "test")
    }

    fn python(text: &str) -> SourceFile {
        SourceFile::new("app/main.py", LanguageId::Python, text)
    }

    #[test]
    fn a_single_replacement_splices_exactly_its_span() {
        let source = python("cfg = yaml.load(raw)\n");
        let script = EditScript::single(Edit::replace(
            ByteSpan::new(6, 15),
            "yaml.safe_load",
            provenance("r1"),
        ));

        let patch = SpanRewriter::new().apply(&source, &script).expect("applies");

        assert_eq!(patch.rewritten, "cfg = yaml.safe_load(raw)\n");
        assert_eq!(patch.original, source.text());
        assert_eq!(patch.applied[0].original_text, "yaml.load");
        assert!(!patch.is_noop());
    }

    #[test]
    fn several_edits_all_use_original_coordinates() {
        let source = python("a = load(x)\nb = load(y)\n");
        let script = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(4, 8), "safe_load", provenance("r1")))
            .with_edit(Edit::replace(ByteSpan::new(16, 20), "safe_load", provenance("r1")));

        let patch = SpanRewriter::new().apply(&source, &script).expect("applies");

        assert_eq!(patch.rewritten, "a = safe_load(x)\nb = safe_load(y)\n");
        assert_eq!(patch.applied.len(), 2);
    }

    #[test]
    fn edit_order_in_the_script_does_not_change_the_result() {
        let source = python("a = load(x)\nb = load(y)\n");
        let forward = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(4, 8), "safe_load", provenance("r1")))
            .with_edit(Edit::replace(ByteSpan::new(16, 20), "safe_load", provenance("r1")));
        let reversed = EditScript::new()
            .with_edit(Edit::replace(ByteSpan::new(16, 20), "safe_load", provenance("r1")))
            .with_edit(Edit::replace(ByteSpan::new(4, 8), "safe_load", provenance("r1")));

        let rewriter = SpanRewriter::new();
        let first = rewriter.apply(&source, &forward).expect("applies");
        let second = rewriter.apply(&source, &reversed).expect("applies");

        assert_eq!(first.rewritten, second.rewritten);
        assert_eq!(first.digest, second.digest);
    }

    #[test]
    fn insertions_and_deletions_are_ordinary_spans() {
        let source = python("import yaml\ncfg = raw\n");
        let script = EditScript::new()
            .with_edit(Edit::insert(0, "import secrets\n", provenance("r1")))
            .with_edit(Edit::delete(ByteSpan::new(18, 21), provenance("r1")));

        let patch = SpanRewriter::new().apply(&source, &script).expect("applies");

        assert_eq!(patch.rewritten, "import secrets\nimport yaml\ncfg = \n");
    }

    #[test]
    fn an_empty_script_produces_a_noop_patch() {
        let source = python("cfg = raw\n");
        let patch = SpanRewriter::new().apply(&source, &EditScript::new()).expect("applies");

        assert!(patch.is_noop());
        assert_eq!(patch.rewritten, source.text());
        assert!(patch.applied.is_empty());
    }

    #[test]
    fn out_of_bounds_spans_are_refused_before_any_text_is_built() {
        let source = python("cfg = raw\n");
        let script =
            EditScript::single(Edit::replace(ByteSpan::new(0, 9_000), "x", provenance("r1")));

        assert!(matches!(
            SpanRewriter::new().apply(&source, &script),
            Err(AstrixError::SpanOutOfBounds { .. })
        ));
    }

    #[test]
    fn spans_that_split_a_character_are_refused() {
        let source = python("label = \"ค่า\"\n");
        let script = EditScript::single(Edit::replace(ByteSpan::new(9, 11), "x", provenance("r1")));

        assert!(matches!(
            SpanRewriter::new().apply(&source, &script),
            Err(AstrixError::NotCharBoundary { .. })
        ));
    }

    #[test]
    fn two_rules_fighting_over_the_same_bytes_is_an_error_not_a_silent_drop() {
        let source = python("cfg = yaml.load(raw)\n");
        let first = EditScript::single(Edit::replace(
            ByteSpan::new(6, 15),
            "yaml.safe_load",
            provenance("r1"),
        ));
        let second =
            EditScript::single(Edit::replace(ByteSpan::new(11, 15), "full_load", provenance("r2")));

        assert!(matches!(
            SpanRewriter::new().apply_all(&source, &[first, second]),
            Err(AstrixError::OverlappingEdits { .. })
        ));
    }

    #[test]
    fn unresolved_imports_block_the_rewrite() {
        let source = python("token = random.random()\n");
        let script = EditScript::single(Edit::replace(
            ByteSpan::new(8, 23),
            "secrets.token_hex(32)",
            provenance("r1"),
        ))
        .require_import(ImportRequirement::module("secrets"));

        assert!(matches!(
            SpanRewriter::new().apply(&source, &script),
            Err(AstrixError::UnresolvedImport { .. })
        ));
    }

    #[test]
    fn applied_edits_record_which_rules_contributed() {
        let source = python("a = load(x)\nb = load(y)\n");
        let scripts = [
            EditScript::single(Edit::replace(ByteSpan::new(4, 8), "safe_load", provenance("r2"))),
            EditScript::single(Edit::replace(ByteSpan::new(16, 20), "safe_load", provenance("r1"))),
        ];

        let patch = SpanRewriter::new().apply_all(&source, &scripts).expect("applies");
        let rules: Vec<&str> =
            patch.contributing_rules().iter().map(|rule| rule.as_str()).collect();

        assert_eq!(rules, vec!["r1", "r2"]);
    }

    #[test]
    fn digest_is_sha256_hex() {
        assert_eq!(digest(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(digest("a").len(), 64);
        assert_ne!(digest("a"), digest("b"));
    }

    #[test]
    fn the_candidate_source_is_re_parsable_in_the_same_language() {
        let source = python("cfg = yaml.load(raw)\n");
        let script = EditScript::single(Edit::replace(
            ByteSpan::new(6, 15),
            "yaml.safe_load",
            provenance("r1"),
        ));

        let patch = SpanRewriter::new().apply(&source, &script).expect("applies");
        let candidate = patch.candidate_source();

        assert_eq!(candidate.language(), LanguageId::Python);
        assert_eq!(candidate.path(), source.path());
        assert_eq!(candidate.text(), patch.rewritten);
    }
}
