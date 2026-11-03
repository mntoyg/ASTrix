//! The single error type shared by every ASTrix crate.

use std::path::PathBuf;

use crate::language::LanguageId;
use crate::span::ByteSpan;

/// Errors raised anywhere in the detect → plan → rewrite → verify pipeline.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AstrixError {
    /// No syntax backend is registered for the requested language.
    #[error("no syntax backend registered for language `{0}`")]
    UnsupportedLanguage(LanguageId),

    /// The backend could not produce a tree at all.
    #[error("failed to parse `{path}`: {reason}")]
    Parse {
        /// File that failed to parse.
        path: PathBuf,
        /// Backend-supplied explanation.
        reason: String,
    },

    /// The tree parsed but contains error or missing nodes, so no rewrite is safe.
    #[error("`{path}` contains {count} syntax error node(s); refusing to rewrite")]
    MalformedSyntax {
        /// File that contains the error nodes.
        path: PathBuf,
        /// Number of `ERROR`/`MISSING` nodes found.
        count: usize,
    },

    /// Two edits in the same script claim overlapping bytes.
    #[error("conflicting edits: {left} overlaps {right}")]
    OverlappingEdits {
        /// The earlier span in canonical order.
        left: ByteSpan,
        /// The later span in canonical order.
        right: ByteSpan,
    },

    /// An edit span lies outside the source buffer.
    #[error("edit span {span} is out of bounds for a {length}-byte source")]
    SpanOutOfBounds {
        /// The offending span.
        span: ByteSpan,
        /// Length of the source buffer in bytes.
        length: usize,
    },

    /// An edit span would split a multi-byte UTF-8 character.
    #[error("edit span {span} does not land on a UTF-8 character boundary")]
    NotCharBoundary {
        /// The offending span.
        span: ByteSpan,
    },

    /// A rule reported a finding but produced an empty remediation plan.
    #[error("rule `{rule_id}` reported a finding at {span} but produced no edits")]
    EmptyEditScript {
        /// Rule that produced the empty plan.
        rule_id: String,
        /// Location of the finding.
        span: ByteSpan,
    },

    /// A script reached the mutator still declaring an unresolved import.
    ///
    /// Import requirements are language-specific and must be lowered into
    /// concrete edits before any rewrite runs; applying the rest of the script
    /// would produce code that no longer resolves.
    #[error("import requirement `{module}` reached the rewriter unresolved")]
    UnresolvedImport {
        /// Module the remediated code still needs.
        module: String,
    },

    /// The zero-breakage gate refused the candidate patch.
    #[error("zero-breakage gate rejected the patch: {reason}")]
    ZeroBreakageViolation {
        /// Human-readable reason, mirroring the failing check.
        reason: String,
    },

    /// The verification sandbox itself failed to run.
    #[error("verification sandbox failure: {0}")]
    Sandbox(String),

    /// Filesystem failure, annotated with the path involved.
    #[error("i/o error at `{path}`")]
    Io {
        /// Path being read or written.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience alias used throughout the workspace.
pub type Result<T, E = AstrixError> = core::result::Result<T, E>;
