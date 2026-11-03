//! Trait contracts and value types shared by every ASTrix crate.
//!
//! `astrix-core` owns the vocabulary of the engine and nothing else: it has no
//! parser, no rule, no process spawning, and no dependency beyond `thiserror`.
//! Everything downstream is written against the three traits defined here.
//!
//! # The three contracts
//!
//! | Trait | Question it answers | Implemented by |
//! |---|---|---|
//! | [`AstVisitor`] | How is a tree traversed? | engine internals, rule drivers |
//! | [`RemediationRule`] | Is this node vulnerable, and what fixes it? | `astrix-rules` |
//! | [`AstMutator`] | How does an edit script become new text? | `astrix-rewriter` |
//!
//! [`AstNode`] sits underneath all three as the backend-agnostic node view
//! that `astrix-parser` implements once per grammar.
//!
//! # Pipeline
//!
//! ```text
//! SourceFile ──parse──▶ tree ──AstVisitor──▶ [Finding]
//!                                               │
//!                                     RemediationRule::remediate
//!                                               ▼
//!                                          EditScript
//!                                               │
//!                                        AstMutator::apply
//!                                               ▼
//!                                            Patch ──▶ zero-breakage gate
//! ```
//!
//! # Zero-breakage policy
//!
//! Three invariants in this crate carry that policy, and every implementation
//! is required to preserve them:
//!
//! 1. **Spans are always original-buffer coordinates.** A [`SourceFile`] is
//!    immutable, and [`Edit`] spans never refer to a partially rewritten
//!    buffer, so a finding stays valid for the whole run.
//! 2. **Rules describe, they never mutate.** [`RemediationRule::remediate`]
//!    returns an [`EditScript`]; only an [`AstMutator`] produces text, and
//!    only after validating bounds, character boundaries and overlap.
//! 3. **A rewrite is a proposal.** [`Patch`] holds both the original and the
//!    rewritten buffer in memory. Nothing is committed until the verification
//!    sandbox accepts it.

pub mod error;
pub mod language;
pub mod mutator;
pub mod node;
pub mod rule;
pub mod source;
pub mod span;
pub mod visitor;

pub use error::{AstrixError, Result};
pub use language::LanguageId;
pub use mutator::{
    AppliedEdit, AstMutator, Edit, EditProvenance, EditScript, ImportRequirement, Patch,
};
pub use node::{AstNode, Children, NamedChildren};
pub use rule::{
    AutofixPolicy, Confidence, CveId, Finding, RemediationRule, RuleId, RuleMetadata,
    RuleMetadataBuilder, Severity,
};
pub use source::SourceFile;
pub use span::{ByteSpan, Point, SourceSpan};
pub use visitor::{walk, walk_in_place, AstVisitor, VisitContext, VisitFlow, WalkStatus};

/// Everything a rule or backend implementation normally needs.
pub mod prelude {
    pub use crate::error::{AstrixError, Result};
    pub use crate::language::LanguageId;
    pub use crate::mutator::{AstMutator, Edit, EditProvenance, EditScript, ImportRequirement};
    pub use crate::node::AstNode;
    pub use crate::rule::{
        AutofixPolicy, Confidence, Finding, RemediationRule, RuleId, RuleMetadata, Severity,
    };
    pub use crate::source::SourceFile;
    pub use crate::span::{ByteSpan, Point, SourceSpan};
    pub use crate::visitor::{AstVisitor, VisitContext, VisitFlow, WalkStatus};
}
