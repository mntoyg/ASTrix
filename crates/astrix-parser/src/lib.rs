//! Tree-sitter backed syntax backends for ASTrix.
//!
//! This crate is the only place in the workspace that knows tree-sitter
//! exists. It implements [`astrix_core::AstNode`] once, in [`TsNode`], and
//! exposes parsing through the [`SyntaxBackend`] contract — so rules, the
//! rewriter and the sandbox stay grammar-agnostic.
//!
//! # Adding a language
//!
//! 1. Add the grammar crate as an optional dependency.
//! 2. Add a `lang-<name>` feature that enables it.
//! 3. Add one arm to [`grammar::load`].
//!
//! Nothing else changes: [`TreeSitterBackend`] and every rule written against
//! [`astrix_core::AstNode`] pick the new language up for free.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "lang-python")] {
//! use astrix_core::{AstNode, LanguageId, SourceFile};
//! use astrix_parser::parse;
//!
//! let source = SourceFile::new("app.py", LanguageId::Python, "cfg = yaml.load(raw)\n");
//! let tree = parse(&source)?;
//!
//! assert_eq!(tree.root().kind(), "module");
//! tree.require_well_formed()?;
//! # }
//! # Ok::<(), astrix_core::AstrixError>(())
//! ```

pub mod backend;
pub mod grammar;
pub mod node;

pub use backend::{parse, SyntaxBackend, SyntaxTree, TreeSitterBackend};
pub use node::TsNode;
