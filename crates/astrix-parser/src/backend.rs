//! Parsing: the [`SyntaxBackend`] contract and its tree-sitter implementation.

use std::path::PathBuf;

use astrix_core::{AstrixError, LanguageId, Result, SourceFile};

use crate::grammar;
use crate::node::TsNode;

/// A parser that turns a [`SourceFile`] into a traversable tree.
///
/// The associated `Tree` type is what keeps ASTrix open to backends other than
/// tree-sitter: a hand-written parser, an LSP-backed index, or a bytecode
/// reader can implement this trait and the rest of the engine is unchanged,
/// because rules only ever see [`astrix_core::AstNode`].
pub trait SyntaxBackend {
    /// Tree representation this backend produces.
    type Tree;

    /// Language this backend parses.
    fn language(&self) -> LanguageId;

    /// Parses `source` into a tree.
    ///
    /// # Errors
    ///
    /// Returns [`AstrixError::Parse`] when the backend cannot produce a tree,
    /// and [`AstrixError::UnsupportedLanguage`] when `source` is in a
    /// different language than [`SyntaxBackend::language`].
    fn parse(&self, source: &SourceFile) -> Result<Self::Tree>;
}

/// A parsed tree-sitter tree, tagged with where it came from.
///
/// The tree borrows nothing from the [`SourceFile`], but spans inside it are
/// only meaningful against that exact buffer — so the path and language are
/// kept here to make a mismatch detectable rather than silent.
#[derive(Debug)]
pub struct SyntaxTree {
    tree: tree_sitter::Tree,
    language: LanguageId,
    path: PathBuf,
}

impl SyntaxTree {
    /// Root node of the tree.
    pub fn root(&self) -> TsNode<'_> {
        TsNode::new(self.tree.root_node())
    }

    /// Language the tree was parsed as.
    pub fn language(&self) -> LanguageId {
        self.language
    }

    /// Path the tree was parsed from.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Borrows the raw tree-sitter tree, for grammar-specific work.
    pub fn raw(&self) -> &tree_sitter::Tree {
        &self.tree
    }

    /// Returns `true` when the tree contains any error or missing node.
    pub fn has_errors(&self) -> bool {
        self.tree.root_node().has_error()
    }

    /// Counts error and missing nodes in the tree.
    pub fn error_count(&self) -> usize {
        if !self.has_errors() {
            return 0;
        }

        let mut cursor = self.tree.walk();
        let mut count = 0_usize;
        let mut descending = true;

        loop {
            if descending {
                let node = cursor.node();
                if node.is_error() || node.is_missing() {
                    count += 1;
                }
                if node.has_error() && cursor.goto_first_child() {
                    continue;
                }
            }

            if cursor.goto_next_sibling() {
                descending = true;
            } else if cursor.goto_parent() {
                descending = false;
            } else {
                break;
            }
        }

        count
    }

    /// Rejects a tree that is not well formed.
    ///
    /// The zero-breakage policy makes this a hard gate rather than a warning:
    /// span arithmetic over a tree the parser had to guess at cannot be
    /// trusted to preserve semantics.
    ///
    /// # Errors
    ///
    /// Returns [`AstrixError::MalformedSyntax`] when the tree contains error
    /// or missing nodes.
    pub fn require_well_formed(&self) -> Result<()> {
        let count = self.error_count();
        if count > 0 {
            return Err(AstrixError::MalformedSyntax { path: self.path.clone(), count });
        }
        Ok(())
    }
}

/// A [`SyntaxBackend`] driven by a compiled tree-sitter grammar.
///
/// A backend is a value, not a global: construct one per language and keep it
/// for the lifetime of a scan. A fresh `tree_sitter::Parser` is created per
/// parse so the backend stays `Send + Sync` and can be shared across threads.
#[derive(Debug, Clone, Copy)]
pub struct TreeSitterBackend {
    language: LanguageId,
}

impl TreeSitterBackend {
    /// Creates a backend for `language`.
    ///
    /// # Errors
    ///
    /// Returns [`AstrixError::UnsupportedLanguage`] when the grammar for
    /// `language` was not compiled into this build.
    pub fn new(language: LanguageId) -> Result<Self> {
        grammar::load(language)?;
        Ok(Self { language })
    }
}

impl SyntaxBackend for TreeSitterBackend {
    type Tree = SyntaxTree;

    fn language(&self) -> LanguageId {
        self.language
    }

    fn parse(&self, source: &SourceFile) -> Result<Self::Tree> {
        if source.language() != self.language {
            return Err(AstrixError::UnsupportedLanguage(source.language()));
        }

        let grammar = grammar::load(self.language)?;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&grammar).map_err(|error| AstrixError::Parse {
            path: source.path().to_path_buf(),
            reason: error.to_string(),
        })?;

        let tree = parser.parse(source.bytes(), None).ok_or_else(|| AstrixError::Parse {
            path: source.path().to_path_buf(),
            reason: "tree-sitter returned no tree".to_owned(),
        })?;

        Ok(SyntaxTree { tree, language: self.language, path: source.path().to_path_buf() })
    }
}

/// Parses `source` with the backend for its own language.
///
/// # Errors
///
/// Propagates [`TreeSitterBackend::new`] and [`SyntaxBackend::parse`] errors.
pub fn parse(source: &SourceFile) -> Result<SyntaxTree> {
    TreeSitterBackend::new(source.language())?.parse(source)
}

#[cfg(all(test, feature = "lang-python"))]
mod tests {
    use super::{parse, SyntaxBackend, TreeSitterBackend};
    use astrix_core::{AstNode, AstrixError, LanguageId, SourceFile};

    fn python(text: &str) -> SourceFile {
        SourceFile::new("app/main.py", LanguageId::Python, text)
    }

    #[test]
    fn parses_python_into_a_module_root() {
        let source = python("import yaml\ncfg = yaml.load(raw)\n");
        let tree = parse(&source).expect("python parses");

        assert_eq!(tree.root().kind(), "module");
        assert_eq!(tree.language(), LanguageId::Python);
        assert!(!tree.has_errors());
        assert_eq!(tree.error_count(), 0);
        tree.require_well_formed().expect("clean source is well formed");
    }

    #[test]
    fn spans_round_trip_through_the_source_buffer() {
        let source = python("cfg = yaml.load(raw)\n");
        let tree = parse(&source).expect("python parses");
        let call = tree
            .root()
            .child(0)
            .and_then(|statement| statement.child(0))
            .and_then(|assignment| assignment.child_by_field_name("right"))
            .expect("assignment has a right-hand side");

        assert_eq!(call.kind(), "call");
        assert_eq!(call.text(&source), "yaml.load(raw)");
        assert_eq!(call.span().start.row, 0);
    }

    #[test]
    fn field_lookup_reaches_grammar_fields() {
        let source = python("yaml.load(raw)\n");
        let tree = parse(&source).expect("python parses");
        let call = tree
            .root()
            .child(0)
            .and_then(|statement| statement.child(0))
            .expect("expression statement wraps a call");

        let function = call.child_by_field_name("function").expect("call has a function field");
        assert_eq!(function.text(&source), "yaml.load");
    }

    #[test]
    fn malformed_sources_are_refused_rather_than_rewritten() {
        let source = python("def broken(:\n    pass\n");
        let tree = parse(&source).expect("tree-sitter always returns a tree");

        assert!(tree.has_errors());
        assert!(tree.error_count() > 0);
        assert!(matches!(tree.require_well_formed(), Err(AstrixError::MalformedSyntax { .. })));
    }

    #[test]
    fn a_backend_refuses_a_file_in_another_language() {
        let backend = TreeSitterBackend::new(LanguageId::Python).expect("python grammar is linked");
        let javascript = SourceFile::new("app.js", LanguageId::JavaScript, "eval(x)\n");

        assert!(matches!(
            backend.parse(&javascript),
            Err(AstrixError::UnsupportedLanguage(LanguageId::JavaScript))
        ));
    }

    #[test]
    fn parsing_is_reproducible() {
        let source = python("cfg = yaml.load(raw)\n");
        let first = parse(&source).expect("parses");
        let second = parse(&source).expect("parses");

        assert_eq!(first.root().span(), second.root().span());
        assert_eq!(first.root().child_count(), second.root().child_count());
    }
}
