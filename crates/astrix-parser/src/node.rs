//! The tree-sitter implementation of [`astrix_core::AstNode`].

use astrix_core::{AstNode, ByteSpan, Point, SourceSpan};

/// A tree-sitter node exposed through the ASTrix node contract.
///
/// This is a thin handle: cloning it copies a few machine words, never a
/// subtree. Rules therefore never need to worry about the cost of walking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsNode<'tree> {
    inner: tree_sitter::Node<'tree>,
}

impl<'tree> TsNode<'tree> {
    /// Wraps a raw tree-sitter node.
    pub fn new(inner: tree_sitter::Node<'tree>) -> Self {
        Self { inner }
    }

    /// Borrows the underlying tree-sitter node, for grammar-specific work such
    /// as running a `tree_sitter::Query`.
    pub fn raw(&self) -> &tree_sitter::Node<'tree> {
        &self.inner
    }
}

impl<'tree> From<tree_sitter::Node<'tree>> for TsNode<'tree> {
    fn from(inner: tree_sitter::Node<'tree>) -> Self {
        Self::new(inner)
    }
}

fn point_of(point: tree_sitter::Point) -> Point {
    Point::new(point.row, point.column)
}

impl<'tree> AstNode<'tree> for TsNode<'tree> {
    fn kind(&self) -> &'tree str {
        self.inner.kind()
    }

    fn kind_id(&self) -> u16 {
        self.inner.kind_id()
    }

    fn span(&self) -> SourceSpan {
        SourceSpan::new(
            ByteSpan::new(self.inner.start_byte(), self.inner.end_byte()),
            point_of(self.inner.start_position()),
            point_of(self.inner.end_position()),
        )
    }

    fn is_named(&self) -> bool {
        self.inner.is_named()
    }

    fn is_error(&self) -> bool {
        self.inner.is_error()
    }

    fn is_missing(&self) -> bool {
        self.inner.is_missing()
    }

    fn child_count(&self) -> usize {
        self.inner.child_count()
    }

    fn child(&self, index: usize) -> Option<Self> {
        self.inner.child(u32::try_from(index).ok()?).map(Self::new)
    }

    fn named_child_count(&self) -> usize {
        self.inner.named_child_count()
    }

    fn named_child(&self, index: usize) -> Option<Self> {
        self.inner.named_child(u32::try_from(index).ok()?).map(Self::new)
    }

    fn child_by_field_name(&self, field: &str) -> Option<Self> {
        self.inner.child_by_field_name(field).map(Self::new)
    }

    fn field_name_for_child(&self, index: usize) -> Option<&'tree str> {
        self.inner.field_name_for_child(u32::try_from(index).ok()?)
    }

    fn parent(&self) -> Option<Self> {
        self.inner.parent().map(Self::new)
    }
}
