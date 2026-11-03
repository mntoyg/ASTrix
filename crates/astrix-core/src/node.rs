//! The backend-agnostic AST node view.

use core::fmt;
use core::marker::PhantomData;

use crate::source::SourceFile;
use crate::span::{ByteSpan, SourceSpan};

/// A read-only, cursor-like view of one node in a concrete syntax tree.
///
/// `AstNode` is the seam that keeps ASTrix multi-language. A parser backend
/// (`astrix-parser`) implements it once per grammar; rules, visitors and the
/// rewriter are written against the trait and never against a grammar. The
/// `'tree` lifetime ties borrowed grammar data — kind names, field names — to
/// the tree the node came from.
///
/// Implementations must be cheap to clone: nodes are expected to be handle-like
/// values, not owned subtrees.
pub trait AstNode<'tree>: Clone + fmt::Debug {
    /// Grammar name of this node, for example `call` or `attribute`.
    fn kind(&self) -> &'tree str;

    /// Numeric grammar id of this node, stable within one grammar version.
    fn kind_id(&self) -> u16;

    /// Location of this node in the originating source buffer.
    fn span(&self) -> SourceSpan;

    /// Returns `true` for named (non-anonymous) grammar nodes.
    fn is_named(&self) -> bool;

    /// Returns `true` when the parser inserted an error node here.
    fn is_error(&self) -> bool;

    /// Returns `true` when the parser inserted a zero-width missing node here.
    fn is_missing(&self) -> bool;

    /// Number of children, including anonymous ones.
    fn child_count(&self) -> usize;

    /// Child at `index`, counting anonymous nodes.
    fn child(&self, index: usize) -> Option<Self>;

    /// Number of named children.
    fn named_child_count(&self) -> usize;

    /// Named child at `index`, skipping anonymous nodes.
    fn named_child(&self, index: usize) -> Option<Self>;

    /// Child bound to the grammar field `field`, for example `function`.
    fn child_by_field_name(&self, field: &str) -> Option<Self>;

    /// Grammar field name of the child at `index`, if it is bound to one.
    fn field_name_for_child(&self, index: usize) -> Option<&'tree str>;

    /// Parent node, or `None` at the root.
    fn parent(&self) -> Option<Self>;

    /// Authoritative byte range of this node.
    fn byte_span(&self) -> ByteSpan {
        self.span().bytes
    }

    /// Returns `true` when this node's kind is exactly `kind`.
    fn has_kind(&self, kind: &str) -> bool {
        self.kind() == kind
    }

    /// Source text covered by this node.
    ///
    /// # Panics
    ///
    /// Panics if `source` is not the buffer this node was parsed from.
    fn text<'src>(&self, source: &'src SourceFile) -> &'src str {
        source.slice(self.byte_span())
    }

    /// Iterator over all children, in grammar order.
    fn children(&self) -> Children<'_, 'tree, Self> {
        Children { node: self, index: 0, len: self.child_count(), _tree: PhantomData }
    }

    /// Iterator over named children, in grammar order.
    fn named_children(&self) -> NamedChildren<'_, 'tree, Self> {
        NamedChildren { node: self, index: 0, len: self.named_child_count(), _tree: PhantomData }
    }

    /// First child whose kind is `kind`.
    fn child_of_kind(&self, kind: &str) -> Option<Self> {
        self.children().find(|child| child.has_kind(kind))
    }

    /// Nearest ancestor whose kind is `kind`, excluding `self`.
    fn ancestor_of_kind(&self, kind: &str) -> Option<Self> {
        let mut current = self.parent();
        while let Some(node) = current {
            if node.has_kind(kind) {
                return Some(node);
            }
            current = node.parent();
        }
        None
    }
}

/// Iterator over every child of a node, returned by [`AstNode::children`].
#[derive(Debug)]
pub struct Children<'node, 'tree, N: AstNode<'tree>> {
    node: &'node N,
    index: usize,
    len: usize,
    _tree: PhantomData<&'tree ()>,
}

impl<'tree, N: AstNode<'tree>> Iterator for Children<'_, 'tree, N> {
    type Item = N;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.len {
            let current = self.index;
            self.index += 1;
            if let Some(child) = self.node.child(current) {
                return Some(child);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.len - self.index))
    }
}

/// Iterator over named children, returned by [`AstNode::named_children`].
#[derive(Debug)]
pub struct NamedChildren<'node, 'tree, N: AstNode<'tree>> {
    node: &'node N,
    index: usize,
    len: usize,
    _tree: PhantomData<&'tree ()>,
}

impl<'tree, N: AstNode<'tree>> Iterator for NamedChildren<'_, 'tree, N> {
    type Item = N;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.len {
            let current = self.index;
            self.index += 1;
            if let Some(child) = self.node.named_child(current) {
                return Some(child);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.len - self.index))
    }
}
