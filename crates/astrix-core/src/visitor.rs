//! Deterministic traversal: the [`AstVisitor`] contract and its driver.

use crate::node::AstNode;
use crate::source::SourceFile;
use crate::span::SourceSpan;

/// What the driver should do after a node is entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisitFlow {
    /// Descend into this node's children.
    Continue,
    /// Leave this node's subtree unexplored, but keep traversing siblings.
    SkipSubtree,
    /// Abort the whole traversal.
    Stop,
}

/// Why a traversal ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkStatus {
    /// Every reachable node was visited.
    Completed,
    /// A visitor returned [`VisitFlow::Stop`].
    Stopped,
}

/// Everything a visitor knows about the node it is currently looking at.
///
/// The context deliberately carries the [`SourceFile`] as well as the node, so
/// a rule can read the original text of a span without having to thread the
/// buffer through its own state.
#[derive(Debug)]
pub struct VisitContext<'ctx, 'tree, N: AstNode<'tree>> {
    node: &'ctx N,
    source: &'ctx SourceFile,
    depth: usize,
    field_name: Option<&'tree str>,
}

impl<'ctx, 'tree, N: AstNode<'tree>> VisitContext<'ctx, 'tree, N> {
    /// Builds a context for `node` at `depth`.
    pub fn new(
        node: &'ctx N,
        source: &'ctx SourceFile,
        depth: usize,
        field_name: Option<&'tree str>,
    ) -> Self {
        Self { node, source, depth, field_name }
    }

    /// The node being visited.
    pub fn node(&self) -> &'ctx N {
        self.node
    }

    /// The buffer the node was parsed from.
    pub fn source(&self) -> &'ctx SourceFile {
        self.source
    }

    /// Distance from the traversal root; the root itself is at depth `0`.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Grammar field name binding this node to its parent, if any.
    pub fn field_name(&self) -> Option<&'tree str> {
        self.field_name
    }

    /// Location of the node in the source buffer.
    pub fn span(&self) -> SourceSpan {
        self.node.span()
    }

    /// Source text covered by the node.
    pub fn text(&self) -> &'ctx str {
        self.source.slice(self.node.byte_span())
    }

    /// Source text of the child bound to grammar field `field`.
    pub fn field_text(&self, field: &str) -> Option<&'ctx str> {
        self.node.child_by_field_name(field).map(|child| self.source.slice(child.byte_span()))
    }
}

/// A traversal strategy over a concrete syntax tree.
///
/// Visitors are driven by [`walk`], never by recursing themselves: the driver
/// owns an explicit stack, so traversal order is fixed (pre-order, children
/// left to right) and deep trees cannot exhaust the native stack. That fixed
/// order is what makes a rule's findings — and therefore the resulting edit
/// script — reproducible across runs.
pub trait AstVisitor<'tree> {
    /// Node type produced by the backend this visitor runs against.
    type Node: AstNode<'tree>;

    /// Value the visitor yields once traversal ends.
    type Output;

    /// Called when a node is reached, before its children.
    fn enter(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> VisitFlow {
        let _ = ctx;
        VisitFlow::Continue
    }

    /// Called after a node's subtree has been traversed, or skipped.
    ///
    /// Not called for a node whose [`AstVisitor::enter`] returned
    /// [`VisitFlow::Stop`].
    fn leave(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>) {
        let _ = ctx;
    }

    /// Consumes the visitor and returns its accumulated result.
    fn finish(self, status: WalkStatus) -> Self::Output;
}

enum Step<N> {
    Enter { node: N, depth: usize },
    Leave { node: N, depth: usize },
}

/// Runs `visitor` over the subtree rooted at `root` and returns its output.
///
/// Traversal is pre-order and iterative. Children are pushed in reverse so
/// they are entered left to right.
pub fn walk<'tree, V>(mut visitor: V, root: &V::Node, source: &SourceFile) -> V::Output
where
    V: AstVisitor<'tree>,
{
    let status = drive(&mut visitor, root, source);
    visitor.finish(status)
}

/// Runs `visitor` over `root` without consuming it, for visitors reused across
/// several files or several roots.
pub fn walk_in_place<'tree, V>(visitor: &mut V, root: &V::Node, source: &SourceFile) -> WalkStatus
where
    V: AstVisitor<'tree>,
{
    drive(visitor, root, source)
}

fn drive<'tree, V>(visitor: &mut V, root: &V::Node, source: &SourceFile) -> WalkStatus
where
    V: AstVisitor<'tree>,
{
    let mut stack: Vec<Step<V::Node>> = vec![Step::Enter { node: root.clone(), depth: 0 }];

    while let Some(step) = stack.pop() {
        match step {
            Step::Enter { node, depth } => {
                let field_name = field_name_in_parent(&node);
                let ctx = VisitContext::new(&node, source, depth, field_name);
                match visitor.enter(&ctx) {
                    VisitFlow::Stop => return WalkStatus::Stopped,
                    VisitFlow::SkipSubtree => stack.push(Step::Leave { node, depth }),
                    VisitFlow::Continue => {
                        let child_count = node.child_count();
                        stack.push(Step::Leave { node: node.clone(), depth });
                        for index in (0..child_count).rev() {
                            if let Some(child) = node.child(index) {
                                stack.push(Step::Enter { node: child, depth: depth + 1 });
                            }
                        }
                    }
                }
            }
            Step::Leave { node, depth } => {
                let field_name = field_name_in_parent(&node);
                let ctx = VisitContext::new(&node, source, depth, field_name);
                visitor.leave(&ctx);
            }
        }
    }

    WalkStatus::Completed
}

/// Recovers the grammar field that binds `node` to its parent.
fn field_name_in_parent<'tree, N: AstNode<'tree>>(node: &N) -> Option<&'tree str> {
    let parent = node.parent()?;
    let span = node.byte_span();
    (0..parent.child_count())
        .find(|index| parent.child(*index).is_some_and(|child| child.byte_span() == span))
        .and_then(|index| parent.field_name_for_child(index))
}

#[cfg(test)]
mod tests {
    use super::{walk, AstVisitor, VisitContext, VisitFlow, WalkStatus};
    use crate::language::LanguageId;
    use crate::node::AstNode;
    use crate::source::SourceFile;
    use crate::span::{ByteSpan, Point, SourceSpan};
    use std::rc::Rc;

    #[derive(Debug)]
    struct Shape {
        kind: &'static str,
        span: ByteSpan,
        children: Vec<Rc<Shape>>,
    }

    #[derive(Debug, Clone)]
    struct MockNode(Rc<Shape>);

    impl MockNode {
        fn leaf(kind: &'static str, span: ByteSpan) -> Self {
            Self(Rc::new(Shape { kind, span, children: Vec::new() }))
        }

        fn branch(kind: &'static str, span: ByteSpan, children: Vec<Self>) -> Self {
            let children = children.into_iter().map(|child| child.0).collect();
            Self(Rc::new(Shape { kind, span, children }))
        }
    }

    impl AstNode<'static> for MockNode {
        fn kind(&self) -> &'static str {
            self.0.kind
        }
        fn kind_id(&self) -> u16 {
            0
        }
        fn span(&self) -> SourceSpan {
            SourceSpan::new(self.0.span, Point::default(), Point::default())
        }
        fn is_named(&self) -> bool {
            true
        }
        fn is_error(&self) -> bool {
            false
        }
        fn is_missing(&self) -> bool {
            false
        }
        fn child_count(&self) -> usize {
            self.0.children.len()
        }
        fn child(&self, index: usize) -> Option<Self> {
            self.0.children.get(index).map(|child| Self(Rc::clone(child)))
        }
        fn named_child_count(&self) -> usize {
            self.child_count()
        }
        fn named_child(&self, index: usize) -> Option<Self> {
            self.child(index)
        }
        fn child_by_field_name(&self, _field: &str) -> Option<Self> {
            None
        }
        fn field_name_for_child(&self, _index: usize) -> Option<&'static str> {
            None
        }
        fn parent(&self) -> Option<Self> {
            None
        }
    }

    #[derive(Default)]
    struct KindRecorder {
        entered: Vec<String>,
        left: Vec<String>,
        stop_at: Option<&'static str>,
        skip_at: Option<&'static str>,
    }

    impl AstVisitor<'static> for KindRecorder {
        type Node = MockNode;
        type Output = (Vec<String>, Vec<String>, WalkStatus);

        fn enter(&mut self, ctx: &VisitContext<'_, 'static, Self::Node>) -> VisitFlow {
            self.entered.push(format!("{}@{}", ctx.node().kind(), ctx.depth()));
            if self.stop_at == Some(ctx.node().kind()) {
                return VisitFlow::Stop;
            }
            if self.skip_at == Some(ctx.node().kind()) {
                return VisitFlow::SkipSubtree;
            }
            VisitFlow::Continue
        }

        fn leave(&mut self, ctx: &VisitContext<'_, 'static, Self::Node>) {
            self.left.push(ctx.node().kind().to_owned());
        }

        fn finish(self, status: WalkStatus) -> Self::Output {
            (self.entered, self.left, status)
        }
    }

    fn tree() -> MockNode {
        MockNode::branch(
            "module",
            ByteSpan::new(0, 20),
            vec![
                MockNode::branch(
                    "call",
                    ByteSpan::new(0, 9),
                    vec![
                        MockNode::leaf("identifier", ByteSpan::new(0, 4)),
                        MockNode::leaf("argument_list", ByteSpan::new(4, 9)),
                    ],
                ),
                MockNode::leaf("comment", ByteSpan::new(10, 20)),
            ],
        )
    }

    fn source() -> SourceFile {
        SourceFile::new("t.py", LanguageId::Python, "load(cfg)\n# trailing")
    }

    #[test]
    fn traversal_is_preorder_left_to_right() {
        let (entered, _, status) = walk(KindRecorder::default(), &tree(), &source());
        assert_eq!(
            entered,
            vec!["module@0", "call@1", "identifier@2", "argument_list@2", "comment@1"]
        );
        assert_eq!(status, WalkStatus::Completed);
    }

    #[test]
    fn leave_fires_after_the_whole_subtree() {
        let (_, left, _) = walk(KindRecorder::default(), &tree(), &source());
        assert_eq!(left, vec!["identifier", "argument_list", "call", "comment", "module"]);
    }

    #[test]
    fn skip_subtree_prunes_children_but_still_leaves_the_node() {
        let visitor = KindRecorder { skip_at: Some("call"), ..KindRecorder::default() };
        let (entered, left, status) = walk(visitor, &tree(), &source());
        assert_eq!(entered, vec!["module@0", "call@1", "comment@1"]);
        assert_eq!(left, vec!["call", "comment", "module"]);
        assert_eq!(status, WalkStatus::Completed);
    }

    #[test]
    fn stop_aborts_immediately() {
        let visitor = KindRecorder { stop_at: Some("call"), ..KindRecorder::default() };
        let (entered, left, status) = walk(visitor, &tree(), &source());
        assert_eq!(entered, vec!["module@0", "call@1"]);
        assert!(left.is_empty());
        assert_eq!(status, WalkStatus::Stopped);
    }

    #[test]
    fn repeated_walks_produce_identical_orders() {
        let (first, _, _) = walk(KindRecorder::default(), &tree(), &source());
        let (second, _, _) = walk(KindRecorder::default(), &tree(), &source());
        assert_eq!(first, second);
    }
}
