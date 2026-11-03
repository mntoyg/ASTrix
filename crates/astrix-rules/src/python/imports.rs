//! Resolving which local name refers to which Python module.
//!
//! A rule that matches `yaml.load(...)` has to know that `yaml` really is the
//! PyYAML module and not a local variable someone happened to call `yaml`.
//! These helpers answer that from the AST alone, which is what lets a rule
//! report [`astrix_core::Confidence::Certain`] instead of guessing.

use astrix_core::{AstNode, SourceFile};

/// Walks up to the outermost node, which for a Python file is `module`.
pub fn module_root<'tree, N: AstNode<'tree>>(node: &N) -> N {
    let mut current = node.clone();
    while let Some(parent) = current.parent() {
        current = parent;
    }
    current
}

/// Returns `true` when `name` is bound to `module` by a plain `import`.
///
/// Recognises `import yaml` and `import yaml as y`, at any nesting depth, so a
/// function-local import counts too.
pub fn binds_module<'tree, N: AstNode<'tree>>(
    root: &N,
    source: &SourceFile,
    name: &str,
    module: &str,
) -> bool {
    find_statement(root, "import_statement", |statement| {
        name_clauses(statement).any(|clause| clause_binds(&clause, source, name, module))
    })
}

/// Returns `true` when `symbol` is imported from `module` under the local name
/// `name`, as in `from yaml import load` or `from yaml import load as l`.
pub fn binds_symbol<'tree, N: AstNode<'tree>>(
    root: &N,
    source: &SourceFile,
    name: &str,
    module: &str,
    symbol: &str,
) -> bool {
    find_statement(root, "import_from_statement", |statement| {
        let from_module = statement
            .child_by_field_name("module_name")
            .is_some_and(|found| found.text(source) == module);

        from_module
            && name_clauses(statement).any(|clause| clause_binds(&clause, source, name, symbol))
    })
}

/// Depth-first search for a statement of `kind` that satisfies `predicate`.
fn find_statement<'tree, N, F>(root: &N, kind: &str, mut predicate: F) -> bool
where
    N: AstNode<'tree>,
    F: FnMut(&N) -> bool,
{
    let mut stack = vec![root.clone()];

    while let Some(node) = stack.pop() {
        if node.has_kind(kind) && predicate(&node) {
            return true;
        }
        for index in 0..node.child_count() {
            if let Some(child) = node.child(index) {
                stack.push(child);
            }
        }
    }

    false
}

/// The children of an import statement bound to its `name` grammar field.
fn name_clauses<'tree, N: AstNode<'tree>>(statement: &N) -> impl Iterator<Item = N> + '_ {
    (0..statement.child_count()).filter_map(move |index| {
        if statement.field_name_for_child(index) == Some("name") {
            statement.child(index)
        } else {
            None
        }
    })
}

/// Matches one import clause against a `(local name, target)` pair.
///
/// Handles the bare `dotted_name` form, where the local name is the target
/// itself, and the `aliased_import` form, where the two differ.
fn clause_binds<'tree, N: AstNode<'tree>>(
    clause: &N,
    source: &SourceFile,
    name: &str,
    target: &str,
) -> bool {
    match clause.kind() {
        "dotted_name" => name == target && clause.text(source) == target,
        "aliased_import" => {
            match (clause.child_by_field_name("name"), clause.child_by_field_name("alias")) {
                (Some(imported), Some(alias)) => {
                    imported.text(source) == target && alias.text(source) == name
                }
                _ => false,
            }
        }
        _ => false,
    }
}
