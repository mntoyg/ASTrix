//! Python remediation rules.

pub mod imports;
pub mod unsafe_yaml_load;

pub use unsafe_yaml_load::UnsafeYamlLoad;

use astrix_core::AstNode;

use crate::registry::RuleRegistry;

/// Registers every built-in Python rule into `registry`.
///
/// Registration order is the order rules are offered a node, which keeps a
/// scan reproducible.
pub fn register_all<'tree, N: AstNode<'tree> + Send + Sync + 'tree>(
    registry: &mut RuleRegistry<'tree, N>,
) {
    registry.register(UnsafeYamlLoad::<N>::new());
}
