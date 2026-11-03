//! CVE-2017-18342 — `yaml.load` without a safe loader.

use core::marker::PhantomData;

use astrix_core::prelude::*;

use crate::python::imports;

/// Loaders that deserialise arbitrary Python objects.
const UNSAFE_LOADERS: &[&str] = &["Loader", "UnsafeLoader", "yaml.Loader", "yaml.UnsafeLoader"];

/// Rewrites PyYAML calls that deserialise untrusted input unsafely.
///
/// # What it matches
///
/// A `call` whose function is `<yaml>.load`, where `<yaml>` is a local name
/// bound to the `yaml` module, in either of two shapes:
///
/// * no `Loader=` keyword argument at all — the CVE-2017-18342 default;
/// * `Loader=` naming a loader that constructs arbitrary Python objects.
///
/// A call that already passes `SafeLoader`, `CSafeLoader` or `FullLoader` is
/// left alone.
///
/// # Why the rewrite is safe
///
/// `yaml.safe_load` and `yaml.load` agree on every document that uses only
/// standard YAML tags, which is every document that is not an exploit attempt.
/// They differ exactly where the vulnerability lives: a document carrying a
/// Python object tag. A project that legitimately depends on that behaviour
/// will fail its own test suite under the patch, and the zero-breakage gate
/// rejects the patch rather than shipping it — which is why this rule can be
/// [`AutofixPolicy::Automatic`] without the policy becoming a guess.
///
/// The `N` parameter names the node type the rule runs against. It carries no
/// data; it exists so one rule body serves every parser backend that
/// implements [`AstNode`], and so a registry can hold rules for exactly one
/// backend without type erasure at the node level.
#[derive(Debug)]
pub struct UnsafeYamlLoad<N> {
    metadata: RuleMetadata,
    _node: PhantomData<fn() -> N>,
}

impl<N> Default for UnsafeYamlLoad<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N> UnsafeYamlLoad<N> {
    /// Creates the rule.
    pub fn new() -> Self {
        Self {
            _node: PhantomData,
            metadata: RuleMetadata::builder(
                "astrix.python.unsafe-yaml-load",
                "yaml.load without a safe loader deserialises arbitrary objects",
            )
            .cves(["CVE-2017-18342"])
            .cwes(["CWE-502"])
            .severity(Severity::Critical)
            .languages([LanguageId::Python])
            .node_kinds(["call"])
            .equivalence_argument(
                "safe_load and load agree on every document using only standard YAML tags; \
                 they differ only on Python object tags, which is the vulnerability itself",
            )
            .autofix(AutofixPolicy::Automatic)
            .build(),
        }
    }
}

/// What a matched call needs in order to become safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// No `Loader=` argument: swap `load` for `safe_load`.
    MissingLoader,
    /// An unsafe `Loader=` argument: swap the loader for `yaml.SafeLoader`.
    UnsafeLoader,
}

/// The `Loader=` keyword argument of a call, if it has one.
fn loader_argument<'tree, N: AstNode<'tree>>(call: &N, source: &SourceFile) -> Option<N> {
    let arguments = call.child_by_field_name("arguments")?;
    arguments.named_children().find(|argument| {
        argument.has_kind("keyword_argument")
            && argument
                .child_by_field_name("name")
                .is_some_and(|name| name.text(source) == "Loader")
    })
}

impl<'tree, N: AstNode<'tree>> RemediationRule<'tree> for UnsafeYamlLoad<N> {
    type Node = N;

    fn metadata(&self) -> &RuleMetadata {
        &self.metadata
    }

    fn detect(&self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> Option<Finding> {
        let call = ctx.node();
        let source = ctx.source();

        let function = call.child_by_field_name("function")?;
        if !function.has_kind("attribute") {
            return None;
        }

        let attribute = function.child_by_field_name("attribute")?;
        if attribute.text(source) != "load" {
            return None;
        }

        let object = function.child_by_field_name("object")?;
        let module_alias = object.text(source);

        let shape = match loader_argument(call, source) {
            None => Shape::MissingLoader,
            Some(argument) => {
                let loader = argument.child_by_field_name("value")?;
                if UNSAFE_LOADERS.contains(&loader.text(source)) {
                    Shape::UnsafeLoader
                } else {
                    return None;
                }
            }
        };

        // An import proves the receiver is PyYAML. Without one, the name may
        // be an unrelated local, so the finding is reported but not certain —
        // and `Remediation::is_unattended` will keep it out of an unattended
        // rewrite.
        let root = imports::module_root(call);
        let confidence = if imports::binds_module(&root, source, module_alias, "yaml") {
            Confidence::Certain
        } else {
            Confidence::Tentative
        };

        let message = match shape {
            Shape::MissingLoader => format!(
                "`{module_alias}.load` without a Loader deserialises arbitrary Python objects"
            ),
            Shape::UnsafeLoader => format!(
                "`{module_alias}.load` is passed a loader that deserialises arbitrary Python \
                 objects"
            ),
        };

        Some(Finding::new(&self.metadata, call.span(), call.kind(), confidence, message))
    }

    fn remediate(
        &self,
        ctx: &VisitContext<'_, 'tree, Self::Node>,
        finding: &Finding,
    ) -> Result<EditScript> {
        let call = ctx.node();
        let source = ctx.source();

        let provenance = EditProvenance::new(
            self.metadata.id.clone(),
            "CVE-2017-18342: restrict YAML deserialisation to standard tags",
        );

        let empty = || AstrixError::EmptyEditScript {
            rule_id: self.metadata.id.to_string(),
            span: finding.span.bytes,
        };

        match loader_argument(call, source) {
            // No loader: `yaml.load(x)` becomes `yaml.safe_load(x)`. Only the
            // attribute is replaced, so the receiver keeps whatever alias the
            // file uses.
            None => {
                let attribute = call
                    .child_by_field_name("function")
                    .and_then(|function| function.child_by_field_name("attribute"))
                    .ok_or_else(empty)?;

                Ok(EditScript::single(Edit::replace(
                    attribute.byte_span(),
                    "safe_load",
                    provenance,
                )))
            }
            // Unsafe loader: keep the call shape and swap only the loader, so
            // positional arguments and formatting are untouched.
            Some(argument) => {
                let loader = argument.child_by_field_name("value").ok_or_else(empty)?;
                Ok(EditScript::single(Edit::replace(
                    loader.byte_span(),
                    "yaml.SafeLoader",
                    provenance,
                )))
            }
        }
    }
}
