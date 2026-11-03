//! CVE remediation rules and the registry that drives them.
//!
//! A rule answers two questions about one node: *is this vulnerable?* and
//! *what single, span-local change fixes it?* It never rewrites anything — it
//! returns an [`astrix_core::EditScript`] and leaves application to
//! `astrix-rewriter`, so every proposed change can be validated, ordered and
//! rejected before a byte moves.
//!
//! # Adding a rule
//!
//! 1. Implement [`astrix_core::RemediationRule`] in the module for its
//!    language.
//! 2. Fill in [`astrix_core::RuleMetadata`], including the
//!    `equivalence_argument`: the written half of the zero-breakage claim.
//! 3. Register it in that language's `register_all`.
//! 4. Add a fixture pair under `tests/fixtures/`, which the TDD harness picks
//!    up with no code change.
//!
//! # Confidence and autofix are separate axes
//!
//! [`astrix_core::AutofixPolicy`] is a property of the rule: *may this kind of
//! rewrite ever run unattended?* [`astrix_core::Confidence`] is a property of
//! one match: *is this particular node really the pattern?*
//! [`Remediation::is_unattended`] requires both, so a rule that is allowed to
//! act unattended still never acts on a guess.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "lang-python")] {
//! use astrix_core::{LanguageId, SourceFile};
//! use astrix_parser::{parse, TsNode};
//! use astrix_rules::builtin_registry;
//!
//! let source = SourceFile::new(
//!     "app.py",
//!     LanguageId::Python,
//!     "import yaml\ncfg = yaml.load(raw)\n",
//! );
//! let tree = parse(&source)?;
//! let registry = builtin_registry::<TsNode<'_>>();
//!
//! let findings = registry.scan(&tree.root(), &source);
//! assert_eq!(findings.len(), 1);
//! assert_eq!(findings[0].rule_id.as_str(), "astrix.python.unsafe-yaml-load");
//! # }
//! # Ok::<(), astrix_core::AstrixError>(())
//! ```

pub mod python;
pub mod registry;

pub use registry::{BoxedRule, Remediation, RuleRegistry};

use astrix_core::AstNode;

/// A registry holding every built-in rule, for every supported language.
pub fn builtin_registry<'tree, N>() -> RuleRegistry<'tree, N>
where
    N: AstNode<'tree> + Send + Sync + 'tree,
{
    let mut registry = RuleRegistry::new();
    python::register_all(&mut registry);
    registry
}

#[cfg(test)]
mod tests {
    use super::builtin_registry;
    use astrix_core::{AutofixPolicy, Confidence, LanguageId, Severity, SourceFile};
    use astrix_parser::{parse, TsNode};

    fn python(text: &str) -> SourceFile {
        SourceFile::new("app/main.py", LanguageId::Python, text)
    }

    fn registry<'tree>() -> super::RuleRegistry<'tree, TsNode<'tree>> {
        builtin_registry()
    }

    #[test]
    fn the_builtin_registry_is_not_empty_and_has_unique_rule_ids() {
        let registry = registry();
        let mut ids: Vec<&str> = registry.rule_ids().collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();

        assert!(count > 0);
        assert_eq!(ids.len(), count, "rule ids must be unique");
    }

    #[test]
    fn every_automatic_rule_states_why_its_rewrite_preserves_behaviour() {
        for metadata in registry().metadata() {
            if metadata.autofix == AutofixPolicy::Automatic {
                assert!(
                    !metadata.equivalence_argument.trim().is_empty(),
                    "rule `{}` may rewrite unattended but states no equivalence argument",
                    metadata.id
                );
            }
        }
    }

    #[test]
    fn every_rule_declares_at_least_one_language_and_one_cve() {
        for metadata in registry().metadata() {
            assert!(!metadata.languages.is_empty(), "rule `{}` targets no language", metadata.id);
            assert!(!metadata.cves.is_empty(), "rule `{}` cites no CVE", metadata.id);
        }
    }

    #[test]
    fn unsafe_yaml_load_is_detected_with_certainty_when_the_import_proves_it() {
        let source = python("import yaml\ncfg = yaml.load(raw)\n");
        let tree = parse(&source).expect("parses");
        let findings = registry().scan(&tree.root(), &source);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Certain);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cves[0].as_str(), "CVE-2017-18342");
    }

    #[test]
    fn an_import_alias_is_followed() {
        let source = python("import yaml as y\ncfg = y.load(raw)\n");
        let tree = parse(&source).expect("parses");
        let findings = registry().scan(&tree.root(), &source);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Certain);
    }

    #[test]
    fn a_lookalike_receiver_with_no_import_is_only_tentative() {
        let source = python("yaml = Config()\ncfg = yaml.load(raw)\n");
        let tree = parse(&source).expect("parses");
        let findings = registry().scan(&tree.root(), &source);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Tentative);
    }

    #[test]
    fn a_safe_loader_is_not_a_finding() {
        let source = python("import yaml\ncfg = yaml.load(raw, Loader=yaml.SafeLoader)\n");
        let tree = parse(&source).expect("parses");

        assert!(registry().scan(&tree.root(), &source).is_empty());
    }

    #[test]
    fn safe_load_itself_is_not_a_finding() {
        let source = python("import yaml\ncfg = yaml.safe_load(raw)\n");
        let tree = parse(&source).expect("parses");

        assert!(registry().scan(&tree.root(), &source).is_empty());
    }

    #[test]
    fn an_explicitly_unsafe_loader_is_a_finding() {
        let source = python("import yaml\ncfg = yaml.load(raw, Loader=yaml.UnsafeLoader)\n");
        let tree = parse(&source).expect("parses");
        let findings = registry().scan(&tree.root(), &source);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("loader"), "{}", findings[0].message);
    }

    #[test]
    fn the_remediation_for_a_missing_loader_replaces_only_the_attribute() {
        let source = python("import yaml\ncfg = yaml.load(raw)\n");
        let tree = parse(&source).expect("parses");
        let remediations = registry().remediate(&tree.root(), &source).expect("plans");

        assert_eq!(remediations.len(), 1);
        let edits = remediations[0].script.edits();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].replacement, "safe_load");
        assert_eq!(source.slice(edits[0].span), "load");
        assert!(remediations[0].is_unattended());
    }

    #[test]
    fn the_remediation_for_an_unsafe_loader_replaces_only_the_loader() {
        let source = python("import yaml\ncfg = yaml.load(raw, Loader=yaml.Loader)\n");
        let tree = parse(&source).expect("parses");
        let remediations = registry().remediate(&tree.root(), &source).expect("plans");

        let edits = remediations[0].script.edits();
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].replacement, "yaml.SafeLoader");
        assert_eq!(source.slice(edits[0].span), "yaml.Loader");
    }

    #[test]
    fn a_tentative_match_is_reported_but_not_eligible_for_an_unattended_fix() {
        let source = python("yaml = Config()\ncfg = yaml.load(raw)\n");
        let tree = parse(&source).expect("parses");
        let remediations = registry().remediate(&tree.root(), &source).expect("plans");

        assert_eq!(remediations.len(), 1);
        assert!(!remediations[0].is_unattended());
    }

    #[test]
    fn findings_are_reported_in_source_order() {
        let source = python("import yaml\na = yaml.load(x)\nb = yaml.load(y)\nc = yaml.load(z)\n");
        let tree = parse(&source).expect("parses");
        let findings = registry().scan(&tree.root(), &source);

        let starts: Vec<usize> = findings.iter().map(|f| f.span.bytes.start).collect();
        let mut sorted = starts.clone();
        sorted.sort_unstable();

        assert_eq!(findings.len(), 3);
        assert_eq!(starts, sorted);
    }

    #[test]
    fn scanning_is_reproducible() {
        let source = python("import yaml\ncfg = yaml.load(raw)\n");
        let tree = parse(&source).expect("parses");

        assert_eq!(registry().scan(&tree.root(), &source), registry().scan(&tree.root(), &source));
    }

    #[test]
    fn rules_for_another_language_are_never_offered_a_node() {
        let source = SourceFile::new("app.js", LanguageId::JavaScript, "yaml.load(raw)\n");
        let tree = parse(&source).expect("parses");

        assert!(registry().scan(&tree.root(), &source).is_empty());
    }
}
