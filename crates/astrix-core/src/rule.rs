//! CVE pattern matching: the [`RemediationRule`] contract and its vocabulary.

use core::fmt;

use crate::error::Result;
use crate::language::LanguageId;
use crate::mutator::EditScript;
use crate::span::SourceSpan;
use crate::visitor::VisitContext;

/// Stable identifier of a rule, for example `astrix.python.unsafe-yaml-load`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(Box<str>);

impl RuleId {
    /// Wraps an identifier string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into().into_boxed_str())
    }

    /// Borrows the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for RuleId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

/// A CVE identifier, for example `CVE-2017-18342`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CveId(Box<str>);

impl CveId {
    /// Wraps a CVE identifier string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into().into_boxed_str())
    }

    /// Borrows the identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for CveId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

/// How damaging the vulnerability is, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational finding.
    Low,
    /// Exploitable under specific conditions.
    Medium,
    /// Directly exploitable.
    High,
    /// Remote code execution or equivalent.
    Critical,
}

impl Severity {
    /// Stable lowercase name, used in fixture manifests and reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sure the rule is that the match is a true positive.
///
/// Under the zero-breakage policy only [`Confidence::Certain`] findings are
/// eligible for an unattended rewrite; anything weaker is reported for review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Syntactic shape matches, but the surrounding semantics are unproven.
    Tentative,
    /// Strong evidence, with one unverifiable assumption remaining.
    Probable,
    /// The match is proven from the AST alone.
    Certain,
}

impl Confidence {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tentative => "tentative",
            Self::Probable => "probable",
            Self::Certain => "certain",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a rule may rewrite unattended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutofixPolicy {
    /// The rewrite is provably semantics-preserving; apply it automatically.
    Automatic,
    /// The rewrite is sound but observable (for example it changes an error
    /// type); produce the patch but require a human to approve it.
    RequiresReview,
    /// No safe mechanical rewrite exists; report only.
    DetectOnly,
}

impl AutofixPolicy {
    /// Returns `true` when the engine may apply the patch without review.
    pub const fn is_automatic(self) -> bool {
        matches!(self, Self::Automatic)
    }
}

/// Everything static about a rule: what it detects and what it is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    /// Stable rule identifier.
    pub id: RuleId,
    /// One-line human-readable summary.
    pub title: String,
    /// CVEs this rule remediates.
    pub cves: Vec<CveId>,
    /// CWE classes this rule addresses, for example `CWE-502`.
    pub cwes: Vec<String>,
    /// Severity of the underlying vulnerability.
    pub severity: Severity,
    /// Languages the rule can run against.
    pub languages: Vec<LanguageId>,
    /// Grammar node kinds worth offering to this rule.
    ///
    /// An empty list means "every named node"; naming kinds lets the engine
    /// skip the rule for irrelevant nodes, which keeps a large rule set cheap.
    pub node_kinds: Vec<String>,
    /// Why the rewrite preserves observable behaviour. This is the written
    /// half of the zero-breakage argument; the sandbox is the executed half.
    pub equivalence_argument: String,
    /// Whether the rewrite may be applied unattended.
    pub autofix: AutofixPolicy,
}

impl RuleMetadata {
    /// Starts a metadata builder for `id` and `title`.
    pub fn builder(id: impl Into<String>, title: impl Into<String>) -> RuleMetadataBuilder {
        RuleMetadataBuilder {
            metadata: Self {
                id: RuleId::new(id),
                title: title.into(),
                cves: Vec::new(),
                cwes: Vec::new(),
                severity: Severity::Medium,
                languages: Vec::new(),
                node_kinds: Vec::new(),
                equivalence_argument: String::new(),
                autofix: AutofixPolicy::DetectOnly,
            },
        }
    }

    /// Returns `true` when this rule declares support for `language`.
    pub fn supports(&self, language: LanguageId) -> bool {
        self.languages.contains(&language)
    }

    /// Returns `true` when a node of kind `kind` is worth offering to the rule.
    pub fn is_interested_in(&self, kind: &str) -> bool {
        self.node_kinds.is_empty() || self.node_kinds.iter().any(|known| known == kind)
    }
}

/// Fluent builder for [`RuleMetadata`].
#[derive(Debug, Clone)]
pub struct RuleMetadataBuilder {
    metadata: RuleMetadata,
}

impl RuleMetadataBuilder {
    /// Adds the CVEs this rule remediates.
    pub fn cves<I: IntoIterator<Item = T>, T: Into<String>>(mut self, cves: I) -> Self {
        self.metadata.cves.extend(cves.into_iter().map(CveId::new));
        self
    }

    /// Adds the CWE classes this rule addresses.
    pub fn cwes<I: IntoIterator<Item = T>, T: Into<String>>(mut self, cwes: I) -> Self {
        self.metadata.cwes.extend(cwes.into_iter().map(Into::into));
        self
    }

    /// Sets the severity of the underlying vulnerability.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.metadata.severity = severity;
        self
    }

    /// Declares the languages the rule runs against.
    pub fn languages<I: IntoIterator<Item = LanguageId>>(mut self, languages: I) -> Self {
        self.metadata.languages.extend(languages);
        self
    }

    /// Narrows the rule to specific grammar node kinds.
    pub fn node_kinds<I: IntoIterator<Item = T>, T: Into<String>>(mut self, kinds: I) -> Self {
        self.metadata.node_kinds.extend(kinds.into_iter().map(Into::into));
        self
    }

    /// Records why the rewrite preserves observable behaviour.
    pub fn equivalence_argument(mut self, argument: impl Into<String>) -> Self {
        self.metadata.equivalence_argument = argument.into();
        self
    }

    /// Sets the autofix policy.
    pub fn autofix(mut self, policy: AutofixPolicy) -> Self {
        self.metadata.autofix = policy;
        self
    }

    /// Finishes the builder.
    pub fn build(self) -> RuleMetadata {
        self.metadata
    }
}

/// One vulnerable location reported by a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Rule that produced this finding.
    pub rule_id: RuleId,
    /// CVEs implicated at this location.
    pub cves: Vec<CveId>,
    /// Severity carried over from the rule.
    pub severity: Severity,
    /// How sure the rule is about this specific match.
    pub confidence: Confidence,
    /// Operator-facing explanation of what is wrong here.
    pub message: String,
    /// Location of the offending construct.
    pub span: SourceSpan,
    /// Grammar kind of the matched node, kept for debugging rule drift.
    pub node_kind: String,
}

impl Finding {
    /// Builds a finding for `node_kind` at `span`.
    pub fn new(
        metadata: &RuleMetadata,
        span: SourceSpan,
        node_kind: impl Into<String>,
        confidence: Confidence,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: metadata.id.clone(),
            cves: metadata.cves.clone(),
            severity: metadata.severity,
            confidence,
            message: message.into(),
            span,
            node_kind: node_kind.into(),
        }
    }

    /// Canonical sort key, so a report of findings is reproducible.
    pub fn sort_key(&self) -> (usize, usize, &str) {
        (self.span.bytes.start, self.span.bytes.end, self.rule_id.as_str())
    }
}

/// A detector for one vulnerability class, paired with its remediation.
///
/// Detection and remediation are deliberately two methods. The engine runs
/// [`RemediationRule::detect`] over the whole tree first, then asks for a plan
/// only for the findings it intends to act on — so a `DetectOnly` rule, or a
/// run in report-only mode, never has to synthesise code it will not use.
///
/// `remediate` returns an [`EditScript`] rather than mutating anything: a rule
/// describes the change in terms of original-buffer spans and never applies it.
/// Applying is [`crate::AstMutator`]'s job, and keeping the two apart is what
/// lets the engine validate, order and reject edits before any byte moves.
pub trait RemediationRule<'tree> {
    /// Node type of the backend this rule runs against.
    type Node: crate::node::AstNode<'tree>;

    /// Static description of the rule.
    fn metadata(&self) -> &RuleMetadata;

    /// Returns `true` when the rule can run against `language`.
    fn supports(&self, language: LanguageId) -> bool {
        self.metadata().supports(language)
    }

    /// Inspects one node and reports a finding if it is vulnerable.
    ///
    /// Must be pure: the same node in the same buffer always yields the same
    /// answer.
    fn detect(&self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> Option<Finding>;

    /// Produces the edits that remediate `finding`.
    ///
    /// `ctx` is positioned on the same node that produced the finding.
    fn remediate(
        &self,
        ctx: &VisitContext<'_, 'tree, Self::Node>,
        finding: &Finding,
    ) -> Result<EditScript>;
}

#[cfg(test)]
mod tests {
    use super::{AutofixPolicy, Confidence, RuleMetadata, Severity};
    use crate::language::LanguageId;

    #[test]
    fn builder_collects_metadata() {
        let metadata = RuleMetadata::builder("astrix.python.unsafe-yaml-load", "Unsafe yaml.load")
            .cves(["CVE-2017-18342"])
            .cwes(["CWE-502"])
            .severity(Severity::Critical)
            .languages([LanguageId::Python])
            .node_kinds(["call"])
            .equivalence_argument("safe_load accepts the same inputs for non-tagged YAML")
            .autofix(AutofixPolicy::Automatic)
            .build();

        assert_eq!(metadata.id.as_str(), "astrix.python.unsafe-yaml-load");
        assert_eq!(metadata.cves.len(), 1);
        assert!(metadata.supports(LanguageId::Python));
        assert!(!metadata.supports(LanguageId::Go));
        assert!(metadata.autofix.is_automatic());
    }

    #[test]
    fn empty_node_kinds_means_every_node_is_offered() {
        let open = RuleMetadata::builder("r.open", "Open").build();
        let narrow = RuleMetadata::builder("r.narrow", "Narrow").node_kinds(["call"]).build();

        assert!(open.is_interested_in("module"));
        assert!(narrow.is_interested_in("call"));
        assert!(!narrow.is_interested_in("module"));
    }

    #[test]
    fn confidence_and_severity_order_from_weakest_to_strongest() {
        assert!(Confidence::Certain > Confidence::Probable);
        assert!(Confidence::Probable > Confidence::Tentative);
        assert!(Severity::Critical > Severity::Low);
    }
}
