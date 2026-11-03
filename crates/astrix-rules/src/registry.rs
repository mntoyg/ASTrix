//! The rule registry and the single-pass scan that drives it.

use astrix_core::prelude::*;
use astrix_core::{walk, Finding, WalkStatus};

/// A rule object the registry can hold.
///
/// Rules are stored behind a trait object so one registry can mix built-in and
/// externally supplied rules. `Send + Sync` is required so a scan can be
/// parallelised across files without re-registering.
pub type BoxedRule<'tree, N> = Box<dyn RemediationRule<'tree, Node = N> + Send + Sync + 'tree>;

/// A finding together with the edits that remediate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remediation {
    /// What was found.
    pub finding: Finding,
    /// How to fix it, in original-buffer coordinates.
    pub script: EditScript,
    /// Whether the rule may apply this unattended.
    pub autofix: AutofixPolicy,
}

impl Remediation {
    /// Returns `true` when the engine may apply this without human review.
    ///
    /// Requires both an [`AutofixPolicy::Automatic`] rule and a
    /// [`Confidence::Certain`] match: a rule that is allowed to act
    /// unattended still may not act on a guess.
    pub fn is_unattended(&self) -> bool {
        self.autofix.is_automatic() && self.finding.confidence == Confidence::Certain
    }
}

/// An ordered set of rules, scanned in one tree traversal.
///
/// The registry exists so adding a CVE costs one `register` call and nothing
/// else. It offers each node to every rule that declares an interest in that
/// node's kind, which keeps a large rule set roughly as cheap as a small one.
pub struct RuleRegistry<'tree, N: AstNode<'tree>> {
    rules: Vec<BoxedRule<'tree, N>>,
}

impl<'tree, N: AstNode<'tree>> Default for RuleRegistry<'tree, N> {
    fn default() -> Self {
        Self { rules: Vec::new() }
    }
}

impl<'tree, N: AstNode<'tree>> core::fmt::Debug for RuleRegistry<'tree, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RuleRegistry").field("rules", &self.rule_ids().collect::<Vec<_>>()).finish()
    }
}

impl<'tree, N: AstNode<'tree>> RuleRegistry<'tree, N> {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a rule.
    pub fn register(
        &mut self,
        rule: impl RemediationRule<'tree, Node = N> + Send + Sync + 'tree,
    ) -> &mut Self {
        self.rules.push(Box::new(rule));
        self
    }

    /// Number of registered rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns `true` when no rule is registered.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Identifiers of every registered rule, in registration order.
    pub fn rule_ids(&self) -> impl Iterator<Item = &str> + use<'_, 'tree, N> {
        self.rules.iter().map(|rule| rule.metadata().id.as_str())
    }

    /// Metadata of every registered rule, in registration order.
    pub fn metadata(&self) -> impl Iterator<Item = &RuleMetadata> + use<'_, 'tree, N> {
        self.rules.iter().map(|rule| rule.metadata())
    }

    /// Finds a registered rule by identifier.
    pub fn get(&self, rule_id: &str) -> Option<&BoxedRule<'tree, N>> {
        self.rules.iter().find(|rule| rule.metadata().id.as_str() == rule_id)
    }

    /// Reports every vulnerable location in `root`, in canonical order.
    pub fn scan(&self, root: &N, source: &SourceFile) -> Vec<Finding> {
        let mut findings = walk(
            ScanVisitor {
                registry: self,
                source_language: source.language(),
                findings: Vec::new(),
            },
            root,
            source,
        );
        findings.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        findings
    }

    /// Reports every vulnerable location together with its remediation.
    ///
    /// Detection and planning share one traversal, so a rule always plans
    /// against the very node it matched.
    ///
    /// # Errors
    ///
    /// Propagates the first [`AstrixError`] a rule raises while planning. A
    /// rule that cannot produce a safe edit is expected to return an error
    /// rather than an approximate rewrite.
    pub fn remediate(&self, root: &N, source: &SourceFile) -> Result<Vec<Remediation>> {
        let visitor = RemediateVisitor {
            registry: self,
            source_language: source.language(),
            remediations: Vec::new(),
            error: None,
        };

        let (mut remediations, error) = walk(visitor, root, source);
        if let Some(error) = error {
            return Err(error);
        }

        remediations.sort_by(|left, right| left.finding.sort_key().cmp(&right.finding.sort_key()));
        Ok(remediations)
    }

    fn interested_rules<'reg>(
        &'reg self,
        language: LanguageId,
        kind: &'reg str,
    ) -> impl Iterator<Item = &'reg BoxedRule<'tree, N>> {
        self.rules.iter().filter(move |rule| {
            let metadata = rule.metadata();
            metadata.supports(language) && metadata.is_interested_in(kind)
        })
    }
}

struct ScanVisitor<'reg, 'tree, N: AstNode<'tree>> {
    registry: &'reg RuleRegistry<'tree, N>,
    source_language: LanguageId,
    findings: Vec<Finding>,
}

impl<'tree, N: AstNode<'tree>> AstVisitor<'tree> for ScanVisitor<'_, 'tree, N> {
    type Node = N;
    type Output = Vec<Finding>;

    fn enter(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> VisitFlow {
        for rule in self.registry.interested_rules(self.source_language, ctx.node().kind()) {
            if let Some(finding) = rule.detect(ctx) {
                self.findings.push(finding);
            }
        }
        VisitFlow::Continue
    }

    fn finish(self, _status: WalkStatus) -> Self::Output {
        self.findings
    }
}

struct RemediateVisitor<'reg, 'tree, N: AstNode<'tree>> {
    registry: &'reg RuleRegistry<'tree, N>,
    source_language: LanguageId,
    remediations: Vec<Remediation>,
    error: Option<AstrixError>,
}

impl<'tree, N: AstNode<'tree>> AstVisitor<'tree> for RemediateVisitor<'_, 'tree, N> {
    type Node = N;
    type Output = (Vec<Remediation>, Option<AstrixError>);

    fn enter(&mut self, ctx: &VisitContext<'_, 'tree, Self::Node>) -> VisitFlow {
        for rule in self.registry.interested_rules(self.source_language, ctx.node().kind()) {
            let Some(finding) = rule.detect(ctx) else { continue };
            let metadata = rule.metadata();

            if metadata.autofix == AutofixPolicy::DetectOnly {
                self.remediations.push(Remediation {
                    finding,
                    script: EditScript::new(),
                    autofix: metadata.autofix,
                });
                continue;
            }

            match rule.remediate(ctx, &finding) {
                Ok(script) if script.is_empty() => {
                    self.error = Some(AstrixError::EmptyEditScript {
                        rule_id: finding.rule_id.to_string(),
                        span: finding.span.bytes,
                    });
                    return VisitFlow::Stop;
                }
                Ok(script) => {
                    self.remediations.push(Remediation {
                        finding,
                        script,
                        autofix: metadata.autofix,
                    });
                }
                Err(error) => {
                    self.error = Some(error);
                    return VisitFlow::Stop;
                }
            }
        }
        VisitFlow::Continue
    }

    fn finish(self, _status: WalkStatus) -> Self::Output {
        (self.remediations, self.error)
    }
}
