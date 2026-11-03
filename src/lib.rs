//! ASTrix — autonomous CVE remediation and AST refactoring, under a
//! zero-breakage policy.
//!
//! This crate is the façade: it wires the five member crates into one
//! pipeline and exposes [`Engine`]. Everything it does is composition — the
//! contracts live in [`astrix_core`], the grammars in [`astrix_parser`], the
//! CVE knowledge in [`astrix_rules`], the byte splicing in
//! [`astrix_rewriter`], and the verification in [`astrix_sandbox`].
//!
//! ```text
//!   SourceFile
//!       │  astrix-parser
//!       ▼
//!     tree ───────────── astrix-rules ──────────▶ [Finding + EditScript]
//!                                                        │
//!                                          astrix-rewriter│
//!                                                        ▼
//!                                                      Patch
//!                                                        │
//!                                         astrix-sandbox │
//!                                                        ▼
//!                                              Verdict: accept / reject
//! ```
//!
//! # Zero-breakage policy
//!
//! Three rules hold across the whole pipeline:
//!
//! 1. **A malformed file is never rewritten.** If the parser had to guess, span
//!    arithmetic cannot be trusted, so [`Engine::remediate`] refuses the file.
//! 2. **Only certain findings are fixed unattended.** A rewrite needs both an
//!    [`astrix_core::AutofixPolicy::Automatic`] rule and a
//!    [`astrix_core::Confidence::Certain`] match. Everything else is reported.
//! 3. **A patch is a proposal.** Nothing is written to disk by this crate.
//!    [`Engine::verify`] gathers evidence and returns a verdict; committing is
//!    the caller's decision.
//!
//! # Example
//!
//! ```
//! use astrix::Engine;
//! use astrix_core::{LanguageId, SourceFile};
//!
//! let source = SourceFile::new(
//!     "app.py",
//!     LanguageId::Python,
//!     "import yaml\ncfg = yaml.load(raw)\n",
//! );
//!
//! let outcome = Engine::new().remediate(&source)?;
//!
//! assert_eq!(outcome.findings.len(), 1);
//! assert_eq!(
//!     outcome.patch.expect("a certain finding is fixed").rewritten,
//!     "import yaml\ncfg = yaml.safe_load(raw)\n",
//! );
//! # Ok::<(), astrix_core::AstrixError>(())
//! ```

use astrix_core::{AstMutator, Confidence, EditScript, Finding, Patch, Result, SourceFile};
use astrix_parser::{parse, TsNode};
use astrix_rewriter::SpanRewriter;
use astrix_rules::{builtin_registry, Remediation};
use astrix_sandbox::{
    CommandGate, StaticGate, VerificationPlan, VerificationReport, ZeroBreakageGate,
};

pub use astrix_core as core_contracts;
pub use astrix_parser as parser;
pub use astrix_rewriter as rewriter;
pub use astrix_rules as rules;
pub use astrix_sandbox as sandbox;

/// What one remediation pass found, fixed, and deliberately left alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationOutcome {
    /// Every finding, in source order.
    pub findings: Vec<Finding>,
    /// The candidate patch, or `None` when nothing was eligible for an
    /// unattended fix.
    pub patch: Option<Patch>,
    /// Findings that were reported but not fixed, because the rule requires
    /// review or the match was not certain.
    pub deferred: Vec<Finding>,
}

impl RemediationOutcome {
    /// Returns `true` when the pass found nothing.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Returns `true` when at least one finding was fixed.
    pub fn has_patch(&self) -> bool {
        self.patch.as_ref().is_some_and(|patch| !patch.is_noop())
    }
}

/// Re-parses a candidate buffer, for use as a sandbox
/// [`astrix_sandbox::SyntaxCheck`].
///
/// # Errors
///
/// Returns the parser's error, or [`astrix_core::AstrixError::MalformedSyntax`] when the
/// rewritten buffer no longer parses cleanly.
pub fn syntax_check(source: &SourceFile) -> Result<()> {
    parse(source)?.require_well_formed()
}

/// The ASTrix pipeline.
///
/// An engine holds no mutable state, so one instance can serve a whole scan.
#[derive(Debug, Clone, Copy, Default)]
pub struct Engine {
    rewriter: SpanRewriter,
}

impl Engine {
    /// Creates an engine with every built-in rule registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports every vulnerable location in `source`, in source order.
    ///
    /// # Errors
    ///
    /// Returns [`astrix_core::AstrixError::MalformedSyntax`] when `source` does not parse
    /// cleanly, and [`astrix_core::AstrixError::UnsupportedLanguage`] when no grammar is
    /// linked for its language.
    pub fn analyze(&self, source: &SourceFile) -> Result<Vec<Finding>> {
        let tree = parse(source)?;
        tree.require_well_formed()?;

        let findings = builtin_registry::<TsNode<'_>>().scan(&tree.root(), source);
        Ok(findings)
    }

    /// Detects, plans and applies every unattended-eligible fix in `source`.
    ///
    /// Findings that need review, or whose match is not certain, are returned
    /// in [`RemediationOutcome::deferred`] and left out of the patch.
    ///
    /// # Errors
    ///
    /// Returns [`astrix_core::AstrixError::MalformedSyntax`] when `source` does not parse
    /// cleanly, [`astrix_core::AstrixError::OverlappingEdits`] when two rules claim the
    /// same bytes, and any error a rule raises while planning.
    pub fn remediate(&self, source: &SourceFile) -> Result<RemediationOutcome> {
        let tree = parse(source)?;
        tree.require_well_formed()?;

        let remediations = builtin_registry::<TsNode<'_>>().remediate(&tree.root(), source)?;

        let mut findings = Vec::with_capacity(remediations.len());
        let mut deferred = Vec::new();
        let mut scripts: Vec<EditScript> = Vec::new();

        for Remediation { finding, script, autofix } in remediations {
            let unattended = autofix.is_automatic() && finding.confidence == Confidence::Certain;

            if unattended {
                scripts.push(script);
            } else {
                deferred.push(finding.clone());
            }
            findings.push(finding);
        }

        let patch = if scripts.is_empty() {
            None
        } else {
            Some(self.rewriter.apply_all(source, &scripts)?)
        };

        Ok(RemediationOutcome { findings, patch, deferred })
    }

    /// Runs the zero-breakage gate over `patch`.
    ///
    /// Uses [`CommandGate`] when `plan` asks for a child process and
    /// [`StaticGate`] otherwise, so a dry run never pays for a process launch.
    ///
    /// # Errors
    ///
    /// Returns [`astrix_core::AstrixError::Sandbox`] when the gate itself cannot run. A
    /// patch that fails its checks is reported as a rejection inside the
    /// report, not as an error.
    pub fn verify(&self, patch: &Patch, plan: &VerificationPlan) -> Result<VerificationReport> {
        if plan.is_static_only() {
            StaticGate::new(syntax_check as fn(&SourceFile) -> Result<()>).verify(patch, plan)
        } else {
            CommandGate::new(syntax_check as fn(&SourceFile) -> Result<()>).verify(patch, plan)
        }
    }

    /// Remediates `source` and returns the patch only if the gate accepts it.
    ///
    /// This is the whole zero-breakage promise in one call: a patch that
    /// cannot be shown to preserve behaviour is discarded, and the caller gets
    /// the evidence either way.
    ///
    /// # Errors
    ///
    /// Propagates [`Engine::remediate`] and [`Engine::verify`] errors.
    pub fn remediate_verified(
        &self,
        source: &SourceFile,
        plan: &VerificationPlan,
    ) -> Result<(RemediationOutcome, Option<VerificationReport>)> {
        let outcome = self.remediate(source)?;

        let Some(patch) = outcome.patch.as_ref() else {
            return Ok((outcome, None));
        };

        let report = self.verify(patch, plan)?;
        if report.verdict().is_accepted() {
            Ok((outcome, Some(report)))
        } else {
            Ok((
                RemediationOutcome {
                    findings: outcome.findings,
                    patch: None,
                    deferred: outcome.deferred,
                },
                Some(report),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Engine, RemediationOutcome};
    use astrix_core::{AstrixError, LanguageId, SourceFile};
    use astrix_sandbox::VerificationPlan;

    fn python(text: &str) -> SourceFile {
        SourceFile::new("app/main.py", LanguageId::Python, text)
    }

    fn remediate(text: &str) -> RemediationOutcome {
        Engine::new().remediate(&python(text)).expect("remediation runs")
    }

    #[test]
    fn a_clean_file_yields_no_findings_and_no_patch() {
        let outcome = remediate("import yaml\ncfg = yaml.safe_load(raw)\n");

        assert!(outcome.is_clean());
        assert!(outcome.patch.is_none());
    }

    #[test]
    fn a_certain_finding_is_fixed() {
        let outcome = remediate("import yaml\ncfg = yaml.load(raw)\n");

        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.deferred.is_empty());
        assert_eq!(
            outcome.patch.expect("patched").rewritten,
            "import yaml\ncfg = yaml.safe_load(raw)\n"
        );
    }

    #[test]
    fn a_tentative_finding_is_reported_but_deferred() {
        let outcome = remediate("yaml = Config()\ncfg = yaml.load(raw)\n");

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.deferred.len(), 1);
        assert!(outcome.patch.is_none());
        assert!(!outcome.has_patch());
    }

    #[test]
    fn several_findings_are_fixed_in_one_patch() {
        let outcome = remediate("import yaml\na = yaml.load(x)\nb = yaml.load(y)\n");
        let patch = outcome.patch.expect("patched");

        assert_eq!(outcome.findings.len(), 2);
        assert_eq!(patch.applied.len(), 2);
        assert_eq!(patch.rewritten, "import yaml\na = yaml.safe_load(x)\nb = yaml.safe_load(y)\n");
    }

    #[test]
    fn a_malformed_file_is_refused_rather_than_rewritten() {
        let error = Engine::new()
            .remediate(&python("import yaml\ndef broken(:\n    yaml.load(x)\n"))
            .expect_err("a file the parser had to guess at must not be rewritten");

        assert!(matches!(error, AstrixError::MalformedSyntax { .. }));
    }

    #[test]
    fn remediation_is_byte_for_byte_reproducible() {
        let source = python("import yaml\na = yaml.load(x)\nb = yaml.load(y)\n");
        let engine = Engine::new();

        let first = engine.remediate(&source).expect("runs").patch.expect("patched");
        let second = engine.remediate(&source).expect("runs").patch.expect("patched");

        assert_eq!(first.rewritten, second.rewritten);
        assert_eq!(first.digest, second.digest);
    }

    #[test]
    fn the_static_gate_accepts_a_sound_patch() {
        let source = python("import yaml\ncfg = yaml.load(raw)\n");
        let engine = Engine::new();
        let patch = engine.remediate(&source).expect("runs").patch.expect("patched");

        let report =
            engine.verify(&patch, &VerificationPlan::static_only(".")).expect("the gate runs");

        assert!(report.verdict().is_accepted(), "{}", report.summary());
    }

    #[test]
    fn analyze_reports_without_rewriting() {
        let source = python("import yaml\ncfg = yaml.load(raw)\n");
        let findings = Engine::new().analyze(&source).expect("runs");

        assert_eq!(findings.len(), 1);
        assert_eq!(source.text(), "import yaml\ncfg = yaml.load(raw)\n");
    }

    #[test]
    fn remediate_verified_returns_no_patch_when_nothing_is_eligible() {
        let source = python("import yaml\ncfg = yaml.safe_load(raw)\n");
        let (outcome, report) = Engine::new()
            .remediate_verified(&source, &VerificationPlan::static_only("."))
            .expect("runs");

        assert!(outcome.is_clean());
        assert!(report.is_none());
    }

    #[test]
    fn an_unsupported_language_is_reported_not_silently_skipped() {
        let source = SourceFile::new("main.go", LanguageId::Go, "package main\n");

        assert!(matches!(
            Engine::new().analyze(&source),
            Err(AstrixError::UnsupportedLanguage(LanguageId::Go))
        ));
    }
}
