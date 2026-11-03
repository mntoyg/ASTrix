//! The zero-breakage gate: the contract, and the checks that need no process.

use std::time::Instant;

use astrix_core::{AstrixError, Patch, Result, SourceFile};

use crate::plan::{CheckKind, IsolationLevel, VerificationPlan};
use crate::report::{CheckOutcome, VerificationReport};

/// The last authority before a patch is written to disk.
///
/// A gate never mutates the patch and never commits it. It answers one
/// question — *does this candidate still behave like the original?* — and
/// returns the evidence. The caller decides what to do with an
/// [`crate::Verdict`], which is what keeps "verified" and "applied" separate
/// concepts in the engine.
pub trait ZeroBreakageGate {
    /// Runs `plan` against `patch` and reports what was observed.
    ///
    /// # Errors
    ///
    /// Returns [`AstrixError::Sandbox`] when the gate itself could not run.
    /// A patch that fails its checks is **not** an error: that is a
    /// [`crate::Verdict::Rejected`] inside a successful report.
    fn verify(&self, patch: &Patch, plan: &VerificationPlan) -> Result<VerificationReport>;

    /// Verifies `patch` and turns a non-acceptance into an error.
    ///
    /// Convenience for callers that treat anything short of acceptance as a
    /// hard stop.
    ///
    /// # Errors
    ///
    /// Returns [`AstrixError::ZeroBreakageViolation`] when the verdict is not
    /// [`crate::Verdict::Accepted`].
    fn require_accepted(
        &self,
        patch: &Patch,
        plan: &VerificationPlan,
    ) -> Result<VerificationReport> {
        let report = self.verify(patch, plan)?;
        let verdict = report.verdict();
        if verdict.is_accepted() {
            Ok(report)
        } else {
            Err(AstrixError::ZeroBreakageViolation { reason: verdict.to_string() })
        }
    }
}

/// Re-parses a rewritten buffer to prove it is still well formed.
///
/// The sandbox stays free of grammar dependencies by taking this as a
/// parameter: the engine supplies an implementation backed by `astrix-parser`,
/// and a test can supply a stub.
pub trait SyntaxCheck {
    /// Returns `Ok(())` when `source` parses with no error or missing nodes.
    ///
    /// # Errors
    ///
    /// Returns the backend's parse error, which is reported as a failing
    /// [`CheckKind::SyntaxValid`] rather than propagated.
    fn check(&self, source: &SourceFile) -> Result<()>;
}

impl<F> SyntaxCheck for F
where
    F: Fn(&SourceFile) -> Result<()>,
{
    fn check(&self, source: &SourceFile) -> Result<()> {
        self(source)
    }
}

/// A [`SyntaxCheck`] that cannot check anything.
///
/// Reports [`CheckKind::SyntaxValid`] as skipped rather than passed, so a
/// gate built without a parser can never claim a syntax guarantee it does not
/// have.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSyntaxCheck;

/// The checks that need nothing but the patch itself.
///
/// `StaticGate` is cheap enough to run on every candidate and is the floor
/// every stronger gate builds on: [`crate::CommandGate`] runs these first and
/// only pays for a process launch if they hold.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticGate<S> {
    syntax: Option<S>,
}

impl StaticGate<NoSyntaxCheck> {
    /// A gate with no parser available; syntax validity is reported as skipped.
    pub fn without_syntax_check() -> Self {
        Self { syntax: None }
    }
}

impl<S: SyntaxCheck> StaticGate<S> {
    /// A gate that re-parses candidates with `syntax`.
    pub fn new(syntax: S) -> Self {
        Self { syntax: Some(syntax) }
    }

    /// Runs the static part of `plan` into `report`.
    ///
    /// Exposed so a stronger gate can reuse the static floor without
    /// reimplementing it.
    pub fn run_static_checks(
        &self,
        patch: &Patch,
        plan: &VerificationPlan,
        report: &mut VerificationReport,
    ) {
        if plan.requires(CheckKind::EditIntegrity) {
            report.record(edit_integrity(patch));
        }
        if plan.requires(CheckKind::EffectiveChange) {
            report.record(effective_change(patch));
        }
        if plan.requires(CheckKind::SyntaxValid) {
            match self.syntax_valid(patch) {
                Some(outcome) => {
                    report.record(outcome);
                }
                None => {
                    report.skip(CheckKind::SyntaxValid);
                }
            }
        }
        if plan.requires(CheckKind::AstShapeStable) {
            report.skip(CheckKind::AstShapeStable);
        }
    }

    fn syntax_valid(&self, patch: &Patch) -> Option<CheckOutcome> {
        let syntax = self.syntax.as_ref()?;
        let started = Instant::now();
        Some(match syntax.check(&patch.candidate_source()) {
            Ok(()) => CheckOutcome::passed(
                CheckKind::SyntaxValid,
                "the rewritten buffer parses cleanly",
                started.elapsed(),
            ),
            Err(error) => {
                CheckOutcome::failed(CheckKind::SyntaxValid, error.to_string(), started.elapsed())
            }
        })
    }
}

/// Proves every applied edit still describes the buffer it was computed against.
///
/// This is the cheapest way to catch a stale finding: if the source moved
/// between detection and rewriting, the displaced text will not match.
fn edit_integrity(patch: &Patch) -> CheckOutcome {
    let started = Instant::now();
    for edit in &patch.applied {
        let actual = patch.original.get(edit.span.start..edit.span.end);
        if actual != Some(edit.original_text.as_str()) {
            return CheckOutcome::failed(
                CheckKind::EditIntegrity,
                format!(
                    "edit at {} expected {:?} but the original buffer holds {:?}",
                    edit.span, edit.original_text, actual
                ),
                started.elapsed(),
            );
        }
    }
    CheckOutcome::passed(
        CheckKind::EditIntegrity,
        format!("{} edit(s) match the original buffer", patch.applied.len()),
        started.elapsed(),
    )
}

fn effective_change(patch: &Patch) -> CheckOutcome {
    let started = Instant::now();
    if patch.is_noop() {
        CheckOutcome::failed(
            CheckKind::EffectiveChange,
            "the rewrite left the buffer unchanged, so nothing was remediated",
            started.elapsed(),
        )
    } else {
        CheckOutcome::passed(
            CheckKind::EffectiveChange,
            format!("{} edit(s) changed the buffer", patch.applied.len()),
            started.elapsed(),
        )
    }
}

impl<S: SyntaxCheck> ZeroBreakageGate for StaticGate<S> {
    fn verify(&self, patch: &Patch, plan: &VerificationPlan) -> Result<VerificationReport> {
        let mut report = VerificationReport::new(IsolationLevel::None, patch.digest.clone());
        self.run_static_checks(patch, plan, &mut report);

        for check in &plan.required_checks {
            if !check.is_static() {
                report.skip(*check);
            }
        }

        Ok(report)
    }
}

impl SyntaxCheck for NoSyntaxCheck {
    fn check(&self, _source: &SourceFile) -> Result<()> {
        Err(AstrixError::Sandbox("no syntax backend was supplied".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::{StaticGate, SyntaxCheck, ZeroBreakageGate};
    use crate::plan::{CheckKind, VerificationPlan};
    use crate::report::Verdict;
    use astrix_core::{
        AppliedEdit, AstrixError, ByteSpan, LanguageId, Patch, Result, RuleId, SourceFile,
    };

    fn patch(original: &str, rewritten: &str, applied: Vec<AppliedEdit>) -> Patch {
        Patch {
            path: "app/main.py".into(),
            language: LanguageId::Python,
            original: original.to_owned(),
            rewritten: rewritten.to_owned(),
            applied,
            digest: "test-digest".to_owned(),
        }
    }

    fn edit(span: ByteSpan, original_text: &str, replacement: &str) -> AppliedEdit {
        AppliedEdit {
            span,
            original_text: original_text.to_owned(),
            replacement: replacement.to_owned(),
            rule_id: RuleId::new("astrix.test.rule"),
        }
    }

    fn accepting_syntax() -> impl SyntaxCheck {
        |_: &SourceFile| -> Result<()> { Ok(()) }
    }

    fn rejecting_syntax() -> impl SyntaxCheck {
        |_: &SourceFile| -> Result<()> {
            Err(AstrixError::MalformedSyntax { path: "app/main.py".into(), count: 1 })
        }
    }

    #[test]
    fn a_sound_patch_is_accepted() {
        let candidate = patch(
            "cfg = yaml.load(raw)\n",
            "cfg = yaml.safe_load(raw)\n",
            vec![edit(ByteSpan::new(6, 15), "yaml.load", "yaml.safe_load")],
        );
        let report = StaticGate::new(accepting_syntax())
            .verify(&candidate, &VerificationPlan::static_only("."))
            .expect("the gate runs");

        assert_eq!(report.verdict(), Verdict::Accepted);
    }

    #[test]
    fn an_edit_that_does_not_match_the_original_buffer_is_rejected() {
        let candidate = patch(
            "cfg = yaml.load(raw)\n",
            "cfg = yaml.safe_load(raw)\n",
            vec![edit(ByteSpan::new(6, 15), "json.load", "yaml.safe_load")],
        );
        let report = StaticGate::new(accepting_syntax())
            .verify(&candidate, &VerificationPlan::static_only("."))
            .expect("the gate runs");

        assert_eq!(report.verdict(), Verdict::Rejected { failed: vec![CheckKind::EditIntegrity] });
    }

    #[test]
    fn a_patch_that_changes_nothing_is_rejected() {
        let candidate = patch("cfg = raw\n", "cfg = raw\n", Vec::new());
        let report = StaticGate::new(accepting_syntax())
            .verify(&candidate, &VerificationPlan::static_only("."))
            .expect("the gate runs");

        assert!(report.failures().contains(&CheckKind::EffectiveChange));
    }

    #[test]
    fn a_patch_that_no_longer_parses_is_rejected() {
        let candidate = patch(
            "cfg = yaml.load(raw)\n",
            "cfg = yaml.safe_load(raw\n",
            vec![edit(ByteSpan::new(6, 20), "yaml.load(raw)", "yaml.safe_load(raw")],
        );
        let report = StaticGate::new(rejecting_syntax())
            .verify(&candidate, &VerificationPlan::static_only("."))
            .expect("the gate runs");

        assert!(report.failures().contains(&CheckKind::SyntaxValid));
    }

    #[test]
    fn a_static_gate_never_claims_to_have_run_the_test_suite() {
        let candidate = patch(
            "cfg = yaml.load(raw)\n",
            "cfg = yaml.safe_load(raw)\n",
            vec![edit(ByteSpan::new(6, 15), "yaml.load", "yaml.safe_load")],
        );
        let plan = VerificationPlan::with_test_suite(".", ["pytest", "-q"]);
        let report =
            StaticGate::new(accepting_syntax()).verify(&candidate, &plan).expect("the gate runs");

        assert_eq!(report.verdict(), Verdict::Inconclusive { skipped: vec![CheckKind::TestSuite] });
    }

    #[test]
    fn without_a_parser_syntax_validity_is_skipped_not_assumed() {
        let candidate = patch(
            "cfg = yaml.load(raw)\n",
            "cfg = yaml.safe_load(raw)\n",
            vec![edit(ByteSpan::new(6, 15), "yaml.load", "yaml.safe_load")],
        );
        let report = StaticGate::without_syntax_check()
            .verify(&candidate, &VerificationPlan::static_only("."))
            .expect("the gate runs");

        assert_eq!(
            report.verdict(),
            Verdict::Inconclusive { skipped: vec![CheckKind::SyntaxValid] }
        );
    }

    #[test]
    fn require_accepted_turns_a_rejection_into_an_error() {
        let candidate = patch("cfg = raw\n", "cfg = raw\n", Vec::new());
        let error = StaticGate::new(accepting_syntax())
            .require_accepted(&candidate, &VerificationPlan::static_only("."))
            .expect_err("a no-op patch is not acceptable");

        assert!(matches!(error, AstrixError::ZeroBreakageViolation { .. }));
    }
}
