//! The evidence a gate produces for one candidate patch.

use core::fmt;
use core::time::Duration;

use crate::plan::{CheckKind, IsolationLevel};

/// Result of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// Which check ran.
    pub kind: CheckKind,
    /// Whether it passed.
    pub passed: bool,
    /// Operator-facing detail: the assertion that held, or the failure.
    pub detail: String,
    /// How long the check took.
    pub elapsed: Duration,
}

impl CheckOutcome {
    /// Records a passing check.
    pub fn passed(kind: CheckKind, detail: impl Into<String>, elapsed: Duration) -> Self {
        Self { kind, passed: true, detail: detail.into(), elapsed }
    }

    /// Records a failing check.
    pub fn failed(kind: CheckKind, detail: impl Into<String>, elapsed: Duration) -> Self {
        Self { kind, passed: false, detail: detail.into(), elapsed }
    }
}

impl fmt::Display for CheckOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mark = if self.passed { "pass" } else { "FAIL" };
        write!(f, "[{mark}] {}: {}", self.kind, self.detail)
    }
}

/// The gate's decision about a candidate patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every required check passed; the patch may be committed.
    Accepted,
    /// At least one required check failed; the patch must be discarded.
    Rejected {
        /// Checks that failed, in run order.
        failed: Vec<CheckKind>,
    },
    /// The plan asked for checks this gate cannot run, so no claim is made.
    ///
    /// Distinct from [`Verdict::Rejected`] on purpose: "I did not verify this"
    /// and "I verified this and it breaks" are different facts, and collapsing
    /// them is how a zero-breakage policy quietly stops being one.
    Inconclusive {
        /// Checks the gate could not perform.
        skipped: Vec<CheckKind>,
    },
}

impl Verdict {
    /// Returns `true` only when every required check passed.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => f.write_str("accepted"),
            Self::Rejected { failed } => {
                write!(f, "rejected ({})", join(failed))
            }
            Self::Inconclusive { skipped } => {
                write!(f, "inconclusive ({} not run)", join(skipped))
            }
        }
    }
}

fn join(checks: &[CheckKind]) -> String {
    checks.iter().map(|check| check.as_str()).collect::<Vec<_>>().join(", ")
}

/// Everything a gate observed while verifying one candidate patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Checks that ran, in run order.
    pub checks: Vec<CheckOutcome>,
    /// Checks the plan asked for but the gate could not run.
    pub skipped: Vec<CheckKind>,
    /// How strongly the gate isolated any commands it ran.
    pub isolation: IsolationLevel,
    /// Digest of the candidate buffer that was verified, for audit trails.
    pub verified_digest: String,
}

impl VerificationReport {
    /// Creates an empty report for `isolation` and `verified_digest`.
    pub fn new(isolation: IsolationLevel, verified_digest: impl Into<String>) -> Self {
        Self {
            checks: Vec::new(),
            skipped: Vec::new(),
            isolation,
            verified_digest: verified_digest.into(),
        }
    }

    /// Records a check outcome.
    pub fn record(&mut self, outcome: CheckOutcome) -> &mut Self {
        self.checks.push(outcome);
        self
    }

    /// Records a check the gate could not run.
    pub fn skip(&mut self, kind: CheckKind) -> &mut Self {
        self.skipped.push(kind);
        self
    }

    /// Checks that failed, in run order.
    pub fn failures(&self) -> Vec<CheckKind> {
        self.checks.iter().filter(|check| !check.passed).map(|check| check.kind).collect()
    }

    /// The gate's decision, derived from the recorded outcomes.
    ///
    /// A failure outranks a skip: a patch that breaks the tests is rejected
    /// even if some other check could not run.
    pub fn verdict(&self) -> Verdict {
        let failed = self.failures();
        if !failed.is_empty() {
            return Verdict::Rejected { failed };
        }
        if !self.skipped.is_empty() {
            return Verdict::Inconclusive { skipped: self.skipped.clone() };
        }
        Verdict::Accepted
    }

    /// Total time spent across every check.
    pub fn elapsed(&self) -> Duration {
        self.checks.iter().map(|check| check.elapsed).sum()
    }

    /// Multi-line operator-facing summary.
    pub fn summary(&self) -> String {
        use fmt::Write as _;
        let mut out = format!("verdict: {} (isolation: {})\n", self.verdict(), self.isolation);
        for check in &self.checks {
            let _ = writeln!(out, "  {check}");
        }
        for skipped in &self.skipped {
            let _ = writeln!(out, "  [skip] {skipped}: not runnable by this gate");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{CheckOutcome, Verdict, VerificationReport};
    use crate::plan::{CheckKind, IsolationLevel};
    use core::time::Duration;

    fn report() -> VerificationReport {
        VerificationReport::new(IsolationLevel::None, "deadbeef")
    }

    #[test]
    fn a_report_with_only_passes_is_accepted() {
        let mut report = report();
        report.record(CheckOutcome::passed(
            CheckKind::SyntaxValid,
            "parses cleanly",
            Duration::ZERO,
        ));

        assert_eq!(report.verdict(), Verdict::Accepted);
        assert!(report.verdict().is_accepted());
    }

    #[test]
    fn a_failure_rejects_the_patch() {
        let mut report = report();
        report.record(CheckOutcome::failed(CheckKind::TestSuite, "3 failing", Duration::ZERO));

        assert_eq!(report.verdict(), Verdict::Rejected { failed: vec![CheckKind::TestSuite] });
    }

    #[test]
    fn a_skipped_check_is_inconclusive_not_accepted() {
        let mut report = report();
        report.record(CheckOutcome::passed(CheckKind::SyntaxValid, "ok", Duration::ZERO));
        report.skip(CheckKind::TestSuite);

        assert_eq!(report.verdict(), Verdict::Inconclusive { skipped: vec![CheckKind::TestSuite] });
        assert!(!report.verdict().is_accepted());
    }

    #[test]
    fn a_failure_outranks_a_skip() {
        let mut report = report();
        report.record(CheckOutcome::failed(CheckKind::SyntaxValid, "broken", Duration::ZERO));
        report.skip(CheckKind::TestSuite);

        assert!(matches!(report.verdict(), Verdict::Rejected { .. }));
    }

    #[test]
    fn the_summary_names_the_isolation_level() {
        let mut report = report();
        report.record(CheckOutcome::passed(CheckKind::SyntaxValid, "ok", Duration::ZERO));

        let summary = report.summary();
        assert!(summary.contains("isolation: none"), "{summary}");
        assert!(summary.contains("syntax-valid"), "{summary}");
    }
}
