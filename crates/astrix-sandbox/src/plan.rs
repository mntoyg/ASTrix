//! What a candidate patch must survive before it may be committed.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// One verification check in the zero-breakage gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CheckKind {
    /// The applied edits still describe the buffer they were computed against.
    EditIntegrity,
    /// The rewrite changed something, so the finding was actually remediated.
    EffectiveChange,
    /// The rewritten buffer parses without error or missing nodes.
    SyntaxValid,
    /// The rewritten tree differs from the original only inside edited spans.
    AstShapeStable,
    /// The project's own test suite still passes.
    TestSuite,
    /// The project's linter still passes.
    Lint,
    /// The project's type checker still passes.
    TypeCheck,
}

impl CheckKind {
    /// Stable lowercase name, used in reports and fixture manifests.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EditIntegrity => "edit-integrity",
            Self::EffectiveChange => "effective-change",
            Self::SyntaxValid => "syntax-valid",
            Self::AstShapeStable => "ast-shape-stable",
            Self::TestSuite => "test-suite",
            Self::Lint => "lint",
            Self::TypeCheck => "type-check",
        }
    }

    /// Returns `true` when the check needs no child process.
    ///
    /// Static checks are cheap enough to run on every candidate; the rest cost
    /// a process launch and are gated behind the plan.
    pub const fn is_static(self) -> bool {
        matches!(
            self,
            Self::EditIntegrity | Self::EffectiveChange | Self::SyntaxValid | Self::AstShapeStable
        )
    }
}

impl core::fmt::Display for CheckKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How well a gate isolates the commands it runs.
///
/// Recorded in every report so an accepted patch states the strength of the
/// evidence behind it, instead of implying more than the gate delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum IsolationLevel {
    /// No child process ran; only in-memory invariants were checked.
    None,
    /// Commands ran as child processes in the project working directory.
    ProcessOnly,
    /// Commands ran against a throwaway copy of the working tree.
    WorkingTreeCopy,
    /// Commands ran inside a container or VM with no host write access.
    Container,
}

impl IsolationLevel {
    /// Stable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ProcessOnly => "process-only",
            Self::WorkingTreeCopy => "working-tree-copy",
            Self::Container => "container",
        }
    }
}

impl core::fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The command and the checks a gate should run for one candidate patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationPlan {
    /// Directory the commands run in.
    pub working_dir: PathBuf,
    /// Test command, as program plus arguments.
    pub test_command: Vec<String>,
    /// Extra environment variables for the child process.
    pub env: Vec<(String, String)>,
    /// How long a single command may run before it is killed.
    pub timeout: Duration,
    /// Checks that must pass for the patch to be accepted, in run order.
    pub required_checks: Vec<CheckKind>,
}

impl VerificationPlan {
    /// A plan with only the static checks, for a dry run.
    pub fn static_only(working_dir: impl Into<PathBuf>) -> Self {
        Self {
            working_dir: working_dir.into(),
            test_command: Vec::new(),
            env: Vec::new(),
            timeout: Duration::from_secs(300),
            required_checks: vec![
                CheckKind::EditIntegrity,
                CheckKind::EffectiveChange,
                CheckKind::SyntaxValid,
            ],
        }
    }

    /// A plan that also runs `test_command` as the test suite check.
    pub fn with_test_suite<I: IntoIterator<Item = T>, T: Into<String>>(
        working_dir: impl Into<PathBuf>,
        test_command: I,
    ) -> Self {
        let mut plan = Self::static_only(working_dir);
        plan.test_command = test_command.into_iter().map(Into::into).collect();
        plan.required_checks.push(CheckKind::TestSuite);
        plan
    }

    /// Overrides the per-command timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Adds an environment variable for the child process.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Directory the commands run in.
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// Returns `true` when the plan asks for `check`.
    pub fn requires(&self, check: CheckKind) -> bool {
        self.required_checks.contains(&check)
    }

    /// Returns `true` when no check in the plan needs a child process.
    pub fn is_static_only(&self) -> bool {
        self.required_checks.iter().all(|check| check.is_static())
    }
}

#[cfg(test)]
mod tests {
    use super::{CheckKind, VerificationPlan};

    #[test]
    fn a_static_plan_needs_no_process() {
        let plan = VerificationPlan::static_only(".");
        assert!(plan.is_static_only());
        assert!(plan.requires(CheckKind::SyntaxValid));
        assert!(!plan.requires(CheckKind::TestSuite));
    }

    #[test]
    fn adding_a_test_suite_makes_the_plan_non_static() {
        let plan = VerificationPlan::with_test_suite(".", ["pytest", "-q"]);
        assert!(!plan.is_static_only());
        assert!(plan.requires(CheckKind::TestSuite));
        assert_eq!(plan.test_command, vec!["pytest", "-q"]);
    }

    #[test]
    fn static_checks_are_classified_consistently() {
        assert!(CheckKind::EditIntegrity.is_static());
        assert!(!CheckKind::TestSuite.is_static());
        assert!(!CheckKind::Lint.is_static());
    }
}
