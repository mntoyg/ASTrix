//! A gate that proves a patch harmless by running the project's own checks.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use astrix_core::{AstrixError, Patch, Result};

use crate::gate::{StaticGate, SyntaxCheck, ZeroBreakageGate};
use crate::plan::{CheckKind, IsolationLevel, VerificationPlan};
use crate::report::{CheckOutcome, VerificationReport};

const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Stages a candidate buffer on disk and puts the original back afterwards.
///
/// The guard restores on drop, including on panic and on an early `?`, so an
/// interrupted verification can never leave a half-verified patch in the
/// working tree. It also refuses to stage over a file whose content is not the
/// buffer the patch was computed from — the one case where restoring would
/// destroy someone else's work.
#[derive(Debug)]
struct StagedFile {
    path: PathBuf,
    original: String,
}

impl StagedFile {
    fn stage(target: PathBuf, patch: &Patch) -> Result<Self> {
        let on_disk = std::fs::read_to_string(&target)
            .map_err(|source| AstrixError::Io { path: target.clone(), source })?;

        if on_disk != patch.original {
            return Err(AstrixError::Sandbox(format!(
                "`{}` no longer matches the buffer the patch was computed from; \
                 refusing to stage over it",
                target.display()
            )));
        }

        std::fs::write(&target, &patch.rewritten)
            .map_err(|source| AstrixError::Io { path: target.clone(), source })?;

        Ok(Self { path: target, original: on_disk })
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.path, &self.original);
    }
}

/// How a command finished.
#[derive(Debug)]
struct CommandResult {
    detail: String,
    succeeded: bool,
    elapsed: Duration,
}

/// Runs the static checks, then the project's test command against the staged
/// candidate.
///
/// Isolation is [`IsolationLevel::ProcessOnly`]: the command runs as a child
/// process in the project working directory, with the candidate staged in
/// place and restored afterwards. Every report says so, so an accepted patch
/// never implies container-grade isolation it did not get.
#[derive(Debug, Clone, Copy)]
pub struct CommandGate<S> {
    static_gate: StaticGate<S>,
}

impl<S: SyntaxCheck> CommandGate<S> {
    /// Creates a gate that re-parses candidates with `syntax`.
    pub fn new(syntax: S) -> Self {
        Self { static_gate: StaticGate::new(syntax) }
    }

    /// Resolves the patched file relative to the plan's working directory.
    fn target_path(patch: &Patch, plan: &VerificationPlan) -> PathBuf {
        if patch.path.is_absolute() {
            patch.path.clone()
        } else {
            plan.working_dir.join(&patch.path)
        }
    }

    fn run(plan: &VerificationPlan, working_dir: &Path) -> Result<CommandResult> {
        let (program, args) = plan
            .test_command
            .split_first()
            .ok_or_else(|| AstrixError::Sandbox("the plan has no test command".to_owned()))?;

        let started = Instant::now();
        let mut child = Command::new(program)
            .args(args)
            .current_dir(working_dir)
            .envs(plan.env.iter().map(|(key, value)| (key.as_str(), value.as_str())))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                AstrixError::Sandbox(format!("could not launch `{program}`: {error}"))
            })?;

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Ok(CommandResult {
                        detail: format!("`{}` exited with {status}", plan.test_command.join(" ")),
                        succeeded: status.success(),
                        elapsed: started.elapsed(),
                    });
                }
                Ok(None) => {
                    if started.elapsed() >= plan.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(CommandResult {
                            detail: format!(
                                "`{}` exceeded the {:?} timeout and was killed",
                                plan.test_command.join(" "),
                                plan.timeout
                            ),
                            succeeded: false,
                            elapsed: started.elapsed(),
                        });
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(error) => {
                    return Err(AstrixError::Sandbox(format!(
                        "could not wait for `{program}`: {error}"
                    )));
                }
            }
        }
    }
}

impl<S: SyntaxCheck> ZeroBreakageGate for CommandGate<S> {
    fn verify(&self, patch: &Patch, plan: &VerificationPlan) -> Result<VerificationReport> {
        let mut report = VerificationReport::new(IsolationLevel::ProcessOnly, patch.digest.clone());

        self.static_gate.run_static_checks(patch, plan, &mut report);

        // A candidate that already fails a static check is never staged on
        // disk: there is nothing to learn from running tests against a patch
        // we know is wrong, and staging it is the only step with side effects.
        if !report.failures().is_empty() {
            for check in &plan.required_checks {
                if !check.is_static() {
                    report.skip(*check);
                }
            }
            return Ok(report);
        }

        for check in &plan.required_checks {
            match check {
                CheckKind::TestSuite => {
                    let target = Self::target_path(patch, plan);
                    let _staged = StagedFile::stage(target, patch)?;
                    let outcome = Self::run(plan, plan.working_dir())?;
                    report.record(if outcome.succeeded {
                        CheckOutcome::passed(CheckKind::TestSuite, outcome.detail, outcome.elapsed)
                    } else {
                        CheckOutcome::failed(CheckKind::TestSuite, outcome.detail, outcome.elapsed)
                    });
                }
                other if !other.is_static() => {
                    report.skip(*other);
                }
                _ => {}
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::CommandGate;
    use crate::gate::{SyntaxCheck, ZeroBreakageGate};
    use crate::plan::{CheckKind, IsolationLevel, VerificationPlan};
    use crate::report::Verdict;
    use astrix_core::{AppliedEdit, ByteSpan, LanguageId, Patch, Result, RuleId, SourceFile};
    use std::path::PathBuf;
    use std::time::Duration;

    const ORIGINAL: &str = "cfg = yaml.load(raw)\n";
    const REWRITTEN: &str = "cfg = yaml.safe_load(raw)\n";

    struct Workspace {
        dir: PathBuf,
    }

    impl Workspace {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("astrix-sandbox-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("temp workspace is creatable");
            std::fs::write(dir.join("main.py"), ORIGINAL).expect("fixture is writable");
            Self { dir }
        }

        fn staged_content(&self) -> String {
            std::fs::read_to_string(self.dir.join("main.py")).expect("fixture is readable")
        }
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn accepting_syntax() -> impl SyntaxCheck {
        |_: &SourceFile| -> Result<()> { Ok(()) }
    }

    fn patch() -> Patch {
        Patch {
            path: "main.py".into(),
            language: LanguageId::Python,
            original: ORIGINAL.to_owned(),
            rewritten: REWRITTEN.to_owned(),
            applied: vec![AppliedEdit {
                span: ByteSpan::new(6, 15),
                original_text: "yaml.load".to_owned(),
                replacement: "yaml.safe_load".to_owned(),
                rule_id: RuleId::new("astrix.python.unsafe-yaml-load"),
            }],
            digest: "test-digest".to_owned(),
        }
    }

    #[cfg(windows)]
    fn shell(script: &str) -> Vec<String> {
        vec!["cmd".to_owned(), "/C".to_owned(), script.to_owned()]
    }

    #[cfg(not(windows))]
    fn shell(script: &str) -> Vec<String> {
        vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()]
    }

    /// A command that succeeds only if `main.py` contains `needle`.
    fn grep_script(needle: &str) -> Vec<String> {
        if cfg!(windows) {
            shell(&format!("findstr /C:{needle} main.py >nul"))
        } else {
            shell(&format!("grep -q {needle} main.py"))
        }
    }

    /// A command that never finishes on its own.
    fn hang_script() -> Vec<String> {
        if cfg!(windows) {
            shell("ping -n 60 127.0.0.1 >nul")
        } else {
            shell("sleep 60")
        }
    }

    #[test]
    fn a_passing_test_command_accepts_the_patch() {
        let workspace = Workspace::new("pass");
        let plan = VerificationPlan::with_test_suite(&workspace.dir, shell("exit 0"));

        let report =
            CommandGate::new(accepting_syntax()).verify(&patch(), &plan).expect("the gate runs");

        assert_eq!(report.verdict(), Verdict::Accepted);
        assert_eq!(report.isolation, IsolationLevel::ProcessOnly);
    }

    #[test]
    fn a_failing_test_command_rejects_the_patch() {
        let workspace = Workspace::new("fail");
        let plan = VerificationPlan::with_test_suite(&workspace.dir, shell("exit 1"));

        let report =
            CommandGate::new(accepting_syntax()).verify(&patch(), &plan).expect("the gate runs");

        assert_eq!(report.verdict(), Verdict::Rejected { failed: vec![CheckKind::TestSuite] });
    }

    #[test]
    fn the_original_file_is_restored_whatever_the_verdict() {
        let workspace = Workspace::new("restore");
        let plan = VerificationPlan::with_test_suite(&workspace.dir, shell("exit 1"));

        let _ = CommandGate::new(accepting_syntax()).verify(&patch(), &plan);

        assert_eq!(workspace.staged_content(), ORIGINAL);
    }

    #[test]
    fn the_candidate_is_what_the_command_actually_sees() {
        let workspace = Workspace::new("staged");
        let plan = VerificationPlan::with_test_suite(&workspace.dir, grep_script("safe_load"));

        let report =
            CommandGate::new(accepting_syntax()).verify(&patch(), &plan).expect("the gate runs");

        assert_eq!(report.verdict(), Verdict::Accepted, "{}", report.summary());
        assert_eq!(workspace.staged_content(), ORIGINAL);
    }

    #[test]
    fn a_hanging_command_is_killed_and_reported_as_a_failure() {
        let workspace = Workspace::new("timeout");
        let plan = VerificationPlan::with_test_suite(&workspace.dir, hang_script())
            .timeout(Duration::from_millis(200));

        let report =
            CommandGate::new(accepting_syntax()).verify(&patch(), &plan).expect("the gate runs");

        assert!(report.failures().contains(&CheckKind::TestSuite), "{}", report.summary());
        assert!(report.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_modified_working_tree_is_refused_rather_than_overwritten() {
        let workspace = Workspace::new("drifted");
        std::fs::write(workspace.dir.join("main.py"), "someone else edited this\n")
            .expect("fixture is writable");
        let plan = VerificationPlan::with_test_suite(&workspace.dir, shell("exit 0"));

        let error = CommandGate::new(accepting_syntax())
            .verify(&patch(), &plan)
            .expect_err("staging over drifted content must fail");

        assert!(error.to_string().contains("refusing to stage"), "{error}");
        assert_eq!(workspace.staged_content(), "someone else edited this\n");
    }

    #[test]
    fn a_statically_broken_patch_never_reaches_the_working_tree() {
        let workspace = Workspace::new("static-first");
        let mut noop = patch();
        noop.rewritten = ORIGINAL.to_owned();
        let plan = VerificationPlan::with_test_suite(&workspace.dir, shell("exit 0"));

        let report =
            CommandGate::new(accepting_syntax()).verify(&noop, &plan).expect("the gate runs");

        assert!(report.failures().contains(&CheckKind::EffectiveChange));
        assert!(report.skipped.contains(&CheckKind::TestSuite));
        assert_eq!(workspace.staged_content(), ORIGINAL);
    }
}
