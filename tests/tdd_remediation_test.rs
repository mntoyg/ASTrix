//! The TDD entrypoint for ASTrix remediation.
//!
//! Every behaviour ASTrix claims is pinned by a fixture directory under
//! `tests/fixtures/`, not by a test function. A fixture is three files:
//!
//! ```text
//! tests/fixtures/<language>/[pending/]<case>/
//!   fixture.toml   what the engine must report
//!   input.<ext>    the vulnerable source
//!   expected.<ext> the source after remediation
//! ```
//!
//! Adding a CVE therefore means adding a directory. The harness discovers it,
//! and no test function changes.
//!
//! # Red and green
//!
//! `status` in the manifest is the TDD marker:
//!
//! * `implemented` — the rule exists and the fixture must pass now. These run
//!   on every `cargo test`.
//! * `pending` — the fixture describes a rule nobody has written yet. The red
//!   assertions live in `#[ignore]`d tests, runnable with
//!   `cargo test -- --ignored`, and
//!   [`pending_fixtures_name_a_rule_that_is_not_registered_yet`] fails loudly
//!   if someone ships the rule without promoting its fixture.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use astrix::Engine;
use astrix_core::{Confidence, Finding, LanguageId, SourceFile};
use astrix_sandbox::VerificationPlan;
use serde::Deserialize;

/// What the engine must report for one fixture.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    /// Human-readable description of the case.
    name: String,
    /// Language of the fixture source.
    language: String,
    /// `implemented` or `pending`.
    status: String,
    /// Rule expected to fire, when any is.
    #[serde(default)]
    rule: Option<String>,
    /// CVEs the finding must cite.
    #[serde(default)]
    cves: Vec<String>,
    /// CWE classes, recorded for traceability.
    #[serde(default)]
    cwes: Vec<String>,
    /// Expected severity, when a rule is expected to fire.
    #[serde(default)]
    severity: Option<String>,
    /// How many findings the engine must report.
    expected_findings: usize,
    /// Confidence every finding must carry.
    #[serde(default)]
    expected_confidence: Option<String>,
    /// Whether an unattended patch must be produced.
    expect_patch: bool,
    /// Why this fixture exists, and what makes the rewrite safe.
    #[serde(default)]
    notes: String,
}

/// One discovered fixture, loaded and ready to run.
#[derive(Debug)]
struct Fixture {
    id: String,
    manifest: Manifest,
    input: SourceFile,
    expected: String,
}

impl Fixture {
    fn is_pending(&self) -> bool {
        self.manifest.status == "pending"
    }

    fn language(&self) -> LanguageId {
        LanguageId::from_name(&self.manifest.language)
            .unwrap_or_else(|| panic!("{}: unknown language `{}`", self.id, self.manifest.language))
    }

    fn expected_confidence(&self) -> Option<Confidence> {
        match self.manifest.expected_confidence.as_deref() {
            None => None,
            Some("certain") => Some(Confidence::Certain),
            Some("probable") => Some(Confidence::Probable),
            Some("tentative") => Some(Confidence::Tentative),
            Some(other) => panic!("{}: unknown confidence `{other}`", self.id),
        }
    }
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures")
}

/// Collects every directory under `tests/fixtures/` that holds a manifest.
fn discover() -> Vec<Fixture> {
    let root = fixtures_root();
    assert!(root.is_dir(), "the fixture suite is missing at {}", root.display());

    let mut dirs = Vec::new();
    collect_fixture_dirs(&root, &mut dirs);
    dirs.sort();

    let mut fixtures: Vec<Fixture> = dirs.iter().map(|dir| load(&root, dir)).collect();
    fixtures.sort_by(|left, right| left.id.cmp(&right.id));
    fixtures
}

fn collect_fixture_dirs(dir: &Path, found: &mut Vec<PathBuf>) {
    if dir.join("fixture.toml").is_file() {
        found.push(dir.to_path_buf());
        return;
    }

    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()));

    for entry in entries {
        let path = entry.expect("directory entry is readable").path();
        if path.is_dir() {
            collect_fixture_dirs(&path, found);
        }
    }
}

fn load(root: &Path, dir: &Path) -> Fixture {
    let id = dir
        .strip_prefix(root)
        .expect("fixture lives under the suite root")
        .to_string_lossy()
        .replace('\\', "/");

    let manifest_text = read(&dir.join("fixture.toml"));
    let manifest: Manifest = toml::from_str(&manifest_text)
        .unwrap_or_else(|error| panic!("{id}: invalid fixture.toml: {error}"));

    let language = LanguageId::from_name(&manifest.language)
        .unwrap_or_else(|| panic!("{id}: unknown language `{}`", manifest.language));
    let extension = language.primary_extension();

    let input_path = dir.join(format!("input.{extension}"));
    let expected_path = dir.join(format!("expected.{extension}"));

    let input = SourceFile::new(
        PathBuf::from(&id).join(format!("input.{extension}")),
        language,
        read(&input_path),
    );

    Fixture { id, manifest, input, expected: read(&expected_path) }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// Runs one fixture through the engine and asserts everything its manifest claims.
///
/// Shared by the green path and by the `#[ignore]`d red path, so a pending
/// fixture is held to exactly the same standard as an implemented one the day
/// its rule lands.
fn assert_fixture_holds(fixture: &Fixture) {
    let engine = Engine::new();
    let outcome = engine
        .remediate(&fixture.input)
        .unwrap_or_else(|error| panic!("{}: remediation failed: {error}", fixture.id));

    assert_eq!(
        outcome.findings.len(),
        fixture.manifest.expected_findings,
        "{}: expected {} finding(s), got {:?}",
        fixture.id,
        fixture.manifest.expected_findings,
        outcome.findings.iter().map(describe).collect::<Vec<_>>(),
    );

    if let Some(expected_rule) = &fixture.manifest.rule {
        for finding in &outcome.findings {
            assert_eq!(
                finding.rule_id.as_str(),
                expected_rule,
                "{}: unexpected rule fired",
                fixture.id
            );
        }
    }

    if let Some(expected) = fixture.expected_confidence() {
        for finding in &outcome.findings {
            assert_eq!(
                finding.confidence, expected,
                "{}: finding at {} has the wrong confidence",
                fixture.id, finding.span
            );
        }
    }

    if let Some(expected) = &fixture.manifest.severity {
        for finding in &outcome.findings {
            assert_eq!(
                finding.severity.as_str(),
                expected,
                "{}: finding at {} has the wrong severity",
                fixture.id,
                finding.span
            );
        }
    }

    for cve in &fixture.manifest.cves {
        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| { finding.cves.iter().any(|cited| cited.as_str() == cve) }),
            "{}: no finding cites {cve}",
            fixture.id,
        );
    }

    match (&outcome.patch, fixture.manifest.expect_patch) {
        (Some(patch), true) => {
            assert_eq!(
                patch.rewritten,
                fixture.expected,
                "{}: remediated source does not match expected.{}",
                fixture.id,
                fixture.language().primary_extension(),
            );
        }
        (None, false) => {
            assert_eq!(
                fixture.input.text(),
                fixture.expected,
                "{}: the manifest expects no patch, so expected.* must equal input.*",
                fixture.id,
            );
        }
        (Some(patch), false) => panic!(
            "{}: the manifest expects no patch but the engine produced:\n{}",
            fixture.id, patch.rewritten
        ),
        (None, true) => {
            panic!("{}: the manifest expects a patch but the engine produced none", fixture.id)
        }
    }
}

fn describe(finding: &Finding) -> String {
    format!("{} at {} ({})", finding.rule_id, finding.span, finding.confidence)
}

fn implemented() -> Vec<Fixture> {
    discover().into_iter().filter(|fixture| !fixture.is_pending()).collect()
}

fn pending() -> Vec<Fixture> {
    discover().into_iter().filter(Fixture::is_pending).collect()
}

// ---------------------------------------------------------------- the suite

#[test]
fn the_fixture_suite_is_discoverable() {
    let fixtures = discover();

    assert!(
        fixtures.len() >= 8,
        "the suite has shrunk to {} fixtures; remediation coverage is the point of this crate",
        fixtures.len()
    );
    assert!(
        fixtures.iter().any(|fixture| !fixture.is_pending()),
        "the suite must contain at least one implemented fixture"
    );
    assert!(
        fixtures.iter().any(Fixture::is_pending),
        "the suite must keep its backlog visible as pending fixtures"
    );
}

#[test]
fn every_fixture_manifest_is_internally_consistent() {
    for fixture in discover() {
        let id = &fixture.id;
        let manifest = &fixture.manifest;

        assert!(
            matches!(manifest.status.as_str(), "implemented" | "pending"),
            "{id}: status must be `implemented` or `pending`, got `{}`",
            manifest.status
        );
        assert!(!manifest.name.trim().is_empty(), "{id}: fixture needs a name");
        assert!(
            !manifest.notes.trim().is_empty(),
            "{id}: fixture must say why it exists and what makes the rewrite safe"
        );

        if manifest.expected_findings > 0 {
            assert!(manifest.rule.is_some(), "{id}: a finding must name the rule that reports it");
            assert!(
                manifest.expected_confidence.is_some(),
                "{id}: a finding must pin the confidence it is reported at"
            );
        } else {
            assert!(
                !manifest.expect_patch,
                "{id}: a fixture with no findings cannot expect a patch"
            );
        }

        for cwe in &manifest.cwes {
            assert!(
                cwe.starts_with("CWE-") && cwe["CWE-".len()..].chars().all(char::is_numeric),
                "{id}: `{cwe}` is not a CWE identifier"
            );
        }

        for cve in &manifest.cves {
            assert!(cve.starts_with("CVE-"), "{id}: `{cve}` is not a CVE identifier");
        }

        assert_eq!(
            manifest.expect_patch,
            fixture.input.text() != fixture.expected,
            "{id}: expect_patch disagrees with whether expected.* differs from input.*"
        );
    }
}

#[test]
fn every_fixture_id_is_unique() {
    let fixtures = discover();
    let unique: BTreeSet<&str> = fixtures.iter().map(|fixture| fixture.id.as_str()).collect();

    assert_eq!(unique.len(), fixtures.len(), "fixture ids must be unique");
}

#[test]
fn every_fixture_input_parses_cleanly() {
    for fixture in discover() {
        let tree = astrix::parser::parse(&fixture.input)
            .unwrap_or_else(|error| panic!("{}: input does not parse: {error}", fixture.id));

        tree.require_well_formed().unwrap_or_else(|error| {
            panic!("{}: a fixture input must be valid source: {error}", fixture.id)
        });
    }
}

#[test]
fn implemented_fixtures_remediate_to_exactly_the_expected_source() {
    let fixtures = implemented();
    assert!(!fixtures.is_empty(), "no implemented fixtures were discovered");

    for fixture in &fixtures {
        assert_fixture_holds(fixture);
    }
}

#[test]
fn implemented_patches_are_accepted_by_the_zero_breakage_gate() {
    let engine = Engine::new();
    let plan = VerificationPlan::static_only(env!("CARGO_MANIFEST_DIR"));

    for fixture in implemented() {
        let Some(patch) = engine.remediate(&fixture.input).expect("remediation runs").patch else {
            continue;
        };

        let report = engine.verify(&patch, &plan).expect("the gate runs");
        assert!(
            report.verdict().is_accepted(),
            "{}: the gate refused the patch\n{}",
            fixture.id,
            report.summary()
        );
    }
}

#[test]
fn remediation_is_idempotent() {
    let engine = Engine::new();

    for fixture in implemented() {
        let Some(patch) = engine.remediate(&fixture.input).expect("remediation runs").patch else {
            continue;
        };

        let second = engine
            .remediate(&fixture.input.with_text(patch.rewritten.clone()))
            .expect("the remediated source still parses");

        assert!(
            !second.has_patch(),
            "{}: a second pass changed the source again:\n{}",
            fixture.id,
            second.patch.map(|patch| patch.rewritten).unwrap_or_default()
        );
    }
}

#[test]
fn remediation_is_byte_for_byte_reproducible() {
    let engine = Engine::new();

    for fixture in implemented() {
        let first = engine.remediate(&fixture.input).expect("remediation runs");
        let second = engine.remediate(&fixture.input).expect("remediation runs");

        assert_eq!(first, second, "{}: two identical runs disagreed", fixture.id);
    }
}

#[test]
fn analysis_never_mutates_the_input() {
    let engine = Engine::new();

    for fixture in implemented() {
        let before = fixture.input.text().to_owned();
        let _ = engine.analyze(&fixture.input).expect("analysis runs");

        assert_eq!(fixture.input.text(), before, "{}: analysis mutated its input", fixture.id);
    }
}

// ------------------------------------------------------------- the backlog

#[test]
fn pending_fixtures_name_a_rule_that_is_not_registered_yet() {
    let registered: BTreeSet<String> =
        astrix::rules::builtin_registry::<astrix::parser::TsNode<'_>>()
            .rule_ids()
            .map(ToOwned::to_owned)
            .collect();

    for fixture in pending() {
        let rule = fixture
            .manifest
            .rule
            .as_deref()
            .unwrap_or_else(|| panic!("{}: a pending fixture must name its rule", fixture.id));

        assert!(
            !registered.contains(rule),
            "{}: rule `{rule}` is registered now — promote this fixture to \
             `status = \"implemented\"`",
            fixture.id,
        );
    }
}

#[test]
#[ignore = "red: these fixtures describe rules that have not been written yet"]
fn pending_fixtures_remediate_to_exactly_the_expected_source() {
    let fixtures = pending();
    assert!(!fixtures.is_empty(), "no pending fixtures were discovered");

    for fixture in &fixtures {
        assert_fixture_holds(fixture);
    }
}
