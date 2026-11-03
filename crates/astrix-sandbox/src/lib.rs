//! Zero-breakage verification for ASTrix candidate patches.
//!
//! This crate is where the ZERO-BREAKAGE POLICY stops being a slogan and
//! becomes a gate. Nothing in ASTrix writes a remediation to disk; the
//! rewriter produces an in-memory [`astrix_core::Patch`], and a
//! [`ZeroBreakageGate`] decides whether that patch has earned the right to be
//! committed.
//!
//! # Design
//!
//! * **A gate reports, it does not commit.** [`ZeroBreakageGate::verify`]
//!   returns evidence; the caller acts on the [`Verdict`].
//! * **Three verdicts, not two.** [`Verdict::Inconclusive`] exists so
//!   "I could not verify this" is never silently reported as
//!   "this is safe".
//! * **Isolation is stated, never implied.** Every [`VerificationReport`]
//!   carries the [`IsolationLevel`] the evidence was gathered at.
//! * **Static checks first.** [`StaticGate`] runs the in-memory invariants, and
//!   a patch that fails them is never staged on disk.
//!
//! # Gates
//!
//! | Gate | Isolation | Runs |
//! |---|---|---|
//! | [`StaticGate`] | [`IsolationLevel::None`] | edit integrity, effective change, re-parse |
//! | [`CommandGate`] | [`IsolationLevel::ProcessOnly`] | the above, then the project's test command |
//!
//! Stronger isolation levels are declared in [`IsolationLevel`] and are
//! implemented by adding a gate, not by changing this contract.

pub mod command;
pub mod gate;
pub mod plan;
pub mod report;

pub use command::CommandGate;
pub use gate::{NoSyntaxCheck, StaticGate, SyntaxCheck, ZeroBreakageGate};
pub use plan::{CheckKind, IsolationLevel, VerificationPlan};
pub use report::{CheckOutcome, Verdict, VerificationReport};
