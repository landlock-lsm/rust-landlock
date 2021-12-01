//! Landlock is a security feature available since Linux 5.13.
//! The goal is to enable to restrict ambient rights
//! (e.g., global filesystem access)
//! for a set of processes by creating safe security sandboxes as new security layers
//! in addition to the existing system-wide access-controls.
//! This kind of sandbox is expected to help mitigate the security impact of bugs,
//! unexpected or malicious behaviors in applications.
//! Landlock empowers any process, including unprivileged ones, to securely restrict themselves.
//! More information about Landlock can be found in the [official website](https://landlock.io).
//!
//! This crate provides a safe abstraction for the Landlock system calls, along with some helpers.
//!
//! # Use cases
//!
//! This crate is especially useful for built-in application sandboxing:
//! * Parser hardening (e.g., archive tools, file format conversion, renderers).
//! * (Part of) applications with limited file renaming or linking needs
//!   (e.g., some system or network services).
//! * Applications dealing with different levels of confidentiality
//!   (e.g., web browser, email server).
//!
//! # Examples
//!
//! Examples can be found with the [`Ruleset` documentation](Ruleset)
//! and the [sandboxer example](https://github.com/landlock-lsm/rust-landlock/blob/master/examples/sandboxer.rs).
//!
//! # Current limitations
//!
//! This crate exposes the Landlock features available as of Linux 5.13
//! and then inherits some [kernel limitations](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#current-limitations)
//! that will be addressed with future kernel releases:
//! * File reparenting: renaming or linking a file to a different parent directory is always denied.
//! * Filesystem topology modification: arbitrary mounts are always denied.
//!
//! # Compatibility
//!
//! Types defined in this crate are designed to enable the strictest Landlock configuration
//! for the given kernel on which the program runs.
//! In the default [best-effort](Compatible::set_best_effort) mode,
//! [`Ruleset`] will determine compatibility
//! with the intersection of the currently running kernel's features
//! and those required by the caller.
//! This way, callers can distinguish between
//! Landlock compatibility issues inherent to the current system
//! (e.g., file names that don't exist)
//! and misconfiguration that should be fixed in the program
//! (e.g., empty or inconsistent access rights).
//! [`RulesetError`] identifies such kind of errors.
//!
//! With [`set_best_effort()`](Compatible::set_best_effort),
//! users of the crate may identify which Landlock features are deemed required
//! and which features may be downgraded to use lower security on systems
//! where they can't be enforced.
//! It is discouraged to compare the system's provided [Landlock ABI](ABI) version directly,
//! as it is difficult to track detailed ABI differences
//! which are handled thanks to the [`Compatible`] trait.
//!
//! To make it easier to migrate to a new version of this library,
//! we use the builder pattern
//! and designed objects to require the minimal set of method arguments.
//! Most `enum` are marked as `non_exhaustive` to enable backward-compatible evolutions.
//!
//! ## Test strategy
//!
//! Developers should test their sandboxed applications
//! with a kernel that supports all requested Landlock features
//! and check that [`RulesetCreated::restrict_self()`] returns a status matching
//! [`Ok(RestrictionStatus { ruleset: RulesetStatus::FullyEnforced, no_new_privs: true, })`](RestrictionStatus)
//! to make sure everything works as expected in an enforced sandbox.
//! However, applications should only check that no error is returned (i.e. `Ok(_)`)
//! and optionally log and inform users that the application is not fully sandboxed
//! because of missing features from the running kernel.

extern crate enumflags2;
extern crate libc;
extern crate thiserror;

use compat::{CompatState, Compatibility, TryCompat};
pub use compat::{Compatible, ABI};
pub use enumflags2::{make_bitflags, BitFlags};
pub use errors::{
    AccessError, AddRuleError, AddRulesError, CompatError, CreateRulesetError, HandleAccessError,
    HandleAccessesError, PathBeneathError, PathFdError, RestrictSelfError, RulesetError,
};
pub use fs::{AccessFs, PathBeneath, PathFd};
pub use ruleset::{Access, RestrictionStatus, Rule, Ruleset, RulesetCreated, RulesetStatus};
use ruleset::{PrivateAccess, PrivateRule};

#[cfg(test)]
pub use errors::TestRulesetError;

mod compat;
mod errors;
mod fs;
mod ruleset;
mod uapi;

#[cfg(all(test, not(feature = "test-without-kernel-support")))]
mod tests {
    use crate::*;

    fn ruleset_root_compat() -> Result<RestrictionStatus, TestRulesetError> {
        Ok(Ruleset::new()
            .handle_access(AccessFs::from_all(ABI::V1))?
            .create()?
            .add_rule(PathBeneath::new(
                PathFd::new("/")?,
                AccessFs::from_all(ABI::V1),
            ))?
            .restrict_self()?)
    }

    fn ruleset_root_fragile() -> Result<RestrictionStatus, TestRulesetError> {
        // Sets default support requirement: abort the whole sandboxing for any Landlock error.
        Ok(Ruleset::new()
            // Must have at least the execute check…
            .set_best_effort(false)
            .handle_access(AccessFs::Execute)?
            // …and possibly others.
            .set_best_effort(true)
            .handle_access(AccessFs::from_all(ABI::V1))?
            .create()?
            .set_no_new_privs(true)
            .add_rule(PathBeneath::new(
                PathFd::new("/")?,
                AccessFs::from_all(ABI::V1),
            ))?
            .restrict_self()?)
    }

    #[test]
    fn allow_root_compat() {
        assert_eq!(
            ruleset_root_compat().unwrap(),
            RestrictionStatus {
                ruleset: RulesetStatus::FullyEnforced,
                no_new_privs: true,
            }
        );
    }

    #[test]
    fn allow_root_fragile() {
        assert_eq!(
            ruleset_root_fragile().unwrap(),
            RestrictionStatus {
                ruleset: RulesetStatus::FullyEnforced,
                no_new_privs: true,
            }
        );
    }
}
