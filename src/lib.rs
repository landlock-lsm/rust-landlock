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
//! A simple example can be found with the [`path_beneath_rules()`] helper.
//! More complex examples can be found with the [`Ruleset` documentation](Ruleset)
//! and the [sandboxer example](https://github.com/landlock-lsm/rust-landlock/blob/master/examples/sandboxer.rs).
//!
//! # Current limitations
//!
//! This crate exposes the Landlock features available as of Linux 5.19
//! and then inherits some [kernel limitations](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#current-limitations)
//! that will be addressed with future kernel releases
//! (e.g., arbitrary mounts are always denied).
//!
//! # Compatibility
//!
//! Types defined in this crate are designed to enable the strictest Landlock configuration
//! for the given kernel on which the program runs.
//! In the default [best-effort](CompatLevel::BestEffort) mode,
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
//! With [`set_compatibility(CompatLevel::BestEffort)`](Compatible::set_compatibility),
//! users of the crate may mark Landlock features that are deemed required
//! and other features that may be downgraded to use lower security on systems
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
//! Alternatively, using [`set_compatibility(CompatLevel::HardRequirement)`](Compatible::set_compatibility)
//! will immediately inform about unsupported Landlock features.
//! These configurations should only depend on the test environment
//! (e.g. [by checking an environment variable](https://github.com/landlock-lsm/rust-landlock/search?q=LANDLOCK_CRATE_TEST_ABI)).
//! However, applications should only check that no error is returned (i.e. `Ok(_)`)
//! and optionally log and inform users that the application is not fully sandboxed
//! because of missing features from the running kernel.

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

pub use access::Access;
pub use compat::{CompatLevel, Compatible, ABI};
pub use enumflags2::{make_bitflags, BitFlags};
pub use errors::{
    AccessError, AddRuleError, AddRulesError, CompatError, CreateRulesetError, HandleAccessError,
    HandleAccessesError, PathBeneathError, PathFdError, RestrictSelfError, RulesetError,
};
pub use fs::{path_beneath_rules, AccessFs, PathBeneath, PathFd};
pub use ruleset::{
    RestrictionStatus, Rule, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
    RulesetStatus,
};

use access::PrivateAccess;
use compat::{CompatState, Compatibility, TryCompat};
use ruleset::PrivateRule;

#[cfg(test)]
use compat::{can_emulate, get_errno_from_landlock_status};
#[cfg(test)]
use errors::TestRulesetError;
#[cfg(test)]
use strum::IntoEnumIterator;

mod access;
mod compat;
mod errors;
mod fs;
mod ruleset;
mod uapi;

#[cfg(test)]
mod tests {
    use crate::*;

    // Emulate old kernel supports.
    fn check_ruleset_support<F>(partial: ABI, full: ABI, check: F, error_if_abi_lt_partial: bool)
    where
        F: Fn(Ruleset) -> Result<RestrictionStatus, TestRulesetError>,
    {
        // If there is no partial support, it means that `full == partial`.
        assert!(partial <= full);
        for abi in ABI::iter() {
            let ret = check(Ruleset::from(abi));

            // Useful for failed tests and with cargo test -- --show-output
            println!("Checking ABI {abi:?}, expecting {ret:#?}");
            if can_emulate(abi, full) {
                if abi < partial && error_if_abi_lt_partial {
                    // TODO: Check exact error type; this may require better error types.
                    assert!(matches!(ret, Err(TestRulesetError::Ruleset(_))));
                } else {
                    let ruleset_status = if abi >= full {
                        RulesetStatus::FullyEnforced
                    } else if abi >= partial {
                        RulesetStatus::PartiallyEnforced
                    } else {
                        RulesetStatus::NotEnforced
                    };
                    assert!(matches!(
                        ret,
                        Ok(RestrictionStatus {
                            ruleset,
                            no_new_privs: true,
                        }) if ruleset == ruleset_status
                    ))
                }
            } else {
                // The errno value should be ENOSYS, EOPNOTSUPP, or EINVAL (e.g. when an unknown
                // access right is provided).
                let errno = get_errno_from_landlock_status().unwrap_or(libc::EINVAL);
                assert!(matches!(
                    ret,
                    Err(TestRulesetError::Ruleset(RulesetError::CreateRuleset(
                        CreateRulesetError::CreateRulesetCall { source }
                    ))) if source.raw_os_error() == Some(errno)
                ))
            }
        }
    }

    #[test]
    fn allow_root_compat() {
        let abi = ABI::V1;

        check_ruleset_support(
            abi,
            abi,
            |ruleset: Ruleset| -> _ {
                Ok(ruleset
                    .handle_access(AccessFs::from_all(abi))?
                    .create()?
                    .add_rule(PathBeneath::new(PathFd::new("/")?, AccessFs::from_all(abi)))?
                    .restrict_self()?)
            },
            false,
        );
    }

    #[test]
    fn allow_root_fragile() {
        let abi = ABI::V1;

        check_ruleset_support(
            abi,
            abi,
            |ruleset: Ruleset| -> _ {
                // Sets default support requirement: abort the whole sandboxing for any Landlock error.
                Ok(ruleset
                    // Must have at least the execute check…
                    .set_compatibility(CompatLevel::HardRequirement)
                    .handle_access(AccessFs::Execute)?
                    // …and possibly others.
                    .set_compatibility(CompatLevel::BestEffort)
                    .handle_access(AccessFs::from_all(abi))?
                    .create()?
                    .set_no_new_privs(true)
                    .add_rule(PathBeneath::new(PathFd::new("/")?, AccessFs::from_all(abi)))?
                    .restrict_self()?)
            },
            true,
        );
    }

    #[test]
    fn ruleset_enforced() {
        let abi = ABI::V1;

        check_ruleset_support(
            abi,
            abi,
            |ruleset: Ruleset| -> _ {
                Ok(ruleset
                    // Restricting without rule exceptions is legitimate to forbid a set of actions.
                    .handle_access(AccessFs::Execute)?
                    .create()?
                    .restrict_self()?)
            },
            false,
        );
    }

    #[test]
    fn abi_v2_refer() {
        check_ruleset_support(
            ABI::V1,
            ABI::V2,
            |ruleset: Ruleset| -> _ {
                Ok(ruleset
                    .handle_access(AccessFs::Execute)?
                    // AccessFs::Refer is not supported by ABI::V1 (best-effort).
                    .handle_access(AccessFs::Refer)?
                    .create()?
                    .restrict_self()?)
            },
            false,
        );
    }
}
