extern crate enumflags2;

use compat::{CompatState, Compatibility, TryCompat};
pub use compat::{Compatible, ABI};
pub use enumflags2::{make_bitflags, BitFlags};
pub use fs::{AccessFs, PathBeneath, PathFd};
use ruleset::PrivateRule;
pub use ruleset::{RestrictionStatus, Rule, Ruleset, RulesetCreated, RulesetStatus};

#[cfg(test)]
use std::io::Error;

mod compat;
mod fs;
mod ruleset;
mod uapi;

#[cfg(test)]
mod tests {
    use crate::*;

    fn ruleset_root_compat() -> Result<RestrictionStatus, Error> {
        let ruleset: Ruleset = Compatibility::new().into();
        ruleset
            .handle_fs(ABI::V1)?
            .create()?
            .add_rule(PathBeneath::new(&PathFd::new("/")?).allow_access(ABI::V1))?
            .restrict_self()
    }

    fn ruleset_root_fragile() -> Result<RestrictionStatus, Error> {
        // Sets default support requirement: abort the whole sandboxing for any Landlock error.
        Ruleset::new()
            // Must have at least the execute check…
            .set_best_effort(false)
            .handle_fs(AccessFs::Execute)?
            // …and possibly others (superset of AccessFs::Execute).
            .set_best_effort(true)
            .handle_fs(ABI::V1)?
            .create()?
            .set_no_new_privs(true)
            .add_rule(PathBeneath::new(&PathFd::new("/")?).allow_access(ABI::V1))?
            .restrict_self()
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
