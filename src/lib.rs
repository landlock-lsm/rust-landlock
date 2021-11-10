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

#[cfg(test)]
mod tests {
    use crate::*;

    fn ruleset_root_compat() -> Result<RestrictionStatus, TestRulesetError> {
        Ok(Ruleset::new()
            .handle_access(AccessFs::from_all(ABI::V1))?
            .create()?
            .add_rule(
                PathBeneath::new(PathFd::new("/")?).allow_access(AccessFs::from_all(ABI::V1)),
            )?
            .restrict_self()?)
    }

    fn ruleset_root_fragile() -> Result<RestrictionStatus, TestRulesetError> {
        // Sets default support requirement: abort the whole sandboxing for any Landlock error.
        Ok(Ruleset::new()
            // Must have at least the execute check…
            .set_best_effort(false)
            .handle_access(AccessFs::Execute)?
            // …and possibly others (superset of AccessFs::Execute).
            .set_best_effort(true)
            .handle_access(AccessFs::from_all(ABI::V1))?
            .create()?
            .set_no_new_privs(true)
            .add_rule(
                PathBeneath::new(PathFd::new("/")?).allow_access(AccessFs::from_all(ABI::V1)),
            )?
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
