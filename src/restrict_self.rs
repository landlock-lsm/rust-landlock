// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Restrict_self flag configuration.
//!
//! The [`RestrictSelfAttr`] trait provides the
//! [`log_subdomains()`](RestrictSelfAttr::log_subdomains) setter shared
//! between [`RulesetCreated`](crate::RulesetCreated) (with a domain) and
//! [`RestrictSelf`] (without a domain).
//!
//! Domain-specific setters ([`log_same_exec()`](crate::RulesetCreatedAttr::log_same_exec),
//! [`log_new_exec()`](crate::RulesetCreatedAttr::log_new_exec)) are on
//! [`RulesetCreatedAttr`](crate::RulesetCreatedAttr) which requires
//! `RestrictSelfAttr` as a supertrait.

use crate::compat::private::OptionCompatLevelMut;
use crate::compat::Compatibility;
use crate::flags::{RestrictSelfFlag, SyscallFlagExt};
use crate::prctl::try_set_no_new_privs;
use crate::{
    uapi, CompatLevel, CompatState, Compatible, LandlockStatus, RestrictSelfError, RulesetError,
};
use private::RestrictSelfFlagsState;

#[cfg(test)]
use crate::ABI;

pub(crate) mod private {
    use crate::RulesetError;

    /// Private plumbing trait for types that store restrict_self flags.
    ///
    /// Follows the same pattern as
    /// [`OptionCompatLevelMut`](crate::compat::private::OptionCompatLevelMut)
    /// for [`Compatible`](crate::Compatible).
    ///
    /// The `try_set_flag()` method encapsulates all internal state access
    /// (requested/actual flags and compat state) to avoid exposing
    /// `pub(crate)` types in the trait interface.
    pub trait RestrictSelfFlagsState {
        fn try_set_flag(
            &mut self,
            flag: super::RestrictSelfFlag,
            set: bool,
        ) -> Result<(), RulesetError>;
    }
}

/// Trait for types that accept restrict_self flag configuration.
///
/// Provides [`log_subdomains()`](Self::log_subdomains) which works both
/// with and without a Landlock domain.
///
/// Implemented by [`RulesetCreated`](crate::RulesetCreated) (via
/// [`RulesetCreatedAttr`](crate::RulesetCreatedAttr) supertrait) and
/// [`RestrictSelf`].
///
/// Domain-specific setters (`log_same_exec`, `log_new_exec`) are on
/// [`RulesetCreatedAttr`](crate::RulesetCreatedAttr).
///
/// This trait is sealed and cannot be implemented outside of this crate.
/// Sealing is done via the `RestrictSelfFlagsState` private supertrait,
/// which also carries the internal plumbing for this trait's default
/// methods; unlike [`SyscallFlag`](crate::SyscallFlag) and
/// [`Access`](crate::Access), no separate `Sealed` marker is needed.
pub trait RestrictSelfAttr: Sized + private::RestrictSelfFlagsState {
    /// Controls logging of denied accesses from nested Landlock domains.
    /// Logging is **enabled** by default.
    ///
    /// Calling with `false` sets the `LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF` flag.
    /// Setters are last-call-wins: calling again with a different boolean
    /// re-configures the flag (e.g., `log_subdomains(false).log_subdomains(true)`
    /// leaves logging enabled).
    ///
    /// Setting to the default value never triggers a compatibility check,
    /// so it cannot error even under
    /// [`CompatLevel::HardRequirement`](crate::CompatLevel::HardRequirement)
    /// on an unsupported kernel.
    ///
    /// Available since Landlock [ABI v7](crate::ABI::V7).
    ///
    /// On error, returns a wrapped
    /// [`SyscallFlagError<RestrictSelfFlag>`](crate::SyscallFlagError).
    ///
    /// # Compat state
    ///
    /// Calling this setter with a non-default value on an unsupported
    /// kernel transitions the compat state away from Full (toward No,
    /// Dummy, or Partial depending on
    /// [`CompatLevel`](crate::CompatLevel)).  Reverting by calling
    /// again with the default value clears the bit but does not reset
    /// the compat state, so a subsequent enforcement may still report
    /// less-than-full enforcement.
    fn log_subdomains(mut self, set: bool) -> Result<Self, RulesetError> {
        self.try_set_flag(RestrictSelfFlag::LogSubdomains, set)?;
        Ok(self)
    }
}

/// Builder for calling `landlock_restrict_self()` without creating a
/// Landlock domain.
///
/// Use this when you want to configure `landlock_restrict_self()` flags
/// without creating a ruleset or a Landlock domain (e.g., muting
/// subdomain audit logs for nested domains).
///
/// Only [`log_subdomains()`](RestrictSelfAttr::log_subdomains) is available
/// on this builder.  Domain-specific setters
/// ([`log_same_exec()`](crate::RulesetCreatedAttr::log_same_exec),
/// [`log_new_exec()`](crate::RulesetCreatedAttr::log_new_exec)) require a
/// Landlock domain via [`RulesetCreated`](crate::RulesetCreated).
///
/// Available since Landlock [ABI v7](crate::ABI::V7).
///
/// `no_new_privs` is enforced by default; call
/// [`no_new_privs(false)`](Self::no_new_privs) to opt out.
///
/// # Example
///
/// ```no_run
/// use landlock::*;
///
/// let status = RestrictSelf::default()
///     .log_subdomains(false)?
///     .apply()?;
/// println!("Landlock status: {:?}", status.landlock);
/// # Ok::<(), RulesetError>(())
/// ```
///
/// Use [`set_compatibility()`](Compatible::set_compatibility) to control
/// how unsupported flags are handled.
///
/// [`apply()`](Self::apply) returns a [`RestrictSelfStatus`] with the
/// Landlock support status and the effective flag states.  Its name
/// differs from [`RulesetCreated::restrict_self()`](crate::RulesetCreated::restrict_self)
/// to avoid the redundant `RestrictSelf::restrict_self()`.
#[derive(Debug)]
pub struct RestrictSelf {
    requested_flags: u32,
    actual_flags: u32,
    no_new_privs: bool,
    compat: Compatibility,
}

impl Default for RestrictSelf {
    /// Returns a new `RestrictSelf`.
    /// This call automatically probes the running kernel to know if it
    /// supports Landlock.
    fn default() -> Self {
        Self {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: Compatibility::new(),
        }
    }
}

#[cfg(test)]
impl From<ABI> for RestrictSelf {
    fn from(abi: ABI) -> Self {
        Self {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: Compatibility::from(abi),
        }
    }
}

impl RestrictSelfFlagsState for RestrictSelf {
    fn try_set_flag(&mut self, flag: RestrictSelfFlag, set: bool) -> Result<(), RulesetError> {
        let raw_bit = flag.raw_bit();
        // Last-call-wins: requested tracks non-default user intent, actual
        // tracks the bit that will be passed to the kernel.
        //
        // requested_flags is updated unconditionally; actual_flags is
        // updated only if try_compat succeeds.  On HardRequirement +
        // unsupported, try_compat returns Err and requested_flags is
        // left in a "user requested this" state; the builder is consumed
        // by `?` on error so this inconsistency is not observable.
        if set == flag.default_value() {
            self.requested_flags &= !raw_bit;
        } else {
            self.requested_flags |= raw_bit;
        }
        if flag.try_compat(set, &mut self.compat)? {
            self.actual_flags |= raw_bit;
        } else {
            self.actual_flags &= !raw_bit;
        }
        Ok(())
    }
}

impl RestrictSelfAttr for RestrictSelf {}

impl OptionCompatLevelMut for RestrictSelf {
    fn as_option_compat_level_mut(&mut self) -> &mut Option<CompatLevel> {
        &mut self.compat.level
    }
}

impl Compatible for RestrictSelf {}

/// Status returned by [`RestrictSelf::apply()`].
///
/// This is a proper subset of [`RestrictionStatus`](crate::RestrictionStatus):
/// `log_same_exec` and `log_new_exec` are domain-specific and not configurable
/// on [`RestrictSelf`], so they are not reported here; `ruleset` does not
/// apply without a domain.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestrictSelfStatus {
    /// Landlock support status of the running system.
    pub landlock: LandlockStatus,
    /// `no_new_privs` was successfully enforced via
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
    pub no_new_privs: bool,
    /// Subdomain logging is enabled (default: true).
    pub log_subdomains: bool,
}

impl RestrictSelf {
    /// Configures whether to call `prctl(PR_SET_NO_NEW_PRIVS)` during
    /// [`apply()`](Self::apply).  Defaults to `true`.
    ///
    /// This `prctl(2)` call is never ignored, even if an error was
    /// encountered while [`CompatLevel::SoftRequirement`] was set.
    ///
    /// See [`RestrictSelfAttr::log_subdomains()`] for compat-state
    /// behavior when toggling this setter on unsupported kernels.
    pub fn no_new_privs(mut self, yes: bool) -> Self {
        self.no_new_privs = yes;
        self
    }

    /// Applies the configured restrict_self flags by calling
    /// `landlock_restrict_self(-1, flags)`.
    ///
    /// If `no_new_privs` is configured (default), also calls
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` first, since the kernel
    /// requires `no_new_privs` (or `CAP_SYS_ADMIN`) for
    /// `landlock_restrict_self()`.  See
    /// [`no_new_privs()`](Self::no_new_privs) to opt out.
    ///
    /// Returns a [`RestrictSelfStatus`] with the Landlock support status.
    /// Skips the restrict_self syscall if no flags are enforceable.
    pub fn apply(mut self) -> Result<RestrictSelfStatus, RulesetError> {
        let enforced_nnp = if self.no_new_privs {
            try_set_no_new_privs(&mut self.compat)?
        } else {
            false
        };

        let log_subdomains = RestrictSelfFlag::LogSubdomains.is_set(self.actual_flags);

        let status = RestrictSelfStatus {
            landlock: self.compat.status(),
            no_new_privs: enforced_nnp,
            log_subdomains,
        };

        // Skip the syscall when the compat state indicates no features are
        // enforceable, mirroring RulesetCreated::restrict_self().
        match self.compat.state {
            CompatState::Init | CompatState::No | CompatState::Dummy => return Ok(status),
            CompatState::Full | CompatState::Partial => {
                if self.actual_flags == 0 {
                    return Ok(status);
                }
            }
        }

        match unsafe { uapi::landlock_restrict_self(-1, self.actual_flags) } {
            0 => Ok(status),
            _ => Err(RestrictSelfError::RestrictSelfCall {
                source: std::io::Error::last_os_error(),
            }
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi;
    use crate::*;

    #[test]
    fn restrict_self_default() {
        let rs = RestrictSelf::default();
        assert_eq!(rs.requested_flags, 0);
        assert_eq!(rs.actual_flags, 0);

        // apply() on an unconfigured RestrictSelf returns the kernel's default
        // flag states.  The compat state is Init, so no real syscall is made.
        let status = rs.apply().unwrap();
        assert!(status.log_subdomains);
    }

    #[test]
    fn restrict_self_log_subdomains() {
        // With mocked V7: flag should be set.
        // TODO: Add real kernel test with audit parsing for end-to-end validation.
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::V7.into(),
        };
        let rs = rs.log_subdomains(false).unwrap();
        assert_ne!(rs.requested_flags, 0);
        assert_ne!(rs.actual_flags, 0);
        assert_eq!(rs.requested_flags, rs.actual_flags);
    }

    #[test]
    fn restrict_self_compatibility() {
        // HardRequirement on unsupported ABI returns error.
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::Unsupported.into(),
        };
        assert!(matches!(
            rs.set_compatibility(CompatLevel::HardRequirement)
                .log_subdomains(false)
                .unwrap_err(),
            RulesetError::RestrictSelfFlags(SyscallFlagError::NotSupported {
                flag: RestrictSelfFlag::LogSubdomains,
                set: false,
            })
        ));
    }

    #[test]
    fn restrict_self_no_flags() {
        // apply() with no flags set should skip the syscall.
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::V7.into(),
        };
        let status = rs.apply().unwrap();
        assert!(matches!(status.landlock, LandlockStatus::Available { .. }));
        assert!(status.log_subdomains); // default: enabled
    }

    #[test]
    fn restrict_self_partial_no_op() {
        // When all flags are dropped by BestEffort (actual_flags == 0),
        // apply() should still return the Landlock status from the kernel probe.
        let mut compat: Compatibility = ABI::V7.into();
        compat.update(CompatState::No);
        assert_eq!(compat.state, CompatState::No);

        let rs = RestrictSelf {
            requested_flags: 0b01,
            actual_flags: 0,
            no_new_privs: true,
            compat,
        };
        let status = rs.apply().unwrap();
        assert!(matches!(status.landlock, LandlockStatus::Available { .. }));
        assert!(status.log_subdomains); // default: enabled (flag was dropped)
    }

    #[test]
    fn restrict_self_best_effort_drops_unsupported() {
        // On an unsupported ABI, BestEffort silently drops all flags.
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::Unsupported.into(),
        };
        let rs = rs.log_subdomains(false).unwrap();
        assert_ne!(rs.requested_flags, 0);
        assert_eq!(rs.actual_flags, 0);
        let status = rs.apply().unwrap();
        assert_eq!(status.landlock, LandlockStatus::NotImplemented);
        assert!(status.log_subdomains); // flag was dropped, logging still enabled
    }

    #[test]
    fn restrict_self_soft_requirement_drops_unsupported() {
        // On an unsupported ABI, SoftRequirement transitions to Dummy and
        // silently drops the flag (without erroring like HardRequirement).
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::Unsupported.into(),
        };
        let rs = rs
            .set_compatibility(CompatLevel::SoftRequirement)
            .log_subdomains(false)
            .unwrap();
        assert_ne!(rs.requested_flags, 0);
        assert_eq!(rs.actual_flags, 0);
        let status = rs.apply().unwrap();
        assert_eq!(status.landlock, LandlockStatus::NotImplemented);
        assert!(status.log_subdomains); // flag was dropped, logging still enabled
    }

    #[test]
    fn restrict_self_subdomains_applied() {
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::V7.into(),
        };
        let rs = rs.log_subdomains(false).unwrap();
        assert_ne!(rs.actual_flags, 0);
        assert_ne!(
            rs.actual_flags & uapi::LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF,
            0
        );
    }

    #[test]
    fn restrict_self_hard_requirement_supported() {
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::V7.into(),
        };
        let rs = rs
            .set_compatibility(CompatLevel::HardRequirement)
            .log_subdomains(false)
            .unwrap();
        assert_ne!(rs.requested_flags, 0);
        assert_ne!(rs.actual_flags, 0);
    }

    #[test]
    fn restrict_self_last_call_wins() {
        // Setting a flag to non-default then back to default should clear
        // both requested and actual (last call wins).
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::V7.into(),
        };
        let rs = rs
            .log_subdomains(false)
            .unwrap()
            .log_subdomains(true)
            .unwrap();
        assert_eq!(rs.requested_flags, 0);
        assert_eq!(rs.actual_flags, 0);
    }

    #[test]
    fn restrict_self_default_after_hard_requirement() {
        // Setting a flag to its default value never requires a compat check,
        // so HardRequirement on an unsupported ABI does not error.
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::Unsupported.into(),
        };
        let rs = rs
            .set_compatibility(CompatLevel::HardRequirement)
            .log_subdomains(true)
            .unwrap();
        assert_eq!(rs.requested_flags, 0);
        assert_eq!(rs.actual_flags, 0);
    }

    #[test]
    fn restrict_self_no_nnp() {
        // With no_new_privs(false) and Unsupported (state Init, syscall
        // skipped), apply() reports no_new_privs: false without calling
        // prctl.
        let rs = RestrictSelf {
            requested_flags: 0,
            actual_flags: 0,
            no_new_privs: true,
            compat: ABI::Unsupported.into(),
        };
        let status = rs.no_new_privs(false).apply().unwrap();
        assert!(!status.no_new_privs);
        assert_eq!(status.landlock, LandlockStatus::NotImplemented);
    }
}
