// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Restrict_self flag configuration.
//!
//! The [`RestrictSelfAttr`] trait provides the
//! [`log_subdomains()`](RestrictSelfAttr::log_subdomains) setter.
//!
//! Domain-specific setters ([`log_same_exec()`](crate::RulesetCreatedAttr::log_same_exec),
//! [`log_new_exec()`](crate::RulesetCreatedAttr::log_new_exec)) are on
//! [`RulesetCreatedAttr`](crate::RulesetCreatedAttr) which requires
//! `RestrictSelfAttr` as a supertrait.

use crate::flags::RestrictSelfFlag;
use crate::RulesetError;

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
/// Implemented by [`RulesetCreated`](crate::RulesetCreated) via the
/// [`RulesetCreatedAttr`](crate::RulesetCreatedAttr) supertrait.
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
