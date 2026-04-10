// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Syscall flag types for `landlock_restrict_self()` and future syscall flags.
//!
//! This module provides a compatibility mechanism for individual syscall flags,
//! parallel to but simpler than the [`Access`](crate::Access) /
//! [`TryCompat`](crate::TryCompat) machinery.
//!
//! Key differences from the [`Access`](crate::Access) pattern:
//!
//! - Access types ([`AccessFs`](crate::AccessFs), [`AccessNet`](crate::AccessNet),
//!   [`Scope`](crate::Scope)) operate on **sets** of rights passed as
//!   [`BitFlags<T>`](enumflags2::BitFlags), where the compat result can be Full,
//!   Partial, or No depending on which bits are supported.  They use the
//!   [`TryCompat`](crate::TryCompat) trait and the full
//!   [`AccessError`](crate::AccessError) hierarchy.
//!
//! - Syscall flags are set **individually** through boolean setter methods
//!   (e.g., [`log_same_exec()`](crate::RulesetCreatedAttr::log_same_exec)), so
//!   the compat result is binary: supported or not.  There is no Partial case,
//!   no set-level validation, and no need for an
//!   [`AccessError`](crate::AccessError)-like hierarchy.  The
//!   [`try_compat()`](SyscallFlagExt::try_compat) default method on
//!   [`SyscallFlagExt`] handles the compat dispatch directly, using
//!   [`Compatibility::try_compat_binary()`](crate::compat::Compatibility::try_compat_binary)
//!   factored out from the No branch of
//!   [`TryCompat::try_compat()`](crate::TryCompat::try_compat).
//!
//! - Access types implement the [`Access`](crate::Access) trait (which requires
//!   [`BitFlag`](enumflags2::BitFlag)) and are used with
//!   [`BitFlags<T>`](enumflags2::BitFlags) throughout the builder.  Syscall
//!   flags are plain enums (no `#[bitflags]`); the raw UAPI bitmask is built
//!   internally by OR-ing the constants returned by
//!   [`raw_bit()`](SyscallFlagExt::raw_bit) into a `u32`.

use crate::compat::{Compatibility, ABI};
use crate::errors::SyscallFlagError;
use crate::private;
use crate::uapi;

/// Marker trait for syscall flag types used in compatibility checks.
///
/// This is the syscall-flag equivalent of the [`Access`](crate::Access) trait,
/// but without the [`BitFlag`](enumflags2::BitFlag) requirement since syscall
/// flags are set individually rather than as sets.
///
/// This trait is sealed and cannot be implemented outside of this crate.
pub trait SyscallFlag: Copy + core::fmt::Debug + private::Sealed {}

/// Internal extension providing compatibility logic for syscall flags.
///
/// This is the syscall-flag equivalent of [`TryCompat`](crate::TryCompat),
/// simplified for single-flag boolean setters where the compat result is
/// binary (supported or not) rather than Full/Partial/No.
///
/// Implementors provide [`default_value()`](Self::default_value),
/// [`raw_bit()`](Self::raw_bit), and [`since()`](Self::since); the
/// [`try_compat()`](Self::try_compat) default method handles the compat
/// state update and level dispatch.
pub(crate) trait SyscallFlagExt: SyscallFlag {
    /// Returns the kernel's default state for this flag.
    fn default_value(self) -> bool;

    /// Returns the raw UAPI constant for this flag.
    fn raw_bit(self) -> u32;

    /// Returns the minimum ABI version that supports this flag.
    fn since(self) -> ABI;

    /// Checks compatibility and returns whether the non-default bit should
    /// be applied.
    ///
    /// Returns `Ok(true)` if [`raw_bit()`](Self::raw_bit) should be set in
    /// the actual flags.  Returns `Ok(false)` if the flag should be cleared
    /// to its default state, either because `set == default_value()` or
    /// because the kernel does not support the flag and the compat level
    /// permits dropping it.  Returns `Err` if the flag is unsupported with
    /// [`CompatLevel::HardRequirement`](crate::CompatLevel::HardRequirement).
    ///
    /// Setting to the default value never requires a compat check.
    ///
    /// This mirrors the compat dispatch in
    /// [`TryCompat::try_compat()`](crate::TryCompat::try_compat) but without
    /// the Partial case (a single flag is either fully supported or not).
    fn try_compat(
        self,
        set: bool,
        compat: &mut Compatibility,
    ) -> Result<bool, SyscallFlagError<Self>> {
        if set == self.default_value() {
            // Setting to the default value is always safe; no compat check
            // needed and the caller should clear the bit.
            return Ok(false);
        }
        compat.try_compat_binary(compat.abi() >= self.since(), || {
            SyscallFlagError::NotSupported { flag: self, set }
        })
    }
}

/// Identifies a configuration flag for the `landlock_restrict_self()` syscall.
///
/// Unlike access rights ([`AccessFs`](crate::AccessFs), [`AccessNet`](crate::AccessNet))
/// and scopes ([`Scope`](crate::Scope)), these flags are not passed to
/// `landlock_create_ruleset()` but to `landlock_restrict_self()`.  They control
/// audit logging behavior rather than access restrictions.
///
/// Each flag is set through a dedicated boolean method on
/// [`RulesetCreatedAttr`](crate::RulesetCreatedAttr) or
/// [`RestrictSelfAttr`](crate::RestrictSelfAttr).  The polarity mapping
/// (e.g., `log_same_exec(false)` maps to `LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`)
/// is handled internally.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
// All variants intentionally share the "Log" prefix to match the kernel's
// LANDLOCK_RESTRICT_SELF_LOG_* naming convention.  Future non-logging flags
// (e.g., TSYNC) will break the shared prefix, removing the need for this allow.
#[allow(clippy::enum_variant_names)]
pub enum RestrictSelfFlag {
    /// Same-exec logging (see [`RulesetCreatedAttr::log_same_exec()`](crate::RulesetCreatedAttr::log_same_exec)).
    LogSameExec,
    /// New-exec logging (see [`RulesetCreatedAttr::log_new_exec()`](crate::RulesetCreatedAttr::log_new_exec)).
    LogNewExec,
    /// Subdomain logging (see [`RestrictSelfAttr::log_subdomains()`](crate::RestrictSelfAttr::log_subdomains)).
    LogSubdomains,
}

impl SyscallFlag for RestrictSelfFlag {}

impl RestrictSelfFlag {
    /// Returns the effective state of this flag given a raw bitmask of
    /// applied flags.
    pub(crate) fn is_set(self, raw_flags: u32) -> bool {
        // Each flag's raw_bit() returns either an OFF or ON UAPI constant
        // depending on the kernel's default for that flag.  When the bit
        // is set in raw_flags, the kernel applies the opposite of the
        // default; when unset, the default applies.
        if raw_flags & self.raw_bit() != 0 {
            !self.default_value()
        } else {
            self.default_value()
        }
    }
}

impl SyscallFlagExt for RestrictSelfFlag {
    fn default_value(self) -> bool {
        match self {
            // Same-exec logging is enabled by default.
            Self::LogSameExec => true,
            // New-exec logging is disabled by default.
            Self::LogNewExec => false,
            // Subdomain logging is enabled by default.
            Self::LogSubdomains => true,
        }
    }

    fn raw_bit(self) -> u32 {
        match self {
            Self::LogSameExec => uapi::LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF,
            Self::LogNewExec => uapi::LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,
            Self::LogSubdomains => uapi::LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF,
        }
    }

    fn since(self) -> ABI {
        match self {
            Self::LogSameExec => ABI::V7,
            Self::LogNewExec => ABI::V7,
            Self::LogSubdomains => ABI::V7,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uapi;

    #[test]
    fn restrict_self_flag_raw_bit() {
        assert_eq!(
            RestrictSelfFlag::LogSameExec.raw_bit(),
            uapi::LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF,
        );
        assert_eq!(
            RestrictSelfFlag::LogNewExec.raw_bit(),
            uapi::LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,
        );
        assert_eq!(
            RestrictSelfFlag::LogSubdomains.raw_bit(),
            uapi::LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF,
        );
    }

    #[test]
    fn restrict_self_flag_default_value() {
        assert!(RestrictSelfFlag::LogSameExec.default_value());
        assert!(!RestrictSelfFlag::LogNewExec.default_value());
        assert!(RestrictSelfFlag::LogSubdomains.default_value());
    }

    #[test]
    fn restrict_self_flag_since() {
        assert_eq!(RestrictSelfFlag::LogSameExec.since(), ABI::V7);
        assert_eq!(RestrictSelfFlag::LogNewExec.since(), ABI::V7);
        assert_eq!(RestrictSelfFlag::LogSubdomains.since(), ABI::V7);
    }
}
