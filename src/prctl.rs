// SPDX-License-Identifier: Apache-2.0 OR MIT

//! `prctl(2)` wrappers used by Landlock enforcement.
//!
//! These helpers are pub(crate) and called from
//! [`RulesetCreated::restrict_self()`](crate::RulesetCreated::restrict_self).

use crate::compat::Compatibility;
use crate::{CompatLevel, CompatState, RestrictSelfError};
use std::io::Error;

fn prctl_set_no_new_privs() -> Result<(), Error> {
    match unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

fn support_no_new_privs() -> bool {
    // Only Linux < 3.5 or kernel with seccomp filters should return an error.
    matches!(
        unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
        0 | 1
    )
}

/// Calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` and dispatches errors based on the
/// current compatibility level.
///
/// Returns `Ok(true)` if `no_new_privs` was successfully enforced.  Returns
/// `Ok(false)` if `prctl` failed but the failure was tolerated by the
/// current [`CompatLevel`] (silently dropped under `BestEffort`, transitions
/// to `Dummy` under `SoftRequirement`).  Returns `Err` if `prctl` failed
/// under `HardRequirement`, or if the running kernel claims to support
/// `no_new_privs` (or Landlock itself) but the call still failed.
pub(crate) fn try_set_no_new_privs(compat: &mut Compatibility) -> Result<bool, RestrictSelfError> {
    if let Err(e) = prctl_set_no_new_privs() {
        match compat.level.into() {
            CompatLevel::BestEffort => {}
            CompatLevel::SoftRequirement => {
                compat.update(CompatState::Dummy);
            }
            CompatLevel::HardRequirement => {
                return Err(RestrictSelfError::SetNoNewPrivsCall { source: e });
            }
        }
        // To get a consistent behavior, calls this prctl whether or not
        // Landlock is supported by the running kernel.
        let support_nnp = support_no_new_privs();
        match compat.state {
            // It should not be an error for kernel (older than 3.5) not supporting
            // no_new_privs.
            CompatState::Init | CompatState::No | CompatState::Dummy => {
                if support_nnp {
                    // The kernel seems to be between 3.5 (included) and 5.13 (excluded),
                    // or Landlock is not enabled; no_new_privs should be supported anyway.
                    return Err(RestrictSelfError::SetNoNewPrivsCall { source: e });
                }
            }
            // A kernel supporting Landlock should also support no_new_privs (unless
            // filtered by seccomp).
            CompatState::Full | CompatState::Partial => {
                return Err(RestrictSelfError::SetNoNewPrivsCall { source: e })
            }
        }
        Ok(false)
    } else {
        Ok(true)
    }
}
