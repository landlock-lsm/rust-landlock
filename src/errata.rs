// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::compat::ABI;
use crate::{uapi, BitFlags};
use enumflags2::bitflags;

/// Fixed kernel issues for the running Landlock implementation.
///
/// Each variant represents a specific bug fix that may have been
/// backported to the running kernel.  Use [`Erratum::current()`]
/// before building a [`Ruleset`](crate::Ruleset) to decide which
/// features are safe to use.
///
/// An [`ABI`] version can be converted into the set of applicable errata
/// with `BitFlags::<Erratum>::from(abi)`.
///
/// # Warning
///
/// Most applications should **not** check errata.  Disabling a sandboxing
/// feature because an erratum is not fixed could leave the system **less**
/// secure than using Landlock's best-effort protection with the buggy
/// feature enabled.  Errata should only be used to **add** features
/// (e.g., enabling a restriction only when its bug is confirmed fixed),
/// never to remove them.
#[bitflags]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Erratum {
    /// Erratum 1 (ABI 4): non-TCP stream sockets (SMC, MPTCP, SCTP)
    /// were incorrectly restricted by TCP access rights during
    /// `bind(2)` and `connect(2)`.
    ///
    /// Affects [`crate::AccessNet::BindTcp`] and [`crate::AccessNet::ConnectTcp`].
    ///
    /// See [erratum 1](https://docs.kernel.org/userspace-api/landlock.html#erratum-1-tcp-socket-identification).
    TcpSocketIdentification = 1 << 0,
    /// Erratum 2 (ABI 6): signal scoping was overly restrictive,
    /// preventing sandboxed threads from signaling other threads
    /// within the same process in different domains.
    ///
    /// Affects [`crate::Scope::Signal`].
    ///
    /// See [erratum 2](https://docs.kernel.org/userspace-api/landlock.html#erratum-2-scoped-signal-handling).
    ScopedSignalHandling = 1 << 1,
    /// Erratum 3 (ABI 1): access rights could be widened through
    /// rename or link actions on disconnected directories under
    /// bind mounts, potentially bypassing `LANDLOCK_ACCESS_FS_REFER`
    /// restrictions.
    ///
    /// See [erratum 3](https://docs.kernel.org/userspace-api/landlock.html#erratum-3-disconnected-directory-handling).
    DisconnectedDirectoryHandling = 1 << 2,
}

impl Erratum {
    /// Queries the running kernel for fixed errata.
    ///
    /// Returns a bitmask of errata that have been fixed in the running
    /// kernel.  Unknown errata bits from newer kernels are preserved.
    /// Returns empty if the kernel doesn't support the errata interface.
    pub fn current() -> BitFlags<Self> {
        let ret = unsafe {
            uapi::landlock_create_ruleset(std::ptr::null(), 0, uapi::LANDLOCK_CREATE_RULESET_ERRATA)
        };
        if ret >= 0 {
            // SAFETY: The kernel may return bits unknown to this crate version.
            // Using from_bits_unchecked to preserve them.
            unsafe { BitFlags::from_bits_unchecked(ret as u32) }
        } else {
            BitFlags::empty()
        }
    }
}

/// Converts an [`ABI`] version into the set of errata applicable to that ABI.
///
/// An erratum is applicable if the ABI includes the feature affected by the bug.
/// For example, [`Erratum::TcpSocketIdentification`] is only applicable to
/// [`ABI::V4`] and later, since TCP access rights were introduced in that version.
///
/// Uses the same incremental accumulation pattern as
/// [`AccessFs::from_write()`](crate::AccessFs::from_write).
///
/// # Stability
///
/// The set of errata returned for a given ABI may grow in future versions
/// of this crate as new kernel bug fixes are identified and backported.
/// Do not rely on the exact set being stable across crate versions.
impl From<ABI> for BitFlags<Erratum> {
    fn from(abi: ABI) -> Self {
        match abi {
            ABI::Unsupported => BitFlags::empty(),
            // Erratum 3: disconnected directory handling (FS, ABI 1+).
            ABI::V1 | ABI::V2 | ABI::V3 => Erratum::DisconnectedDirectoryHandling.into(),
            // Erratum 1: TCP socket identification (net, ABI 4+).
            ABI::V4 | ABI::V5 => Self::from(ABI::V3) | Erratum::TcpSocketIdentification,
            // Erratum 2: scoped signal handling (scopes, ABI 6+).
            // When adding a new ABI version without new errata, append it here.
            ABI::V6 => Self::from(ABI::V5) | Erratum::ScopedSignalHandling,
        }
    }
}

/// Returns the set of errata that have not been backported yet for a given ABI.
///
/// This is the single source of truth for known backport gaps.  When an
/// erratum is backported to a kernel version, remove it from the
/// corresponding match arm.  The CI will catch mismatches.
#[cfg(test)]
fn not_backported_yet(abi: ABI) -> BitFlags<Erratum> {
    match abi {
        ABI::Unsupported => BitFlags::empty(),
        // TODO: erratum 3 (DisconnectedDirectoryHandling) should be backported.
        ABI::V1 | ABI::V2 => Erratum::DisconnectedDirectoryHandling.into(),
        // 6.4, 6.7, 6.10: EOL, no errata interface on stable.kernel.
        ABI::V3 | ABI::V4 | ABI::V5 => BitFlags::empty(),
        // 6.12: all errata backported.
        ABI::V6 => BitFlags::empty(),
    }
}

#[test]
fn errata_query() {
    // Verifies the syscall wrapper works on any kernel.
    let _errata = Erratum::current();
}

#[test]
fn errata_up_to_date() {
    use crate::compat::{ABI, TEST_ABI, TEST_ABI_ENV_NAME};

    // This test requires LANDLOCK_CRATE_TEST_ABI to be explicitly set because
    // the errata assertions are tied to specific CI kernel versions.  Without
    // it, TEST_ABI is auto-detected from the running kernel, but From<i32>
    // maps unknown ABI versions to the highest known one, making the
    // ABI-to-kernel mapping ambiguous (e.g., a 6.15 kernel maps to V6 before
    // ABI::V7 exists).  Since Erratum::current() queries the real kernel, the
    // expected errata for the declared ABI may not match.
    if std::env::var(TEST_ABI_ENV_NAME).is_err() {
        eprintln!("Skipping errata_up_to_date: {} not set", TEST_ABI_ENV_NAME,);
        return;
    }

    let current = Erratum::current();
    let applicable: BitFlags<Erratum> = (*TEST_ABI).into();
    let expected = applicable & !not_backported_yet(*TEST_ABI);

    // Kernel must never report errata for features absent from this ABI.
    assert!(
        current & !applicable == BitFlags::empty(),
        "kernel reported errata not applicable to ABI {:?}: {:?}",
        *TEST_ABI,
        current & !applicable,
    );

    match *TEST_ABI {
        ABI::Unsupported => assert!(current.is_empty()),
        ABI::V1 | ABI::V2 => assert_eq!(current, expected),
        // 6.4, 6.7, 6.10: EOL, no errata interface on stable.kernel.
        ABI::V3 | ABI::V4 | ABI::V5 => {}
        ABI::V6 => assert_eq!(current, expected),
    }
}
