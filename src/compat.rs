use crate::{uapi, AccessError, BitFlags, CompatError};
use enumflags2::BitFlag;

#[cfg(test)]
use crate::{make_bitflags, AccessFs};

/// Version of the Landlock [ABI](https://en.wikipedia.org/wiki/Application_binary_interface).
#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Copy, Clone)]
#[non_exhaustive]
pub enum ABI {
    Unsupported = 0,
    V1 = 1,
}

impl ABI {
    // Must remain private to avoid inconsistent behavior by passing Ok(self) to a builder method,
    // e.g. to make it impossible to call ruleset.handle_fs(ABI::new_current()?)
    fn new_current() -> Self {
        ABI::from(unsafe {
            // Landlock ABI version starts at 1 but errno is only set for negative values.
            uapi::landlock_create_ruleset(
                std::ptr::null(),
                0,
                uapi::LANDLOCK_CREATE_RULESET_VERSION,
            )
        })
    }

    // There is no way to not publicly expose an implementation of an external trait such as
    // From<i32>.  See RFC https://github.com/rust-lang/rfcs/pull/2529
    fn from(value: i32) -> ABI {
        match value {
            // The only possible error values should be EOPNOTSUPP and ENOSYS, but let's interpret
            // all kind of errors as unsupported.
            n if n <= 0 => ABI::Unsupported,
            1 => ABI::V1,
            // Returns the greatest known ABI.
            _ => ABI::V1,
        }
    }
}

#[test]
fn abi_from() {
    // EOPNOTSUPP (-95), ENOSYS (-38)
    for n in &[-95, -38, -1, 0] {
        assert_eq!(ABI::from(*n), ABI::Unsupported);
    }

    assert_eq!(ABI::from(1), ABI::V1);
    assert_eq!(ABI::from(2), ABI::V1);
    assert_eq!(ABI::from(9), ABI::V1);
}

/// Returned by ruleset builder.
#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Copy, Clone)]
pub(crate) enum CompatState {
    /// Initial unknown state.
    Start,
    /// All requested restrictions are enforced.
    Full,
    /// Some requested restrictions are enforced, following a best-effort approach.
    Partial,
    /// The running system doesn't support Landlock.
    No,
    /// Final unsupported state.
    Final,
}

impl CompatState {
    pub(crate) fn update(&mut self, other: Self) {
        *self = match (*self, other) {
            (CompatState::Final, _) => CompatState::Final,
            (_, CompatState::Final) => CompatState::Final,
            (CompatState::Start, state) => state,
            (state, CompatState::Start) => state,
            (CompatState::No, CompatState::No) => CompatState::No,
            (CompatState::Full, CompatState::Full) => CompatState::Full,
            (_, _) => CompatState::Partial,
        }
    }
}

#[test]
fn compat_state_update_1() {
    let mut state = CompatState::Start;

    state.update(CompatState::Start);
    assert_eq!(state, CompatState::Start);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::No);

    state.update(CompatState::Start);
    assert_eq!(state, CompatState::No);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Start);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Final);
    assert_eq!(state, CompatState::Final);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Final);

    state.update(CompatState::Start);
    assert_eq!(state, CompatState::Final);
}

#[test]
fn compat_state_update_2() {
    let mut state = CompatState::Full;

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Full);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Start);
    assert_eq!(state, CompatState::Partial);
}

/// Properly handles runtime unsupported features.  This enables to guarantee consistent behaviors
/// across crate users and runtime kernels even if this crate get new features.  It eases backward
/// compatibility and enables future-proofness.
///
/// Landlock is a security feature designed to help improve security of a running system thanks to
/// application developers.  To protect users as much as possible, compatibility with the running
/// system should then be handled in a best-effort way, contrary to common system features.  In
/// some circumstances (e.g. applications carefully designed to only be run with a specific kernel
/// version), it may be required to check if some of there features are enforced, which is possible
/// with XXX
#[cfg_attr(test, derive(Debug))]
#[derive(Clone)]
// Compatibility is not public outside this crate.
pub struct Compatibility {
    pub(crate) abi: ABI,
    pub(crate) is_best_effort: bool,
    pub(crate) state: CompatState,
}

impl Compatibility {
    pub fn new() -> Compatibility {
        let abi = ABI::new_current();
        Compatibility {
            abi: abi,
            is_best_effort: true,
            state: match abi {
                // Forces the state as unsupported because all possible types will be useless.
                ABI::Unsupported => CompatState::Final,
                _ => CompatState::Start,
            },
        }
    }
}

pub trait Compatible {
    /// To enable a best-effort security approach, Landlock features that are not supported by the
    /// running system are silently ignored by default.  If you want to error out when not all your
    /// requested requirements are met, then you can configure it with `set_best_effort(false)`.
    fn set_best_effort(self, best_effort: bool) -> Self;
}

// TryCompat is not public outside this crate.
pub trait TryCompat<T> {
    fn try_compat(self, compat: &mut Compatibility) -> Result<Self, CompatError<T>>
    where
        Self: Sized,
        T: BitFlag;
}

// Creates an illegal/overflowed BitFlags<T> with all its bits toggled, including undefined ones.
fn full_negation<T>(flags: BitFlags<T>) -> BitFlags<T>
where
    T: BitFlag,
{
    unsafe { BitFlags::<T>::from_bits_unchecked(!flags.bits()) }
}

#[test]
fn bit_flags_full_negation() {
    let scoped_negation = !BitFlags::<AccessFs>::all();
    assert_eq!(scoped_negation, BitFlags::<AccessFs>::empty());
    // !BitFlags::<AccessFs>::all() could be equal to full_negation(BitFlags::<AccessFs>::all()))
    // if all the 64-bits would be used, which is not currently the case.
    assert_ne!(scoped_negation, full_negation(BitFlags::<AccessFs>::all()));
}

impl<T> TryCompat<T> for BitFlags<T>
where
    T: BitFlag,
    BitFlags<T>: From<ABI>,
{
    fn try_compat(self, compat: &mut Compatibility) -> Result<Self, CompatError<T>> {
        let (state, ret) = if self.is_empty() {
            // Empty access-rights would result to a runtime error.
            (CompatState::Final, Err(AccessError::Empty.into()))
        } else if !Self::all().contains(self) {
            // Unknown access-rights (at build time) would result to a runtime error.
            // This can only be reached by using the unsafe BitFlags::from_bits_unchecked().
            (
                CompatState::Final,
                Err(AccessError::Unknown {
                    access: self,
                    unknown: self & full_negation(Self::all()),
                }
                .into()),
            )
        } else {
            let compat_bits = self & Self::from(compat.abi);
            if compat_bits.is_empty() {
                (
                    CompatState::No,
                    if compat.is_best_effort {
                        // TODO: This creates an empty access-right and could be an issue with
                        // future ABIs.  This method should return Result<Option<Self>,
                        // CompatError> instead, and in this case Ok(None).
                        Ok(compat_bits)
                    } else {
                        Err(AccessError::Incompatible { access: self }.into())
                    },
                )
            } else if compat_bits != self {
                (
                    CompatState::Partial,
                    if compat.is_best_effort {
                        Ok(compat_bits)
                    } else {
                        Err(AccessError::PartiallyCompatible {
                            access: self,
                            incompatible: self & full_negation(compat_bits),
                        }
                        .into())
                    },
                )
            } else {
                (CompatState::Full, Ok(compat_bits))
            }
        };
        compat.state.update(state);
        ret
    }
}

#[test]
fn compat_bit_flags() {
    let mut compat = Compatibility {
        abi: ABI::V1,
        is_best_effort: true,
        state: CompatState::Start,
    };

    let ro_access = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
    assert_eq!(ro_access, ro_access.try_compat(&mut compat).unwrap());

    let empty_access = BitFlags::<AccessFs>::empty();
    assert!(matches!(
        empty_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Empty)
    ));

    let all_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63) };
    assert!(matches!(
        all_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == all_unknown_access && unknown == all_unknown_access
    ));

    let some_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63 | 1) };
    assert!(matches!(
        some_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == some_unknown_access && unknown == all_unknown_access
    ));

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    compat.abi = ABI::Unsupported;
    assert_eq!(empty_access, ro_access.try_compat(&mut compat).unwrap());

    // Access-rights are not valid when they are required for the current ABI.
    compat.is_best_effort = false;
    assert!(matches!(
        ro_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Incompatible { access }) if access == ro_access
    ));
}
