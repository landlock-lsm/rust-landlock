use crate::{uapi, Access, AccessError, BitFlags, CompatError};

#[cfg(test)]
use crate::{make_bitflags, AccessFs};
#[cfg(test)]
use std::convert::TryInto;
#[cfg(test)]
use strum::{EnumCount, IntoEnumIterator};
#[cfg(test)]
use strum_macros::{EnumCount as EnumCountMacro, EnumIter};

/// Version of the Landlock [ABI](https://en.wikipedia.org/wiki/Application_binary_interface).
///
/// `ABI` enables to get the features supported by a specific Landlock ABI.
/// For example, [`AccessFs::from_all(ABI::V1)`](Access::from_all)
/// gets all the file system access rights defined by the first version.
///
/// Without `ABI`, it would be hazardous to rely on the the full set of access flags
/// (e.g., `BitFlags::<AccessFs>::all()` or `BitFlags::ALL`),
/// a moving target that would change the semantics of your Landlock rule
/// when migrating to a newer version of this crate
/// (i.e. non-breaking change with new supported features).
/// This usage should then be considered indeterministic because requested features
/// (e.g., access rights)
/// could not be tied to the application source code.
///
/// Such `ABI` is also convenient to get the features supported by a specific Linux kernel
/// without relying on the kernel version (which may not be accessible or patched).
#[cfg_attr(
    test,
    derive(Debug, PartialEq, Eq, PartialOrd, EnumIter, EnumCountMacro)
)]
#[derive(Copy, Clone)]
#[non_exhaustive]
pub enum ABI {
    /// Kernel not supporting Landlock, either because it is not built with Landlock
    /// or Landlock is not enabled at boot.
    Unsupported = 0,
    /// First Landlock ABI,
    /// introduced with [Linux 5.13](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=62fb9874f5da54fdb243003b386128037319b219).
    V1 = 1,
    /// Second Landlock ABI,
    /// introduced with [Linux 5.19](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=3d7cb6b04c3f3115719235cc6866b10326de34cd).
    V2 = 2,
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
            _ => ABI::V2,
        }
    }

    #[cfg(test)]
    fn is_known(value: i32) -> bool {
        value > 0 && value < ABI::COUNT as i32
    }
}

#[test]
fn abi_from() {
    // EOPNOTSUPP (-95), ENOSYS (-38)
    for n in [-95, -38, -1, 0] {
        assert_eq!(ABI::from(n), ABI::Unsupported);
    }

    let mut last_i = 1;
    let mut last_abi = ABI::Unsupported;
    for (i, abi) in ABI::iter().enumerate() {
        last_i = i.try_into().unwrap();
        last_abi = abi;
        assert_eq!(ABI::from(last_i), last_abi);
    }

    assert_eq!(ABI::from(last_i + 1), last_abi);
    assert_eq!(ABI::from(9), last_abi);
}

#[test]
fn known_abi() {
    assert!(!ABI::is_known(-1));
    assert!(!ABI::is_known(0));
    assert!(!ABI::is_known(99));

    let mut last_i = -1;
    for (i, _) in ABI::iter().enumerate().skip(1) {
        last_i = i as i32;
        assert!(ABI::is_known(last_i));
    }
    assert!(!ABI::is_known(last_i + 1));
}

#[cfg(test)]
lazy_static! {
    static ref TEST_ABI: ABI = match std::env::var("LANDLOCK_CRATE_TEST_ABI") {
        Ok(s) => {
            let n = s.parse::<i32>().unwrap();
            if ABI::is_known(n) || n == 0 {
                ABI::from(n)
            } else {
                panic!("Unknown ABI: {}", n);
            }
        }
        Err(std::env::VarError::NotPresent) => ABI::iter().last().unwrap(),
        Err(e) => panic!("Failed to read LANDLOCK_CRATE_TEST_ABI: {}", e),
    };
}

#[cfg(test)]
pub fn can_emulate(mock: ABI, full_support: ABI) -> bool {
    mock <= *TEST_ABI || full_support <= *TEST_ABI
}

#[cfg(test)]
pub fn landlock_is_enabled() -> bool {
    *TEST_ABI != ABI::Unsupported
}

#[test]
fn current_kernel_abi() {
    // Ensures that the tested Landlock ABI is the latest known version supported by the running
    // kernel.  If this test failed, you need set the LANDLOCK_CRATE_TEST_ABI environment variable
    // to the Landlock ABI version supported by your kernel.  With a missing variable, the latest
    // Landlock ABI version known by this crate is automatically set.
    // From Linux 5.13 to 5.18, you need to run: LANDLOCK_CRATE_TEST_ABI=1 cargo test
    assert_eq!(*TEST_ABI, ABI::new_current());
}

/// Returned by ruleset builder.
#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Copy, Clone)]
pub(crate) enum CompatState {
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
            (CompatState::No, CompatState::No) => CompatState::No,
            (CompatState::Full, CompatState::Full) => CompatState::Full,
            (_, _) => CompatState::Partial,
        }
    }
}

#[test]
fn compat_state_update_1() {
    let mut state = CompatState::Full;

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Full);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Final);
    assert_eq!(state, CompatState::Final);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Final);
}

#[test]
fn compat_state_update_2() {
    let mut state = CompatState::Full;

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Full);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Partial);
}

#[cfg_attr(test, derive(Debug))]
#[derive(Clone)]
// Compatibility is not public outside this crate.
pub struct Compatibility {
    pub(crate) abi: ABI,
    pub(crate) is_best_effort: bool,
    pub(crate) state: CompatState,
}

impl From<ABI> for Compatibility {
    fn from(abi: ABI) -> Self {
        Compatibility {
            abi,
            is_best_effort: true,
            state: match abi {
                // Forces the state as unsupported because all possible types will be useless.
                ABI::Unsupported => CompatState::Final,
                _ => CompatState::Full,
            },
        }
    }
}

impl Compatibility {
    // Compatibility is an opaque struct.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        ABI::new_current().into()
    }
}

/// Properly handles runtime unsupported features.
///
/// This guarantees consistent behaviors across crate users
/// and runtime kernels even if this crate get new features.
/// It eases backward compatibility and enables future-proofness.
///
/// Landlock is a security feature designed to help improve security of a running system
/// thanks to application developers.
/// To protect users as much as possible,
/// compatibility with the running system should then be handled in a best-effort way,
/// contrary to common system features.
/// In some circumstances
/// (e.g. applications carefully designed to only be run with a specific set of kernel features),
/// it may be required to error out if some of these features are not available
/// and will then not be enforced.
pub trait Compatible {
    /// To enable a best-effort security approach,
    /// Landlock features that are not supported by the running system
    /// are silently ignored by default,
    /// which is a sane choice for most use cases.
    /// However, on some rare circumstances,
    /// developers may want to have some guarantees that their applications
    /// will not run if a certain level of sandboxing is not possible.
    /// If you really want to error out when not all your requested requirements are met,
    /// then you can configure it with `set_best_effort(false)`.
    ///
    /// The order of this call is important because
    /// it defines the behavior of the following method calls that return a [`Result`].
    /// If `set_best_effort(false)` is called on an object,
    /// then a [`CompatError`] may be returned for the next method calls,
    /// until the next call to `set_best_effort(true)`.
    /// This enables to change the behavior of a set of build calls,
    /// for instance to be sure that the sandbox will at least restrict some access rights.
    ///
    /// # Example
    ///
    /// Create a ruleset which will at least support execution constraints.
    ///
    /// ```
    /// use landlock::{
    ///     Access, AccessFs, Compatible, PathBeneath, Ruleset, RulesetCreated, RulesetError, ABI,
    /// };
    ///
    /// fn ruleset_fragile() -> Result<RulesetCreated, RulesetError> {
    ///     Ok(Ruleset::new()
    ///         // This ruleset must handle at least the execute access.
    ///         .set_best_effort(false)
    ///         // This handle_access() call will return
    ///         // a wrapped AccessError<AccessFs>::Incompatible error
    ///         // if the running kernel can't handle AccessFs::Execute.
    ///         .handle_access(AccessFs::Execute)?
    ///         // This ruleset may also handle other access rights
    ///         // if they are supported by the running kernel.
    ///         // Because handle_access() replaces the previously set value,
    ///         // the new value must be a superset of AccessFs::Execute.
    ///         .set_best_effort(true)
    ///         .handle_access(AccessFs::from_all(ABI::V1))?
    ///         .create()?)
    /// }
    /// ```
    fn set_best_effort(self, best_effort: bool) -> Self;
}

// TryCompat is not public outside this crate.
pub trait TryCompat<T> {
    fn try_compat(self, compat: &mut Compatibility) -> Result<Self, CompatError<T>>
    where
        Self: Sized,
        T: Access;
}

// Creates an illegal/overflowed BitFlags<T> with all its bits toggled, including undefined ones.
fn full_negation<T>(flags: BitFlags<T>) -> BitFlags<T>
where
    T: Access,
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
    T: Access,
{
    fn try_compat(self, compat: &mut Compatibility) -> Result<Self, CompatError<T>> {
        let (state, new_access) = if self.is_empty() {
            // Empty access-rights would result to a runtime error.
            return Err(AccessError::Empty.into());
        } else if !Self::all().contains(self) {
            // Unknown access-rights (at build time) would result to a runtime error.
            // This can only be reached by using the unsafe BitFlags::from_bits_unchecked().
            return Err(AccessError::Unknown {
                access: self,
                unknown: self & full_negation(Self::all()),
            }
            .into());
        } else {
            let compat_bits = self & T::from_all(compat.abi);
            if compat_bits.is_empty() {
                if compat.is_best_effort {
                    // TODO: This creates an empty access-right and could be an issue with
                    // future ABIs.  This method should return Result<Option<Self>,
                    // CompatError> instead, and in this case Ok(None).
                    (CompatState::No, compat_bits)
                } else {
                    return Err(AccessError::Incompatible { access: self }.into());
                }
            } else if compat_bits != self {
                if compat.is_best_effort {
                    (CompatState::Partial, compat_bits)
                } else {
                    return Err(AccessError::PartiallyCompatible {
                        access: self,
                        incompatible: self & full_negation(compat_bits),
                    }
                    .into());
                }
            } else {
                (CompatState::Full, compat_bits)
            }
        };
        compat.state.update(state);
        Ok(new_access)
    }
}

#[test]
fn compat_bit_flags() {
    let mut compat = ABI::V1.into();

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
