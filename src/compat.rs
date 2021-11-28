use crate::{uapi, Access, CompatError};

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
                panic!("Unknown ABI: {n}");
            }
        }
        Err(std::env::VarError::NotPresent) => ABI::iter().last().unwrap(),
        Err(e) => panic!("Failed to read LANDLOCK_CRATE_TEST_ABI: {e}"),
    };
}

#[cfg(test)]
pub(crate) fn can_emulate(mock: ABI, full_support: ABI) -> bool {
    mock <= *TEST_ABI || full_support <= *TEST_ABI
}

#[cfg(test)]
pub(crate) fn get_errno_from_landlock_status() -> Option<i32> {
    use std::io::Error;

    if unsafe {
        uapi::landlock_create_ruleset(std::ptr::null(), 0, uapi::LANDLOCK_CREATE_RULESET_VERSION)
    } < 0
    {
        match Error::last_os_error().raw_os_error() {
            // Returns ENOSYS when the kernel is not built with Landlock support,
            // or EOPNOTSUPP when Landlock is supported but disabled at boot time.
            ret @ Some(libc::ENOSYS | libc::EOPNOTSUPP) => ret,
            // Other values can only come from bogus seccomp filters or debug tampering.
            _ => unreachable!(),
        }
    } else {
        None
    }
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
#[cfg_attr(test, derive(Debug))]
#[derive(Copy, Clone, PartialEq)]
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
    fn update(&mut self, other: Self) {
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

#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Clone)]
// Compatibility is not public outside this crate.
pub struct Compatibility {
    pub(crate) abi: ABI,
    pub(crate) level: CompatLevel,
    pub(crate) state: CompatState,
    // is_mooted is required to differenciate a kernel not supporting Landlock from an error that
    // occured with CompatLevel::SoftRequirement.  is_mooted is only changed with update() and only
    // used to not set no_new_privs in RulesetCreated::restrict_self().
    is_mooted: bool,
}

impl From<ABI> for Compatibility {
    fn from(abi: ABI) -> Self {
        Compatibility {
            abi,
            level: CompatLevel::default(),
            state: match abi {
                // Forces the state as unsupported because all possible types will be useless.
                ABI::Unsupported => CompatState::Final,
                _ => CompatState::Full,
            },
            is_mooted: false,
        }
    }
}

impl Compatibility {
    // Compatibility is an opaque struct.
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        ABI::new_current().into()
    }

    pub(crate) fn update(&mut self, state: CompatState) {
        self.state.update(state);
        if state == CompatState::Final {
            self.abi = ABI::Unsupported;
            self.is_mooted = true;
        }
    }

    pub(crate) fn is_mooted(&self) -> bool {
        self.is_mooted
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
    /// If we really want to error out when not all our requested requirements are met,
    /// then we can configure it with `set_compatibility()`.
    ///
    /// The `Compatible` trait is implemented for all object builders
    /// (e.g. [`Ruleset`](crate::Ruleset)).
    /// Such builders have a set of methods to incrementally build an object.
    /// These build methods rely on kernel features that may not be available at runtime.
    /// The `set_compatibility()` method enables to control the effect of
    /// the following build method calls starting from this call.
    /// Such effect can be:
    /// * to silently ignore unsupported features
    ///   and continue building ([`CompatLevel::BestEffort`]);
    /// * to silently ignore unsupported features
    ///   and ignore the whole build ([`CompatLevel::SoftRequirement`]);
    /// * to return an error for any unsupported feature ([`CompatLevel::HardRequirement`]).
    ///
    /// Taking [`Ruleset`](crate::Ruleset) as an example,
    /// the [`handle_access()`](crate::RulesetAttr::handle_access()) build method
    /// returns a [`Result`] that can be [`Err(RulesetError)`](crate::RulesetError)
    /// with a nested [`CompatError`].
    /// Such error can only occur with a running Linux kernel not supporting the requested
    /// Landlock accesses *and* if the current compatibility level is
    /// [`CompatLevel::HardRequirement`].
    /// However, such error is not possible with [`CompatLevel::BestEffort`]
    /// nor [`CompatLevel::SoftRequirement`].
    ///
    /// The order of this call is important because
    /// it defines the behavior of the following build method calls that return a [`Result`].
    /// If `set_compatibility(CompatLevel::HardRequirement)` is called on an object,
    /// then a [`CompatError`] may be returned for the next method calls,
    /// until the next call to `set_compatibility()`.
    /// This enables to change the behavior of a set of build method calls,
    /// for instance to be sure that the sandbox will at least restrict some access rights.
    ///
    /// New objects inherit the compatibility configuration of their parents, if any.
    /// For instance, [`Ruleset::create()`](crate::Ruleset::create()) returns
    /// a [`RulesetCreated`](crate::RulesetCreated) object that inherits the
    /// `Ruleset`'s compatibility configuration.
    ///
    /// # Example
    ///
    /// Create a ruleset which will at least support all restrictions provided by
    /// the [first version of Landlock](ABI::V1), and may also support the
    /// [`AccessFs::Refer`](crate::AccessFs::Refer) restriction according to the running kernel.
    ///
    /// ```
    /// use landlock::{
    ///     ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    ///     RulesetCreated, RulesetError,
    /// };
    ///
    /// fn ruleset_fragile() -> Result<RulesetCreated, RulesetError> {
    ///     Ok(Ruleset::new()
    ///         // This ruleset must handle at least all accesses defined by
    ///         // the first Landlock version (e.g. AccessFs::WriteFile).
    ///         .set_compatibility(CompatLevel::HardRequirement)
    ///         // This handle_access() call may now return a wrapped
    ///         // AccessError<AccessFs>::Incompatible error if Landlock
    ///         // is not supported by the running kernel.
    ///         .handle_access(AccessFs::from_all(ABI::V1))?
    ///         // This ruleset may also handle the AccessFs::Refer right (defined by
    ///         // the second version of Landlock) if it is supported by the running kernel.
    ///         .set_compatibility(CompatLevel::BestEffort)
    ///         // The following handle_access() calls will now never return an error.
    ///         .handle_access(AccessFs::Refer)?
    ///         .create()?)
    /// }
    /// ```
    fn set_compatibility(self, level: CompatLevel) -> Self;

    /// Cf. [`set_compatibility()`](Compatible::set_compatibility()):
    ///
    /// - `set_best_effort(true)` translates to `set_compatibility(CompatLevel::BestEffort)`.
    ///
    /// - `set_best_effort(false)` translates to `set_compatibility(CompatLevel::HardRequirement)`.
    #[deprecated(note = "Use set_compatibility() instead")]
    fn set_best_effort(self, best_effort: bool) -> Self
    where
        Self: Sized,
    {
        self.set_compatibility(match best_effort {
            true => CompatLevel::BestEffort,
            false => CompatLevel::HardRequirement,
        })
    }
}

#[test]
#[allow(deprecated)]
fn deprecated_set_best_effort() {
    use crate::{CompatLevel, Compatible, Ruleset};

    assert_eq!(
        Ruleset::new().set_best_effort(true).compat,
        Ruleset::new()
            .set_compatibility(CompatLevel::BestEffort)
            .compat
    );
    assert_eq!(
        Ruleset::new().set_best_effort(false).compat,
        Ruleset::new()
            .set_compatibility(CompatLevel::HardRequirement)
            .compat
    );
}

/// See the [`Compatible`] documentation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CompatLevel {
    /// Takes into account the build requests if they are supported by the running system,
    /// or silently ignores them otherwise.
    /// Never returns a compatibility error.
    #[default]
    BestEffort,
    /// Takes into account the build requests if they are supported by the running system,
    /// or silently ignores the whole build object otherwise.
    /// Never returns a compatibility error.
    /// If not supported,
    /// the call to [`RulesetCreated::restrict_self()`](crate::RulesetCreated::restrict_self())
    /// will return a
    /// [`RestrictionStatus { ruleset: RulesetStatus::NotEnforced, no_new_privs: false, }`](crate::RestrictionStatus).
    SoftRequirement,
    /// Takes into account the build requests if they are supported by the running system,
    /// or returns a compatibility error otherwise ([`CompatError`]).
    HardRequirement,
}

// TryCompat is not public outside this crate.
pub trait TryCompat<T> {
    fn try_compat(self, compat: &mut Compatibility) -> Result<Option<Self>, CompatError<T>>
    where
        Self: Sized,
        T: Access;
}
