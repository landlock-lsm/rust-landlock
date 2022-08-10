use crate::{
    uapi, AccessFs, AddRuleError, AddRulesError, BitFlags, CompatState, Compatibility, Compatible,
    CreateRulesetError, HandleAccessError, HandleAccessesError, RestrictSelfError, RulesetError,
    TryCompat, ABI,
};
use enumflags2::BitFlag;
use libc::close;
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;

#[cfg(test)]
use crate::*;

pub trait Access: PrivateAccess {
    /// Gets the access rights defined by a specific [`ABI`].
    /// Union of [`from_read()`](Access::from_read) and [`from_write()`](Access::from_write).
    fn from_all(abi: ABI) -> BitFlags<Self> {
        // An empty access-right would be an error if passed to the kernel, but because the kernel
        // doesn't support Landlock, no Landlock syscall should be called.  try_compat() should
        // also return RestrictionStatus::Unrestricted when called with unsupported/empty
        // access-righs.
        Self::from_read(abi) | Self::from_write(abi)
    }

    /// Gets the access rights identified as read-only according to a specific ABI.
    /// Exclusive with [`from_write()`](Access::from_write).
    fn from_read(abi: ABI) -> BitFlags<Self>;

    /// Gets the access rights identified as write-only according to a specific ABI.
    /// Exclusive with [`from_read()`](Access::from_read).
    fn from_write(abi: ABI) -> BitFlags<Self>;
}

pub trait PrivateAccess: BitFlag {
    fn ruleset_handle_access(
        ruleset: Ruleset,
        access: BitFlags<Self>,
    ) -> Result<Ruleset, HandleAccessesError>
    where
        Self: Access;

    fn into_add_rules_error(error: AddRuleError<Self>) -> AddRulesError
    where
        Self: Access;

    fn into_handle_accesses_error(error: HandleAccessError<Self>) -> HandleAccessesError
    where
        Self: Access;
}

// Public interface without methods and which is impossible to implement outside this crate.
pub trait Rule<T>: PrivateRule<T>
where
    T: Access,
{
}

// PrivateRule is not public outside this crate.
pub trait PrivateRule<T>: TryCompat<T>
where
    T: Access,
{
    fn as_ptr(&self) -> *const libc::c_void;
    fn get_type_id(&self) -> uapi::landlock_rule_type;
    fn get_flags(&self) -> u32;
    fn check_consistency(&self, ruleset: &RulesetCreated) -> Result<(), AddRulesError>;
}

/// Enforcement status of a ruleset.
#[derive(Debug, PartialEq, Eq)]
pub enum RulesetStatus {
    /// All requested restrictions are enforced.
    FullyEnforced,
    /// Some requested restrictions are enforced,
    /// following a best-effort approach.
    PartiallyEnforced,
    /// The running system doesn't support Landlock
    /// or a subset of the requested Landlock features.
    NotEnforced,
}

impl From<CompatState> for RulesetStatus {
    fn from(state: CompatState) -> Self {
        match state {
            CompatState::No | CompatState::Final => RulesetStatus::NotEnforced,
            CompatState::Full => RulesetStatus::FullyEnforced,
            CompatState::Partial => RulesetStatus::PartiallyEnforced,
        }
    }
}

// The Debug, PartialEq and Eq implementations are useful for crate users to debug and check the
// result of a Landlock ruleset enforcement.
/// Status of a [`RulesetCreated`]
/// after calling [`restrict_self()`](RulesetCreated::restrict_self).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestrictionStatus {
    /// Status of the Landlock ruleset enforcement.
    pub ruleset: RulesetStatus,
    /// Status of `prctl(2)`'s `PR_SET_NO_NEW_PRIVS` enforcement.
    pub no_new_privs: bool,
}

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

/// Landlock ruleset builder.
///
/// `Ruleset` enables to create a Landlock ruleset in a flexible way
/// following the builder pattern.
/// Most build steps return a [`Result`] with [`RulesetError`].
///
/// You should probably not create more than one ruleset per application.
/// Creating multiple rulesets is only useful when gradually restricting an application
/// (e.g., a first set of generic restrictions before reading any file,
/// then a second set of tailored restrictions after reading the configuration).
///
/// # Simple example
///
/// Simple helper handling only Landlock-related errors.
///
/// ```
/// use landlock::{
///     Access, AccessFs, PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetError, ABI,
/// };
/// use std::os::unix::io::AsRawFd;
///
/// fn restrict_fd<T>(hierarchy: T) -> Result<RestrictionStatus, RulesetError>
/// where
///     T: AsRawFd,
/// {
///     // The Landlock ABI should be incremented (and tested) regularly.
///     let abi = ABI::V1;
///     let access_all = AccessFs::from_all(abi);
///     let access_read = AccessFs::from_read(abi);
///     Ok(Ruleset::new()
///         .handle_access(access_all)?
///         .create()?
///         .add_rule(PathBeneath::new(hierarchy, access_read))?
///         .restrict_self()?)
/// }
///
/// let fd = PathFd::new("/home").expect("failed to open /home");
/// let status = restrict_fd(fd).expect("failed to build the ruleset");
/// ```
///
/// # Generic example
///
/// More generic helper handling a set of file hierarchies
/// and multiple types of error (i.e. [`RulesetError`](crate::RulesetError)
/// and [`PathFdError`](crate::PathFdError).
///
/// ```
/// use landlock::{
///     Access, AccessFs, PathBeneath, PathFd, PathFdError, RestrictionStatus, Ruleset,
///     RulesetError, ABI,
/// };
/// use thiserror::Error;
///
/// #[derive(Debug, Error)]
/// enum MyRestrictError {
///     #[error(transparent)]
///     Ruleset(#[from] RulesetError),
///     #[error(transparent)]
///     AddRule(#[from] PathFdError),
/// }
///
/// fn restrict_paths(hierarchies: &[&str]) -> Result<RestrictionStatus, MyRestrictError> {
///     // The Landlock ABI should be incremented (and tested) regularly.
///     let abi = ABI::V1;
///     let access_all = AccessFs::from_all(abi);
///     let access_read = AccessFs::from_read(abi);
///     Ok(Ruleset::new()
///         .handle_access(access_all)?
///         .create()?
///         .add_rules(
///             hierarchies
///                 .iter()
///                 .map::<Result<_, MyRestrictError>, _>(|p| {
///                     Ok(PathBeneath::new(PathFd::new(p)?, access_read))
///                 }),
///         )?
///         .restrict_self()?)
/// }
///
/// let status = restrict_paths(&["/usr", "/home"]).expect("failed to build the ruleset");
/// ```
#[cfg_attr(test, derive(Debug))]
pub struct Ruleset {
    pub(crate) requested_handled_fs: BitFlags<AccessFs>,
    pub(crate) actual_handled_fs: BitFlags<AccessFs>,
    pub(crate) compat: Compatibility,
}

impl From<Compatibility> for Ruleset {
    fn from(compat: Compatibility) -> Self {
        Ruleset {
            // Non-working default handled FS accesses to force users to set them explicitely.
            requested_handled_fs: Default::default(),
            actual_handled_fs: Default::default(),
            compat,
        }
    }
}

#[cfg(test)]
impl From<ABI> for Ruleset {
    fn from(abi: ABI) -> Self {
        Ruleset::from(Compatibility::from(abi))
    }
}

#[test]
fn ruleset_add_rule_iter() {
    assert!(matches!(
        Ruleset::from(ABI::Unsupported)
            .handle_access(AccessFs::Execute)
            .unwrap()
            .create()
            .unwrap()
            .add_rule(PathBeneath::new(
                PathFd::new("/").unwrap(),
                AccessFs::ReadFile
            ))
            .unwrap_err(),
        RulesetError::AddRules(AddRulesError::Fs(AddRuleError::UnhandledAccess { .. }))
    ));
}

impl Ruleset {
    // Ruleset is an opaque struct.
    /// Returns a new `Ruleset`.
    /// This call automatically probes the running kernel to know if it supports Landlock.
    ///
    /// To be able to successfully call [`create()`](Ruleset::create),
    /// it is required to set the handled accesses with
    /// [`handle_access()`](Ruleset::handle_access).
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // The API should be future-proof: one Rust program or library should have the same
        // behavior if built with an old or a newer crate (e.g. with an extended ruleset_attr
        // enum).  It should then not be possible to give an "all-possible-handled-accesses" to the
        // Ruleset builder because this value would be relative to the running kernel.
        Compatibility::new().into()
    }

    /// Attempts to add a set of access rights that will be supported by this ruleset.
    /// By default, all actions requiring these access rights will be denied.
    /// Consecutive calls to `handle_access()` will be interpreted as logical ORs
    /// with the previous handled accesses.
    ///
    /// On error, returns a wrapped [`HandleAccessesError`].
    /// E.g., `RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError<AccessFs>))`
    pub fn handle_access<T, U>(self, access: T) -> Result<Self, RulesetError>
    where
        T: Into<BitFlags<U>>,
        U: Access,
    {
        Ok(U::ruleset_handle_access(self, access.into())?)
    }

    /// Attempts to create a real Landlock ruleset (if supported by the running kernel).
    /// The returned [`RulesetCreated`] is also a builder.
    ///
    /// On error, returns a wrapped [`CreateRulesetError`].
    pub fn create(self) -> Result<RulesetCreated, RulesetError> {
        let body = || -> Result<RulesetCreated, CreateRulesetError> {
            // Checks that the ruleset handles at least an access.
            if self.requested_handled_fs.is_empty() {
                // No handle_access() call.
                return Err(CreateRulesetError::MissingHandledAccess);
            }

            let attr = uapi::landlock_ruleset_attr {
                handled_access_fs: self.actual_handled_fs.bits(),
            };

            match self.compat.abi {
                ABI::Unsupported => {
                    #[cfg(test)]
                    assert_eq!(self.compat.state, CompatState::Final);
                    Ok(RulesetCreated::new(self, -1))
                }
                _ => match unsafe { uapi::landlock_create_ruleset(&attr, size_of_val(&attr), 0) } {
                    fd if fd >= 0 => Ok(RulesetCreated::new(self, fd)),
                    _ => Err(CreateRulesetError::CreateRulesetCall {
                        source: Error::last_os_error(),
                    }),
                },
            }
        };
        Ok(body()?)
    }
}

#[test]
fn ruleset_created_handle_access_or() {
    // Tests AccessFs::ruleset_handle_access()
    let ruleset = Ruleset::from(ABI::V1)
        .handle_access(AccessFs::Execute)
        .unwrap()
        .handle_access(AccessFs::ReadDir)
        .unwrap();
    let access = make_bitflags!(AccessFs::{Execute | ReadDir});
    assert_eq!(ruleset.requested_handled_fs, access);
    assert_eq!(ruleset.actual_handled_fs, access);

    // Tests that only the required handled accesses are reported as incompatible:
    // access should not contains AccessFs::Execute.
    assert!(matches!(Ruleset::from(ABI::Unsupported)
        .handle_access(AccessFs::Execute)
        .unwrap()
        .set_best_effort(false)
        .handle_access(AccessFs::ReadDir)
        .unwrap_err(),
        RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(
            CompatError::Access(AccessError::Incompatible { access })
        ))) if access == AccessFs::ReadDir
    ));
}

impl Compatible for Ruleset {
    fn set_best_effort(mut self, best_effort: bool) -> Self {
        self.compat.is_best_effort = best_effort;
        self
    }
}

/// Ruleset created with [`Ruleset::create()`].
#[cfg_attr(test, derive(Debug))]
pub struct RulesetCreated {
    fd: RawFd,
    no_new_privs: bool,
    pub(crate) requested_handled_fs: BitFlags<AccessFs>,
    compat: Compatibility,
}

impl RulesetCreated {
    fn new(ruleset: Ruleset, fd: RawFd) -> Self {
        RulesetCreated {
            fd,
            no_new_privs: true,
            requested_handled_fs: ruleset.requested_handled_fs,
            compat: ruleset.compat,
        }
    }

    /// Attempts to add a new rule to the ruleset.
    ///
    /// On error, returns a wrapped [`AddRulesError`].
    pub fn add_rule<T, U>(mut self, rule: T) -> Result<Self, RulesetError>
    where
        T: Rule<U>,
        U: Access,
    {
        let body = || -> Result<Self, AddRulesError> {
            rule.check_consistency(&self)?;
            let compat_rule = rule
                .try_compat(&mut self.compat)
                .map_err(AddRuleError::Compat)?;
            match self.compat.abi {
                ABI::Unsupported => {
                    #[cfg(test)]
                    assert_eq!(self.compat.state, CompatState::Final);
                    Ok(self)
                }
                _ => match unsafe {
                    uapi::landlock_add_rule(
                        self.fd,
                        compat_rule.get_type_id(),
                        compat_rule.as_ptr(),
                        compat_rule.get_flags(),
                    )
                } {
                    0 => Ok(self),
                    _ => Err(AddRuleError::<U>::AddRuleCall {
                        source: Error::last_os_error(),
                    }
                    .into()),
                },
            }
        };
        Ok(body()?)
    }

    /// Attempts to add a set of new rules to the ruleset.
    ///
    /// On error, returns a (double) wrapped [`AddRulesError`].
    ///
    /// # Example
    ///
    /// Create a custom iterator to read paths from environment variable.
    ///
    /// ```
    /// use landlock::{
    ///     Access, AccessFs, BitFlags, PathBeneath, PathFd, PathFdError, RestrictionStatus, Ruleset,
    ///     RulesetError, ABI,
    /// };
    /// use std::env;
    /// use std::ffi::OsStr;
    /// use std::os::unix::ffi::{OsStrExt, OsStringExt};
    /// use thiserror::Error;
    ///
    /// #[derive(Debug, Error)]
    /// enum PathEnvError<'a> {
    ///     #[error(transparent)]
    ///     Ruleset(#[from] RulesetError),
    ///     #[error(transparent)]
    ///     AddRuleIter(#[from] PathFdError),
    ///     #[error("missing environment variable {0}")]
    ///     MissingVar(&'a str),
    /// }
    ///
    /// struct PathEnv {
    ///     paths: Vec<u8>,
    ///     access: BitFlags<AccessFs>,
    /// }
    ///
    /// impl PathEnv {
    ///     // env_var is the name of an environment variable
    ///     // containing paths requested to be allowed.
    ///     // Paths are separated with ":", e.g. "/bin:/lib:/usr:/proc".
    ///     // In case an empty string is provided,
    ///     // no restrictions are applied.
    ///     // `access` is the set of access rights allowed for each of the parsed paths.
    ///     fn new<'a>(
    ///         env_var: &'a str, access: BitFlags<AccessFs>
    ///     ) -> Result<Self, PathEnvError<'a>> {
    ///         Ok(Self {
    ///             paths: env::var_os(env_var)
    ///                 .ok_or(PathEnvError::MissingVar(env_var))?
    ///                 .into_vec(),
    ///             access,
    ///         })
    ///     }
    ///
    ///     fn iter(
    ///         &self,
    ///     ) -> impl Iterator<Item = Result<PathBeneath<PathFd>, PathEnvError<'static>>> + '_ {
    ///         let is_empty = self.paths.is_empty();
    ///         self.paths
    ///             .split(|b| *b == b':')
    ///             // Skips the first empty element from of an empty string.
    ///             .skip_while(move |_| is_empty)
    ///             .map(OsStr::from_bytes)
    ///             .map(move |path|
    ///                 Ok(PathBeneath::new(PathFd::new(path)?, self.access)))
    ///     }
    /// }
    ///
    /// fn restrict_env() -> Result<RestrictionStatus, PathEnvError<'static>> {
    ///     Ok(Ruleset::new()
    ///         .handle_access(AccessFs::from_all(ABI::V1))?
    ///         .create()?
    ///         // In the shell: export EXECUTABLE_PATH="/usr:/bin:/sbin"
    ///         .add_rules(PathEnv::new("EXECUTABLE_PATH", AccessFs::Execute.into())?.iter())?
    ///         .restrict_self()?)
    /// }
    /// ```
    pub fn add_rules<I, T, U, E>(mut self, rules: I) -> Result<Self, E>
    where
        I: IntoIterator<Item = Result<T, E>>,
        T: Rule<U>,
        U: Access,
        E: std::error::Error,
        E: From<RulesetError>,
    {
        for rule in rules {
            self = self.add_rule(rule?)?;
        }
        Ok(self)
    }

    /// Configures the ruleset to call `prctl(2)` with the `PR_SET_NO_NEW_PRIVS` command
    /// in [`restrict_self()`](RulesetCreated::restrict_self).
    pub fn set_no_new_privs(mut self, no_new_privs: bool) -> Self {
        self.no_new_privs = no_new_privs;
        self
    }

    /// Attempts to restrict the calling thread with the ruleset
    /// according to the best-effort configuration
    /// (see [`RulesetCreated::set_best_effort()`]).
    /// Call `prctl(2)` with the `PR_SET_NO_NEW_PRIVS`
    /// according to the ruleset configuration.
    ///
    /// On error, returns a wrapped [`RestrictSelfError`].
    pub fn restrict_self(mut self) -> Result<RestrictionStatus, RulesetError> {
        let mut body = || -> Result<RestrictionStatus, RestrictSelfError> {
            let enforced_nnp = if self.no_new_privs {
                if let Err(e) = prctl_set_no_new_privs() {
                    if !self.compat.is_best_effort {
                        return Err(RestrictSelfError::SetNoNewPrivsCall { source: e });
                    }
                    // To get a consistent behavior, calls this prctl whether or not Landlock is
                    // supported by the running kernel.
                    let support_nnp = support_no_new_privs();
                    match self.compat.abi {
                        // It should not be an error for kernel (older than 3.5) not supporting
                        // no_new_privs.
                        ABI::Unsupported => {
                            if support_nnp {
                                // The kernel seems to be between 3.5 (included) and 5.13 (excluded),
                                // or Landlock is not enabled; no_new_privs should be supported anyway.
                                return Err(RestrictSelfError::SetNoNewPrivsCall { source: e });
                            }
                        }
                        // A kernel supporting Landlock should also support no_new_privs (unless
                        // filtered by seccomp).
                        _ => return Err(RestrictSelfError::SetNoNewPrivsCall { source: e }),
                    }
                    false
                } else {
                    true
                }
            } else {
                false
            };

            match self.compat.abi {
                ABI::Unsupported => {
                    #[cfg(test)]
                    assert_eq!(self.compat.state, CompatState::Final);
                    Ok(RestrictionStatus {
                        ruleset: self.compat.state.into(),
                        no_new_privs: enforced_nnp,
                    })
                }
                _ => match unsafe { uapi::landlock_restrict_self(self.fd, 0) } {
                    0 => {
                        self.compat.state.update(CompatState::Full);
                        Ok(RestrictionStatus {
                            ruleset: self.compat.state.into(),
                            no_new_privs: enforced_nnp,
                        })
                    }
                    // TODO: match specific Landlock restrict self errors
                    _ => Err(RestrictSelfError::RestrictSelfCall {
                        source: Error::last_os_error(),
                    }),
                },
            }
        };
        Ok(body()?)
    }
}

impl Drop for RulesetCreated {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { close(self.fd) };
        }
    }
}

impl Compatible for RulesetCreated {
    fn set_best_effort(mut self, best_effort: bool) -> Self {
        self.compat.is_best_effort = best_effort;
        self
    }
}

#[test]
fn ruleset_unsupported() {
    assert_eq!(
        Ruleset::from(ABI::Unsupported)
            .handle_access(AccessFs::Execute)
            .unwrap()
            .create()
            .unwrap()
            .restrict_self()
            .unwrap(),
        RestrictionStatus {
            ruleset: RulesetStatus::NotEnforced,
            no_new_privs: true,
        }
    );

    assert_eq!(
        Ruleset::from(ABI::Unsupported)
            .handle_access(AccessFs::Execute)
            .unwrap()
            .create()
            .unwrap()
            .set_no_new_privs(false)
            .restrict_self()
            .unwrap(),
        RestrictionStatus {
            ruleset: RulesetStatus::NotEnforced,
            no_new_privs: false,
        }
    );

    assert!(matches!(
        Ruleset::from(ABI::Unsupported)
            // Empty access-rights
            .handle_access(AccessFs::from_all(ABI::Unsupported))
            .unwrap_err(),
        RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(
            CompatError::Access(AccessError::Empty)
        )))
    ));

    assert!(matches!(
        Ruleset::from(ABI::Unsupported)
            // No handle_access() call.
            .create()
            .unwrap_err(),
        RulesetError::CreateRuleset(CreateRulesetError::MissingHandledAccess)
    ));

    assert!(matches!(
        Ruleset::from(ABI::V1)
            // Empty access-rights
            .handle_access(AccessFs::from_all(ABI::Unsupported))
            .unwrap_err(),
        RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(
            CompatError::Access(AccessError::Empty)
        )))
    ));

    // Tests inconsistency between the ruleset handled access-rights and the rule access-rights.
    for handled_access in &[
        make_bitflags!(AccessFs::{Execute | WriteFile}),
        AccessFs::Execute.into(),
    ] {
        let ruleset = Ruleset::from(ABI::V1)
            .handle_access(*handled_access)
            .unwrap();
        // Fakes a call to create() to test without involving the kernel (i.e. no
        // landlock_ruleset_create() call).
        let ruleset_created = RulesetCreated::new(ruleset, -1);
        assert!(matches!(
            ruleset_created
                .add_rule(PathBeneath::new(
                    PathFd::new("/").unwrap(),
                    AccessFs::ReadFile
                ))
                .unwrap_err(),
            RulesetError::AddRules(AddRulesError::Fs(AddRuleError::UnhandledAccess { .. }))
        ));
    }
}
