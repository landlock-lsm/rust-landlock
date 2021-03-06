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
    fn from_all(abi: ABI) -> BitFlags<Self>;
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

#[derive(Debug, PartialEq, Eq)]
pub enum RulesetStatus {
    /// All requested restrictions are enforced.
    FullyEnforced,
    /// Some requested restrictions are enforced, following a best-effort approach.
    PartiallyEnforced,
    /// The running system doesn't support Landlock or a subset of the requested Landlock features.
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
/// Returned by ruleset builder.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RestrictionStatus {
    /// Status of the Landlock ruleset enforcement.
    pub ruleset: RulesetStatus,
    /// Status of prctl(2)'s PR_SET_NO_NEW_PRIVS enforcement.
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

#[cfg_attr(test, derive(Debug))]
pub struct Ruleset {
    pub(crate) requested_handled_fs: BitFlags<AccessFs>,
    pub(crate) actual_handled_fs: BitFlags<AccessFs>,
    pub(crate) compat: Compatibility,
}

impl From<Compatibility> for Ruleset {
    fn from(compat: Compatibility) -> Self {
        let handled_fs = AccessFs::from_all(ABI::V1);
        Ruleset {
            requested_handled_fs: handled_fs,
            actual_handled_fs: handled_fs,
            compat,
        }
    }
}

#[test]
fn ruleset_add_rule_iter() {
    let compat = ABI::Unsupported.into();
    let new_ruleset = |compat: &Compatibility| -> Ruleset { compat.clone().into() };

    assert!(matches!(
        new_ruleset(&compat)
            .handle_access(AccessFs::Execute)
            .unwrap()
            .create()
            .unwrap()
            .add_rule(PathBeneath::new(PathFd::new("/").unwrap()).allow_access(AccessFs::ReadFile))
            .unwrap_err(),
        RulesetError::AddRules(AddRulesError::Fs(AddRuleError::UnhandledAccess { .. }))
    ));
}

impl Ruleset {
    // Ruleset is an opaque struct.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // The API should be future-proof: one Rust program or library should have the same
        // behavior if built with an old or a newer crate (e.g. with an extended ruleset_attr
        // enum).  It should then not be possible to give an "all-possible-handled-accesses" to the
        // Ruleset builder because this value would be relative to the running kernel.
        Compatibility::new().into()
    }

    /// On error, returns a wrapped `HandleAccessesError`
    /// E.g., `RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError<AccessFs>))`
    pub fn handle_access<T, U>(self, access: T) -> Result<Self, RulesetError>
    where
        T: Into<BitFlags<U>>,
        U: Access,
    {
        Ok(U::ruleset_handle_access(self, access.into())?)
    }

    /// On error, returns a wrapped `CreateRulesetError`
    pub fn create(self) -> Result<RulesetCreated, RulesetError> {
        let body = || -> Result<RulesetCreated, CreateRulesetError> {
            let attr = uapi::landlock_ruleset_attr {
                handled_access_fs: self.actual_handled_fs.bits(),
            };

            match self.compat.abi {
                ABI::Unsupported => {
                    #[cfg(test)]
                    assert_eq!(self.compat.state, CompatState::Final);
                    Ok(RulesetCreated::new(self, -1))
                }
                ABI::V1 => {
                    match unsafe { uapi::landlock_create_ruleset(&attr, size_of_val(&attr), 0) } {
                        fd if fd >= 0 => Ok(RulesetCreated::new(self, fd)),
                        _ => Err(CreateRulesetError::CreateRulesetCall {
                            source: Error::last_os_error(),
                        }),
                    }
                }
            }
        };
        Ok(body()?)
    }
}

impl Compatible for Ruleset {
    fn set_best_effort(mut self, best_effort: bool) -> Self {
        self.compat.is_best_effort = best_effort;
        self
    }
}

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

    /// On error, returns a wrapped `AddRulesError`
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
                ABI::V1 => match unsafe {
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

    /// On error, returns a (double) wrapped `AddRulesError`
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

    pub fn set_no_new_privs(mut self, no_new_privs: bool) -> Self {
        self.no_new_privs = no_new_privs;
        self
    }

    /// On error, returns a wrapped `RestrictSelfError`
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
                ABI::V1 => match unsafe { uapi::landlock_restrict_self(self.fd, 0) } {
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
    use crate::errors::*;

    let mut compat = ABI::Unsupported.into();
    let new_ruleset = |compat: &Compatibility| -> Ruleset { compat.clone().into() };

    assert_eq!(
        new_ruleset(&compat)
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
        new_ruleset(&compat)
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
        new_ruleset(&compat)
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
        new_ruleset(&compat)
            // Empty access-rights
            .handle_access(AccessFs::from_all(ABI::Unsupported))
            .unwrap_err(),
        RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(
            CompatError::Access(AccessError::Empty)
        )))
    ));

    compat = ABI::V1.into();

    // Restricting without rule exceptions is legitimate to forbid a set of actions.
    assert_eq!(
        new_ruleset(&compat)
            .create()
            .unwrap()
            .restrict_self()
            .unwrap(),
        RestrictionStatus {
            ruleset: RulesetStatus::FullyEnforced,
            no_new_privs: true,
        }
    );

    assert_eq!(
        new_ruleset(&compat)
            .handle_access(AccessFs::Execute)
            .unwrap()
            .create()
            .unwrap()
            .restrict_self()
            .unwrap(),
        RestrictionStatus {
            ruleset: RulesetStatus::FullyEnforced,
            no_new_privs: true,
        }
    );

    assert!(matches!(
        new_ruleset(&compat)
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
        assert!(matches!(
            new_ruleset(&compat)
                .handle_access(*handled_access)
                .unwrap()
                .create()
                .unwrap()
                .add_rule(
                    PathBeneath::new(PathFd::new("/").unwrap()).allow_access(AccessFs::ReadFile)
                )
                .unwrap_err(),
            RulesetError::AddRules(AddRulesError::Fs(AddRuleError::UnhandledAccess { .. }))
        ));
    }
}
