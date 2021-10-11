use crate::{uapi, AccessFs, BitFlags, CompatState, Compatibility, TryCompat, ABI};
use libc::close;
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;

#[cfg(test)]
use crate::SupportLevel;

// Public interface without methods and which is impossible to implement outside this crate.
pub trait Rule: PrivateRule {}

pub trait PrivateRule: TryCompat {
    fn as_ptr(&self) -> *const libc::c_void;
    fn get_type_id(&self) -> uapi::landlock_rule_type;
    fn get_flags(&self) -> u32;
}

/// Returned by ruleset builder.
#[derive(Debug, PartialEq)]
pub enum RestrictionStatus {
    /// All requested restrictions are enforced.
    FullyRestricted,
    /// Some requested restrictions are enforced, following a best-effort approach.
    PartiallyRestricted,
    /// The running system doesn't support Landlock or a subset of the requested features..
    Unrestricted,
}

impl From<CompatState> for RestrictionStatus {
    fn from(state: CompatState) -> Self {
        match state {
            CompatState::Start | CompatState::No | CompatState::Final => {
                RestrictionStatus::Unrestricted
            }
            CompatState::Full => RestrictionStatus::FullyRestricted,
            CompatState::Partial => RestrictionStatus::PartiallyRestricted,
        }
    }
}

fn prctl_set_no_new_privs() -> Result<(), Error> {
    match unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

#[derive(Debug)]
pub struct RulesetInit {
    handled_fs: BitFlags<AccessFs>,
    compat: Compatibility,
}

impl RulesetInit {
    pub fn new(compat: Compatibility) -> Self {
        // The API should be future-proof: one Rust program or library should have the same
        // behavior if built with an old or a newer crate (e.g. with an extended ruleset_attr
        // enum).  It should then not be possible to give an "all-possible-handled-accesses" to the
        // Ruleset builder because this value would be relative to the running kernel.
        RulesetInit {
            handled_fs: ABI::V1.into(),
            compat: compat,
        }
    }

    pub fn handle_fs<T>(mut self, access: T) -> Result<Self, Error>
    where
        T: Into<BitFlags<AccessFs>>,
    {
        self.handled_fs = access.into().try_compat(&mut self.compat)?;
        Ok(self)
    }

    pub fn create(self) -> Result<RulesetCreated, Error> {
        let attr = uapi::landlock_ruleset_attr {
            handled_access_fs: self.handled_fs.bits(),
        };
        match self.compat.abi {
            ABI::Unsupported => Ok(RulesetCreated {
                fd: -1,
                no_new_privs: false,
                compat: self.compat,
            }),
            ABI::V1 => match unsafe { uapi::landlock_create_ruleset(&attr, size_of_val(&attr), 0) }
            {
                fd if fd >= 0 => Ok(RulesetCreated {
                    fd: fd,
                    no_new_privs: true,
                    compat: self.compat,
                }),
                _ => Err(Error::last_os_error()),
            },
        }
    }
}

#[derive(Debug)]
pub struct RulesetCreated {
    fd: RawFd,
    no_new_privs: bool,
    compat: Compatibility,
}

impl RulesetCreated {
    pub fn add_rule<T>(mut self, rule: T) -> Result<Self, Error>
    where
        T: Rule,
    {
        // TODO: check subset of PathBeneath.allow_access with RulesetInit.handle_fs
        let compat_rule = rule.try_compat(&mut self.compat)?;
        match self.compat.abi {
            ABI::Unsupported => Ok(self),
            ABI::V1 => match unsafe {
                uapi::landlock_add_rule(
                    self.fd,
                    compat_rule.get_type_id(),
                    compat_rule.as_ptr(),
                    compat_rule.get_flags(),
                )
            } {
                0 => Ok(self),
                _ => Err(Error::last_os_error()),
            },
        }
    }

    pub fn set_no_new_privs(mut self, no_new_privs: bool) -> Self {
        self.no_new_privs = no_new_privs;
        self
    }

    pub fn restrict_self(mut self) -> Result<RestrictionStatus, Error> {
        match self.compat.abi {
            ABI::Unsupported => Ok(self.compat.state.into()),
            ABI::V1 => {
                if self.no_new_privs {
                    // If Landlock is supported, then no_new_privs should also be supported (unless
                    // blocked e.g., by seccomp-bpf).  Otherwise, we should inform users by
                    // returning the syscall error.
                    prctl_set_no_new_privs()?;
                }
                match unsafe { uapi::landlock_restrict_self(self.fd, 0) } {
                    0 => {
                        self.compat.state.update(CompatState::Full);
                        Ok(self.compat.state.into())
                    }
                    _ => Err(Error::last_os_error()),
                }
            }
        }
    }
}

impl Drop for RulesetCreated {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}

#[test]
fn ruleset_unsupported() {
    use std::io::ErrorKind;

    let mut compat = Compatibility {
        abi: ABI::Unsupported,
        level: SupportLevel::Optional,
        state: CompatState::Start,
    };
    assert_eq!(
        RulesetInit::new(compat)
            .create()
            .unwrap()
            .restrict_self()
            .unwrap(),
        RestrictionStatus::Unrestricted
    );
    assert_eq!(
        RulesetInit::new(compat)
            .handle_fs(AccessFs::Execute)
            .unwrap()
            .create()
            .unwrap()
            .restrict_self()
            .unwrap(),
        RestrictionStatus::Unrestricted
    );

    assert_eq!(
        RulesetInit::new(compat)
            // Empty access-rights
            .handle_fs(ABI::Unsupported)
            .unwrap_err()
            .kind(),
        ErrorKind::Other
    );

    compat.abi = ABI::V1;
    assert_eq!(
        RulesetInit::new(compat)
            .handle_fs(AccessFs::Execute)
            .unwrap()
            .create()
            .unwrap()
            .restrict_self()
            .unwrap(),
        RestrictionStatus::FullyRestricted
    );
    assert_eq!(
        RulesetInit::new(compat)
            // Empty access-rights
            .handle_fs(ABI::Unsupported)
            .unwrap_err()
            .kind(),
        ErrorKind::Other
    );
}
