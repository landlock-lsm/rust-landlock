use super::uapi;
use super::{AccessFs, BitFlags, Compat, CompatStatus, Compatibility, TryCompat, ABI};
use libc::close;
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;

pub trait Rule {
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
    /// The running system doesn't support Landlock.
    Unrestricted,
}

fn prctl_set_no_new_privs() -> Result<(), Error> {
    match unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub struct RulesetInit {
    handled_fs: BitFlags<AccessFs>,
}

impl RulesetInit {
    pub fn new(compat: &Compatibility) -> Result<Compat<Self>, Error> {
        // The API should be future-proof: one Rust program or library should have the same
        // behavior if built with an old or a newer crate (e.g. with an extended ruleset_attr
        // enum).  It should then not be possible to give an "all-possible-handled-accesses" to the
        // Ruleset builder because this value would be relative to the running kernel.
        compat.create(1, || RulesetInit {
            handled_fs: ABI::V1.into(),
        })
    }
}

impl Compat<RulesetInit> {
    pub fn handle_fs<T>(self, access: T) -> Result<Self, Error>
    where
        T: Into<BitFlags<AccessFs>>,
    {
        let compat_access = access.into().try_compat(&self.0.compat)?;
        self.update(1, |mut data| {
            data.handled_fs = compat_access;
            Ok(data)
        })
    }

    pub fn create(self) -> Result<Compat<RulesetCreated>, Error> {
        self.update(1, |data| {
            let attr = uapi::landlock_ruleset_attr {
                handled_access_fs: data.handled_fs.bits(),
            };
            match unsafe { uapi::landlock_create_ruleset(&attr, size_of_val(&attr), 0) } {
                fd if fd >= 0 => Ok(RulesetCreated {
                    fd: fd,
                    no_new_privs: true,
                }),
                _ => Err(Error::last_os_error()),
            }
        })
    }
}

pub struct RulesetCreated {
    fd: RawFd,
    no_new_privs: bool,
}

impl Compat<RulesetCreated> {
    pub fn add_rule<T>(self, rule: Compat<T>) -> Result<Self, Error>
    where
        T: Rule,
    {
        self.merge(1, rule.into(), |self_data, rule_data| {
            match unsafe {
                uapi::landlock_add_rule(
                    self_data.fd,
                    rule_data.get_type_id(),
                    rule_data.as_ptr(),
                    rule_data.get_flags(),
                )
            } {
                0 => Ok(self_data),
                _ => Err(Error::last_os_error()),
            }
        })
    }

    pub fn set_no_new_privs(self, no_new_privs: bool) -> Result<Self, Error> {
        self.update(1, |mut data| {
            data.no_new_privs = no_new_privs;
            Ok(data)
        })
    }

    pub fn restrict_self(self) -> Result<RestrictionStatus, Error> {
        match self.0.build {
            None => Ok(RestrictionStatus::Unrestricted),
            Some(ref build) => {
                if build.data.no_new_privs {
                    // If Landlock is supported, then no_new_privs should also be supported (unless
                    // blocked e.g., by seccomp-bpf).  Otherwise, we should inform users by
                    // returning the syscall error.
                    prctl_set_no_new_privs()?;
                }
                match unsafe { uapi::landlock_restrict_self(build.data.fd, 0) } {
                    0 => match build.status {
                        CompatStatus::Full => Ok(RestrictionStatus::FullyRestricted),
                        CompatStatus::Partial => Ok(RestrictionStatus::PartiallyRestricted),
                    },
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
