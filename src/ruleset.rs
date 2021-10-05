use super::uapi;
use super::{AccessFs, Compat, CompatStatus, Compatibility};
use libc::close;
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;

pub trait Rule {
    fn as_ptr(&self) -> *const libc::c_void;
    fn get_type_id(&self) -> uapi::landlock_rule_type;
    fn get_flags(&self) -> u32;
}

/// If you only want a full restriction enforced, then you need to adjust the error threshold with
/// `.set_error_threshold()` before calling `.restrict_self()`.
pub enum RestrictionStatus {
    /// All requested restrictions are enforced.
    // TODO: FullyRestricted(RestrictSet),
    FullyRestricted,
    /// Some requested restrictions are enforced, and some unexpected error may have append (e.g.
    /// wrong PathBeneath FD: EBADFD, but no EINVAL).
    // TODO: PartiallyRestricted((RestrictSet), (with last saved error)
    PartiallyRestricted(Option<Error>),
    /// Contains an error if restrict_self() failed, or None if the build chain is incompatible
    /// with the running system.
    Unrestricted(Option<Error>),
}

impl RestrictionStatus {
    // It is not an error to run on a system not supporting Landlock.
    pub fn into_result(self) -> Result<(), Error> {
        match self {
            RestrictionStatus::FullyRestricted => Ok(()),
            RestrictionStatus::PartiallyRestricted(err) => err.map_or(Ok(()), |x| Err(x)),
            RestrictionStatus::Unrestricted(err) => err.map_or(Ok(()), |x| Err(x)),
        }
    }
}

fn prctl_set_no_new_privs() -> Result<(), Error> {
    match unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub struct RulesetInit {
    handled_fs: AccessFs,
}

impl RulesetInit {
    pub fn new(compat: &Compatibility) -> Result<Compat<Self>, Error> {
        // The API should be future-proof: one Rust program or library should have the same
        // behavior if built with an old or a newer crate (e.g. with an extended ruleset_attr
        // enum).  It should then not be possible to give an "all-possible-handled-accesses" to the
        // Ruleset builder because this value would be relative to the running kernel.
        compat.create(1, || {
            RulesetInit {
                // FIXME: Replace all() with group1()
                handled_fs: AccessFs::all(),
            }
        })
    }
}

impl Compat<RulesetInit> {
    pub fn handle_fs(self, access: AccessFs) -> Result<Self, Error> {
        self.update(1, |mut data| {
            data.handled_fs = access;
            // TODO: Check compatibility and update it accordingly.
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

    pub fn restrict_self(self) -> RestrictionStatus {
        match self.0.build {
            None => RestrictionStatus::Unrestricted(self.get_last_error()),
            Some(ref build) => {
                if build.data.no_new_privs {
                    if let Err(e) = prctl_set_no_new_privs() {
                        return RestrictionStatus::Unrestricted(Some(e));
                    }
                }
                match unsafe { uapi::landlock_restrict_self(build.data.fd, 0) } {
                    0 => match build.status {
                        CompatStatus::Full => RestrictionStatus::FullyRestricted,
                        CompatStatus::Partial => {
                            RestrictionStatus::PartiallyRestricted(self.get_last_error())
                        }
                    },
                    _ => RestrictionStatus::Unrestricted(Some(Error::last_os_error())),
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
