#[macro_use]
extern crate bitflags;

use libc::close;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem::size_of_val;
use std::os::unix::io::{AsRawFd, RawFd};

mod uapi;

bitflags! {
    pub struct AccessFs: u64 {
        const EXECUTE = uapi::LANDLOCK_ACCESS_FS_EXECUTE as u64;
        const WRITE_FILE = uapi::LANDLOCK_ACCESS_FS_WRITE_FILE as u64;
        const READ_FILE = uapi::LANDLOCK_ACCESS_FS_READ_FILE as u64;
        const READ_DIR = uapi::LANDLOCK_ACCESS_FS_READ_DIR as u64;
        const REMOVE_DIR = uapi::LANDLOCK_ACCESS_FS_REMOVE_DIR as u64;
        const REMOVE_FILE = uapi::LANDLOCK_ACCESS_FS_REMOVE_FILE as u64;
        const MAKE_CHAR = uapi::LANDLOCK_ACCESS_FS_MAKE_CHAR as u64;
        const MAKE_DIR = uapi::LANDLOCK_ACCESS_FS_MAKE_DIR as u64;
        const MAKE_REG = uapi::LANDLOCK_ACCESS_FS_MAKE_REG as u64;
        const MAKE_SOCK = uapi::LANDLOCK_ACCESS_FS_MAKE_SOCK as u64;
        const MAKE_FIFO = uapi::LANDLOCK_ACCESS_FS_MAKE_FIFO as u64;
        const MAKE_BLOCK = uapi::LANDLOCK_ACCESS_FS_MAKE_BLOCK as u64;
        const MAKE_SYM = uapi::LANDLOCK_ACCESS_FS_MAKE_SYM as u64;
    }
}

pub trait Rule {
    fn as_ptr(&self) -> *const libc::c_void;
    fn get_type_id(&self) -> uapi::landlock_rule_type;
    fn get_flags(&self) -> u32;
}

/// Properly handles runtime unsupported features.  This enables to guarantee consistent behaviors
/// across crate users and runtime kernels even if this crate get new features.  It eases backward
/// compatibility and future-proofness.
///
/// Landlock is a security feature designed to help improve security of a running system thanks to
/// application developers.  To protect users as much as possible, compatibility with the running
/// system should then be handled in a best-effort way, contrary to common system features.  In
/// some circumstances (e.g. applications carefully designed to only be run with a specific kernel
/// version), it may be required to check if a some of there features are enforced, which is
/// possible with the Compat::into_result() helper.
pub struct Compat<T>(CompatKind<T>);

enum CompatKind<T> {
    // Contains the requested data.
    Full(T),
    // Contains the compliant version of the requested data, used by Compat::into_option().
    // TODO: Actually use Partial.
    #[allow(dead_code)]
    Partial(T),
    // No possible compatibility: will do nothing.
    No,
    // No compatibility because of a runtime error.
    Error(Error),
}

impl<T> From<CompatKind<T>> for Compat<T> {
    fn from(kind: CompatKind<T>) -> Self {
        Compat(kind)
    }
}

impl<T> Compat<T> {
    // By default, a Landlock user should implement a best-effort security.
    //
    // The From/Into traits are much more verbose to use because they require dedicated variables
    // with explicit type to infer the right implementation.
    fn into_option(self) -> Option<T> {
        match self.0 {
            CompatKind::Full(r) => Some(r),
            CompatKind::Partial(r) => Some(r),
            CompatKind::No => None,
            CompatKind::Error(_) => None,
        }
    }

    /// It is still possible to manually handle (chained) runtime incompatibilities (e.g. with `?`).
    ///
    /// If you are unsure when to use this function, ignore it.
    pub fn into_result(self) -> Result<Self, Error> {
        match self.0 {
            CompatKind::Full(r) => Ok(CompatKind::Full(r).into()),
            CompatKind::Partial(_) => {
                Err(Error::new(ErrorKind::InvalidData, "Partial compatibility"))
            }
            CompatKind::No => Err(Error::new(ErrorKind::InvalidData, "Incompatibility")),
            CompatKind::Error(e) => Err(e),
        }
    }
}

pub struct PathBeneath<'a> {
    attr: uapi::landlock_path_beneath_attr,
    // Ties the lifetime of a PathBeneath instance to the litetime of its wrapped attr.parent_fd .
    _parent_fd: PhantomData<&'a u32>,
}

impl PathBeneath<'_> {
    pub fn new<'a, T>(parent: &'a T) -> Compat<Self>
    where
        T: AsRawFd,
    {
        CompatKind::Full(PathBeneath {
            attr: {
                uapi::landlock_path_beneath_attr {
                    // FIXME: Replace all() with group1()
                    allowed_access: AccessFs::all().bits,
                    parent_fd: parent.as_raw_fd(),
                }
            },
            _parent_fd: PhantomData,
        })
        .into()
    }
}

impl Compat<PathBeneath<'_>> {
    pub fn allow_access(self, allowed: AccessFs) -> Self {
        match self.into_option() {
            None => CompatKind::No,
            Some(mut pb) => {
                pb.attr.allowed_access = allowed.bits;
                // TODO: Checks supported bitflags and create a compliant version if required.
                CompatKind::Full(pb)
            }
        }
        .into()
    }
}

impl Rule for PathBeneath<'_> {
    fn as_ptr(&self) -> *const libc::c_void {
        &self.attr as *const _ as _
    }

    fn get_type_id(&self) -> uapi::landlock_rule_type {
        uapi::landlock_rule_type_LANDLOCK_RULE_PATH_BENEATH
    }

    fn get_flags(&self) -> u32 {
        0
    }
}

fn prctl_set_no_new_privs() -> Result<(), Error> {
    match unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } {
        0 => Ok(()),
        _ => Err(Error::last_os_error()),
    }
}

pub struct RulesetAttr {
    handled_fs: AccessFs,
}

impl RulesetAttr {
    pub fn new() -> Compat<Self> {
        // The API should be future-proof: one Rust program or library should have the same
        // behavior if built with an old or a newer crate (e.g. with an extended ruleset_attr
        // enum).  It should then not be possible to give an "all-possible-handled-accesses" to the
        // Ruleset builder because this value would be relative to the running kernel.
        CompatKind::Full(RulesetAttr {
            // FIXME: Replace all() with group1()
            handled_fs: AccessFs::all(),
        })
        .into()
    }
}

impl Compat<RulesetAttr> {
    pub fn handle_fs(self, access: AccessFs) -> Self {
        match self.into_option() {
            None => CompatKind::No,
            Some(mut ra) => {
                ra.handled_fs = access;
                CompatKind::Full(ra)
            }
        }
        .into()
    }

    pub fn create(self) -> Compat<Ruleset> {
        match self.into_option() {
            None => CompatKind::No,
            Some(ra) => Ruleset::new(ra),
        }
        .into()
    }
}

pub struct Ruleset {
    fd: RawFd,
    no_new_privs: bool,
}

impl Ruleset {
    fn new(attribute: RulesetAttr) -> CompatKind<Self> {
        let attr = uapi::landlock_ruleset_attr {
            handled_access_fs: attribute.handled_fs.bits,
        };

        match unsafe { uapi::landlock_create_ruleset(&attr, size_of_val(&attr), 0) } {
            fd if fd >= 0 => CompatKind::Full(Ruleset {
                fd: fd,
                no_new_privs: true,
            }),
            _ => CompatKind::Error(Error::last_os_error()),
        }
    }
}

impl Compat<Ruleset> {
    pub fn add_rule<T>(self, rule: Compat<T>) -> Self
    where
        T: Rule,
    {
        match self.into_option() {
            None => CompatKind::No,
            Some(ruleset) => match rule.into_option() {
                None => CompatKind::Full(ruleset),
                Some(r) => {
                    match unsafe {
                        uapi::landlock_add_rule(
                            ruleset.fd,
                            r.get_type_id(),
                            r.as_ptr(),
                            r.get_flags(),
                        )
                    } {
                        0 => CompatKind::Full(ruleset),
                        _ => CompatKind::Error(Error::last_os_error()),
                    }
                }
            },
        }
        .into()
    }

    pub fn set_no_new_privs(self, no_new_privs: bool) -> Self {
        match self.into_option() {
            None => CompatKind::No,
            Some(mut r) => {
                r.no_new_privs = no_new_privs;
                CompatKind::Full(r)
            }
        }
        .into()
    }

    pub fn restrict_self(self) -> Result<(), Error> {
        match self.into_option() {
            None => Ok(()),
            Some(r) => {
                if r.no_new_privs {
                    prctl_set_no_new_privs()?;
                }
                match unsafe { uapi::landlock_restrict_self(r.fd, 0) } {
                    0 => Ok(()),
                    _ => Err(Error::last_os_error()),
                }
            }
        }
    }
}

impl Drop for Ruleset {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    fn ruleset_root_compat() -> Result<(), Error> {
        RulesetAttr::new()
            // FIXME: Make it impossible to use AccessFs::all() but group1() instead
            .handle_fs(AccessFs::all())
            .create()
            .set_no_new_privs(true)
            .add_rule(PathBeneath::new(&File::open("/")?).allow_access(AccessFs::all()))
            .restrict_self()
    }

    fn ruleset_root_fragile() -> Result<(), Error> {
        RulesetAttr::new()
            .into_result()?
            // FIXME: Make it impossible to use AccessFs::all() but group1() instead
            .handle_fs(AccessFs::all())
            .into_result()?
            .create()
            .into_result()?
            .set_no_new_privs(true)
            .into_result()?
            .add_rule(
                PathBeneath::new(&File::open("/")?)
                    .into_result()?
                    .allow_access(AccessFs::all())
                    .into_result()?,
            )
            .into_result()?
            .restrict_self()
    }

    #[test]
    fn allow_root_compat() {
        ruleset_root_compat().unwrap()
    }

    #[test]
    fn allow_root_fragile() {
        ruleset_root_fragile().unwrap()
    }
}
