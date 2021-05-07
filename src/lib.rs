#[macro_use]
extern crate bitflags;

use libc::close;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem::{replace, size_of_val};
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
/// compatibility and enables future-proofness.
///
/// Landlock is a security feature designed to help improve security of a running system thanks to
/// application developers.  To protect users as much as possible, compatibility with the running
/// system should then be handled in a best-effort way, contrary to common system features.  In
/// some circumstances (e.g. applications carefully designed to only be run with a specific kernel
/// version), it may be required to check if some of there features are enforced, which is possible
/// with the `Compat<T>::into_result()` helper.
pub struct Compat<T>(CompatObject<T>);

struct CompatObject<T> {
    /// Saves the last call status for `Compat<T>::into_result()`.
    last: LastCall,
    /// Saves the last encountered error for `RestrictionStatus`.
    // TODO: save the first error instead?
    prev_error: Option<Error>,
    compat: Compatibility,
    /// It is `None` if the build chain is incompatible with the running system.
    build: Option<CompatBuild<T>>,
}

/// Last attempted call, which may not be the last from the build chain.
enum LastCall {
    /// Did handle the build method and all arguments.
    FullSuccess,
    /// Did handle the build method but not all arguments (which had been made compatible for the
    /// call, e.g. removing some handled accesses).
    PartialSuccess,
    /// Didn't handle the build method or don't handle any argument.
    Unsupported,
    /// The build is None.
    Fake,
    /// Did handle the build method and a subset of arguments, but the call returned an error (e.g.
    /// invalid FD or not enough permissions).
    // This API should guarantee that no EINVAL is returned.
    RuntimeError(Error),
}

struct CompatBuild<T> {
    status: CompatStatus,
    data: T,
}

#[derive(Copy, Clone)]
enum CompatStatus {
    Full,
    Partial,
}

#[derive(Copy, Clone)]
pub enum ErrorThreshold {
    /// Handles the return value in a compatible way: method calls will always return `Ok(Self)`.
    /// This is the encouraged way to use this API.  The last runtime error in the build chain can
    /// be catched thanks to the return RestrictionStatus.
    NoError,
    /// Only considers a runtime error as an error.
    // Maps to LastCall::RuntimeError.
    Runtime,
    /// Considers a runtime error or a full incompatibility as an error.
    // Maps to LastCall::Unsupported.
    Incompatible,
    /// Considers a runtime error or a partial compatibility as an error.
    // Maps to LastCall::PartialSuccess.
    PartiallyCompatible,
}

impl From<CompatStatus> for LastCall {
    fn from(status: CompatStatus) -> Self {
        match status {
            CompatStatus::Full => LastCall::FullSuccess,
            CompatStatus::Partial => LastCall::PartialSuccess,
        }
    }
}

impl<T> Compat<T> {
    fn set_last_call_status(mut self, status: LastCall) -> Result<Self, Error> {
        // Only downgrades build compatibility.
        match status {
            LastCall::FullSuccess => {}
            _ => {
                if let Some(ref mut build) = self.0.build {
                    build.status = CompatStatus::Partial;
                }
            }
        }
        // Saves the previous error, if any.
        if let LastCall::RuntimeError(e) = replace(&mut self.0.last, status) {
            self.0.prev_error = Some(e);
        }
        self.into_result()
    }

    fn get_last_error(self) -> Option<Error> {
        match self.0.last {
            LastCall::RuntimeError(e) => Some(e),
            _ => self.0.prev_error,
        }
    }

    fn update<U, F>(self, minimum_version: i32, new_data: F) -> Result<Compat<U>, Error>
    where
        F: FnOnce(T) -> Result<U, Error>,
    {
        let (status, build) = match self.0.build {
            None => (LastCall::Fake, None),
            Some(build) => {
                if self.0.compat.is_compatible(minimum_version) {
                    match new_data(build.data) {
                        Ok(data) => (
                            LastCall::FullSuccess,
                            Some(CompatBuild {
                                status: build.status,
                                data: data,
                            }),
                        ),
                        Err(e) => (LastCall::RuntimeError(e), None),
                    }
                } else {
                    (LastCall::Unsupported, None)
                }
            }
        };
        Compat(CompatObject {
            last: self.0.last,
            prev_error: self.0.prev_error,
            // TODO: Merge thresholds?
            compat: self.0.compat,
            build: build,
        })
        .set_last_call_status(status)
    }

    fn into_result(self) -> Result<Self, Error> {
        match self.0.last {
            LastCall::FullSuccess => Ok(self),
            LastCall::PartialSuccess => match self.0.compat.threshold {
                ErrorThreshold::PartiallyCompatible => {
                    Err(Error::new(ErrorKind::InvalidData, "Partial compatibility"))
                }
                _ => Ok(self),
            },
            LastCall::Unsupported | LastCall::Fake => match self.0.compat.threshold {
                ErrorThreshold::PartiallyCompatible | ErrorThreshold::Incompatible => {
                    Err(Error::new(ErrorKind::InvalidData, "Incompatibility"))
                }
                _ => Ok(self),
            },
            // Matches ErrorThreshold::Runtime and all others.
            LastCall::RuntimeError(e) => Err(e),
        }
    }

    pub fn set_error_threshold(mut self, threshold: ErrorThreshold) -> Self {
        self.0.compat.threshold = threshold;
        self
    }
}

#[derive(Copy, Clone)]
pub struct Compatibility {
    abi_version: i32,
    /// Saves the error threshold for the build chain.
    threshold: ErrorThreshold,
}

impl Compatibility {
    pub fn new() -> Result<Compatibility, Error> {
        match unsafe {
            uapi::landlock_create_ruleset(
                std::ptr::null(),
                0,
                uapi::LANDLOCK_CREATE_RULESET_VERSION,
            )
        } {
            // Landlock ABI version starts at 1 but errno is only set for negative values.
            ret if ret >= 0 => Ok(Compatibility {
                abi_version: ret,
                threshold: ErrorThreshold::NoError,
            }),
            _ => Err(Error::last_os_error()),
        }
    }

    pub fn set_error_threshold(&mut self, threshold: ErrorThreshold) {
        self.threshold = threshold;
    }

    fn is_compatible(&self, minimum_version: i32) -> bool {
        self.abi_version >= minimum_version
    }

    // @new_data returns a default fully supported version of an object.
    fn create<T, F>(&self, minimum_version: i32, new_data: F) -> Result<Compat<T>, Error>
    where
        F: FnOnce() -> T,
    {
        let is_compatible = self.is_compatible(minimum_version);
        Compat(CompatObject {
            last: LastCall::FullSuccess,
            prev_error: None,
            compat: *self,
            build: if is_compatible {
                Some(CompatBuild {
                    status: CompatStatus::Full,
                    data: new_data(),
                })
            } else {
                None
            },
        })
        .set_last_call_status(if is_compatible {
            LastCall::FullSuccess
        } else {
            LastCall::Unsupported
        })
    }
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

pub struct PathBeneath<'a> {
    attr: uapi::landlock_path_beneath_attr,
    // Ties the lifetime of a PathBeneath instance to the litetime of its wrapped attr.parent_fd .
    _parent_fd: PhantomData<&'a u32>,
}

impl PathBeneath<'_> {
    pub fn new<'a, T>(compat: &Compatibility, parent: &'a T) -> Result<Compat<Self>, Error>
    where
        T: AsRawFd,
    {
        compat.create(1, || {
            PathBeneath {
                attr: uapi::landlock_path_beneath_attr {
                    // FIXME: Replace all() with a dedicated Default implementation
                    allowed_access: AccessFs::all().bits,
                    parent_fd: parent.as_raw_fd(),
                },
                _parent_fd: PhantomData,
            }
        })
    }
}

impl Compat<PathBeneath<'_>> {
    // TODO: Replace with `append_allowed_accesses()`?
    pub fn allow_access(self, allowed: AccessFs) -> Result<Self, Error> {
        self.update(1, |mut data| {
            data.attr.allowed_access = allowed.bits;
            // TODO: Checks supported bitflags and update accordingly.
            Ok(data)
        })
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
                handled_access_fs: data.handled_fs.bits,
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
    pub fn add_rule<T>(mut self, mut rule: Compat<T>) -> Result<Self, Error>
    where
        T: Rule,
    {
        match self.0.build {
            None => self.set_last_call_status(LastCall::Fake),
            Some(ref mut ruleset_build) => {
                let last_call_status = match rule.0.build {
                    None => LastCall::Unsupported,
                    Some(ref mut rule_build) => match unsafe {
                        uapi::landlock_add_rule(
                            ruleset_build.data.fd,
                            rule_build.data.get_type_id(),
                            rule_build.data.as_ptr(),
                            rule_build.data.get_flags(),
                        )
                    } {
                        0 => rule_build.status.into(),
                        _ => LastCall::RuntimeError(Error::last_os_error()),
                    },
                };
                self.set_last_call_status(last_call_status)
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    fn ruleset_root_compat() -> Result<(), Error> {
        let compat = Compatibility::new()?;
        RulesetInit::new(&compat)?
            // FIXME: Make it impossible to use AccessFs::all() but group1() instead
            .handle_fs(AccessFs::all())?
            .create()?
            .set_no_new_privs(true)?
            .add_rule(PathBeneath::new(&compat, &File::open("/")?)?.allow_access(AccessFs::all())?)?
            .restrict_self()
            .into_result()
    }

    fn ruleset_root_fragile() -> Result<(), Error> {
        let mut compat = Compatibility::new()?;
        // Sets default error threshold: abort the whole sandboxing for any runtime error.
        compat.set_error_threshold(ErrorThreshold::Runtime);
        RulesetInit::new(&compat)?
            // Must have at least the execute check…
            .set_error_threshold(ErrorThreshold::PartiallyCompatible)
            // FIXME: Make it impossible to use AccessFs::all() but group1() instead
            .handle_fs(AccessFs::EXECUTE)?
            .set_error_threshold(ErrorThreshold::NoError)
            // …and possibly others.
            .handle_fs(AccessFs::all())?
            .create()?
            .set_no_new_privs(true)?
            // Useful to catch wrong PathBeneath's FD type.
            .set_error_threshold(ErrorThreshold::Runtime)
            .add_rule(PathBeneath::new(&compat, &File::open("/")?)?.allow_access(AccessFs::all())?)?
            .restrict_self()
            .into_result()
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
