use crate::{
    uapi, AddRuleError, CompatError, Compatibility, Compatible, PathBeneathError, PrivateRule,
    Rule, RulesetCreated, TryCompat, ABI,
};
use enumflags2::{bitflags, make_bitflags, BitFlags};
use std::fs::{File, OpenOptions};
use std::io::Error;
use std::marker::PhantomData;
use std::mem::zeroed;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

/// WARNING: Don't use `BitFlags::<AccessFs>::all()` nor `BitFlags::ALL` but `ABI::V1.into()`
/// instead.
#[bitflags]
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessFs {
    Execute = uapi::LANDLOCK_ACCESS_FS_EXECUTE as u64,
    WriteFile = uapi::LANDLOCK_ACCESS_FS_WRITE_FILE as u64,
    ReadFile = uapi::LANDLOCK_ACCESS_FS_READ_FILE as u64,
    ReadDir = uapi::LANDLOCK_ACCESS_FS_READ_DIR as u64,
    RemoveDir = uapi::LANDLOCK_ACCESS_FS_REMOVE_DIR as u64,
    RemoveFile = uapi::LANDLOCK_ACCESS_FS_REMOVE_FILE as u64,
    MakeChar = uapi::LANDLOCK_ACCESS_FS_MAKE_CHAR as u64,
    MakeDir = uapi::LANDLOCK_ACCESS_FS_MAKE_DIR as u64,
    MakeReg = uapi::LANDLOCK_ACCESS_FS_MAKE_REG as u64,
    MakeSock = uapi::LANDLOCK_ACCESS_FS_MAKE_SOCK as u64,
    MakeFifo = uapi::LANDLOCK_ACCESS_FS_MAKE_FIFO as u64,
    MakeBlock = uapi::LANDLOCK_ACCESS_FS_MAKE_BLOCK as u64,
    MakeSym = uapi::LANDLOCK_ACCESS_FS_MAKE_SYM as u64,
}

impl From<ABI> for BitFlags<AccessFs> {
    fn from(abi: ABI) -> Self {
        match abi {
            // An empty access-right would be an error if passed to the kernel, but because the
            // kernel doesn't support Landlock, no Landlock syscall should be called.
            // try_compat() should also return RestrictionStatus::Unrestricted when called with
            // unsupported/empty access-righs.
            ABI::Unsupported => BitFlags::<AccessFs>::empty(),
            ABI::V1 => make_bitflags!(AccessFs::{
                Execute
                | WriteFile
                | ReadFile
                | ReadDir
                | RemoveDir
                | RemoveFile
                | MakeChar
                | MakeDir
                | MakeReg
                | MakeSock
                | MakeFifo
                | MakeBlock
                | MakeSym
            }),
        }
    }
}

const ACCESS_FILE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    ReadFile | WriteFile | Execute
});

#[cfg_attr(test, derive(Debug))]
pub struct PathBeneath<'a> {
    attr: uapi::landlock_path_beneath_attr,
    // Ties the lifetime of a PathBeneath instance to the litetime of its wrapped attr.parent_fd .
    _parent_fd: PhantomData<&'a u32>,
    allowed_access: BitFlags<AccessFs>,
    is_best_effort: bool,
}

impl PathBeneath<'_> {
    pub fn new<'a, T>(parent: &'a T) -> Self
    where
        T: AsRawFd,
    {
        // By default, allows all v1 accesses on this path exception.
        PathBeneath {
            attr: uapi::landlock_path_beneath_attr {
                // Invalid access-rights until try_compat() is called.
                allowed_access: 0,
                parent_fd: parent.as_raw_fd(),
            },
            _parent_fd: PhantomData,
            allowed_access: ABI::V1.into(),
            is_best_effort: true,
        }
    }

    // TODO: Replace with `append_allowed_accesses()`?
    pub fn allow_access<T>(mut self, access: T) -> Self
    where
        T: Into<BitFlags<AccessFs>>,
    {
        self.allowed_access = access.into();
        self
    }

    // Check with our own support requirement.
    fn filter_access(mut self) -> Result<Self, PathBeneathError> {
        let is_file = unsafe {
            let mut stat = zeroed();
            match libc::fstat(self.attr.parent_fd, &mut stat) {
                0 => (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR,
                _ => {
                    return Err(PathBeneathError::StatCall {
                        source: Error::last_os_error(),
                    })
                }
            }
        };

        // Gets subset of valid accesses according the FD type.
        let valid_access = if is_file {
            self.allowed_access & ACCESS_FILE
        } else {
            self.allowed_access
        };

        if self.allowed_access != valid_access {
            if self.is_best_effort {
                self.allowed_access = valid_access;
            } else {
                // Linux would return EINVAL.
                return Err(PathBeneathError::DirectoryAccess {
                    access: self.allowed_access,
                    incompatible: self.allowed_access ^ valid_access,
                });
            }
        }
        Ok(self)
    }
}

impl TryCompat<AccessFs> for PathBeneath<'_> {
    fn try_compat(self, compat: &mut Compatibility) -> Result<Self, CompatError<AccessFs>> {
        let mut filtered = self.filter_access()?;
        filtered.attr.allowed_access = filtered.allowed_access.try_compat(compat)?.bits();
        Ok(filtered)
    }
}

impl Compatible for PathBeneath<'_> {
    fn set_best_effort(mut self, best_effort: bool) -> Self {
        self.is_best_effort = best_effort;
        self
    }
}

#[test]
fn path_beneath_try_compat() {
    use crate::*;

    let compat: Compatibility = ABI::V1.into();

    for file in &["/etc/passwd", "/dev/null"] {
        let mut compat_copy = compat.clone();
        let ro_access = AccessFs::ReadDir | AccessFs::ReadFile;
        assert!(matches!(
            PathBeneath::new(&PathFd::new(file).unwrap())
                .allow_access(ro_access)
                .set_best_effort(false)
                .try_compat(&mut compat_copy)
                .unwrap_err(),
            CompatError::PathBeneath(PathBeneathError::DirectoryAccess { access, incompatible })
                if access == ro_access && incompatible == AccessFs::ReadDir
        ));
        // compat_copy.state is not consistent when an error occurs.
    }

    let full_access: BitFlags<AccessFs> = ABI::V1.into();
    for best_effort in &[true, false] {
        let mut compat_copy = compat.clone();
        let raw_access = PathBeneath::new(&PathFd::new("/").unwrap())
            .allow_access(full_access)
            .set_best_effort(*best_effort)
            .try_compat(&mut compat_copy)
            .unwrap()
            .attr
            .allowed_access;
        assert_eq!(raw_access, full_access.bits());
        assert_eq!(compat_copy.state, CompatState::Full);
    }
}

// It is useful for documentation generation to explicitely implement Rule for every types, instead
// of doing it generically.
impl Rule<AccessFs> for PathBeneath<'_> {}

impl PrivateRule<AccessFs> for PathBeneath<'_> {
    fn as_ptr(&self) -> *const libc::c_void {
        &self.attr as *const _ as _
    }

    fn get_type_id(&self) -> uapi::landlock_rule_type {
        uapi::landlock_rule_type_LANDLOCK_RULE_PATH_BENEATH
    }

    fn get_flags(&self) -> u32 {
        0
    }

    fn check_consistency(&self, ruleset: &RulesetCreated) -> Result<(), AddRuleError<AccessFs>> {
        // Checks that this rule doesn't contain a superset of the access-rights handled by the
        // ruleset.  This check is about requested access-rights but not actual access-rights.
        // Indeed, we want to get a deterministic behavior, i.e. not based on the running kernel
        // (which is handled by Ruleset and RulesetCreated).
        if ruleset.requested_handled_fs.contains(self.allowed_access) {
            Ok(())
        } else {
            Err(AddRuleError::UnhandledAccess {
                access: self.allowed_access,
                incompatible: self.allowed_access & !ruleset.requested_handled_fs,
            })
        }
    }
}

#[test]
fn path_beneath_check_consistency() {
    use crate::*;

    let ro_access = AccessFs::ReadDir | AccessFs::ReadFile;
    let rx_access = AccessFs::Execute | AccessFs::ReadFile;
    assert!(matches!(
        Ruleset::new()
            .handle_fs(ro_access)
            .unwrap()
            .create()
            .unwrap()
            .add_rule(PathBeneath::new(&PathFd::new("/").unwrap()).allow_access(rx_access))
            .unwrap_err(),
        AddRuleError::UnhandledAccess { access, incompatible }
            if access == rx_access && incompatible == AccessFs::Execute
    ));
}

pub struct PathFd {
    file: File,
    // TODO: Keep path string for error handling.
}

impl PathFd {
    pub fn new<T>(path: T) -> Result<Self, Error>
    where
        T: AsRef<Path>,
    {
        // TODO: Add fallback for kernel not supporting O_PATH.
        Ok(PathFd {
            file: OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(path.as_ref())?,
        })
    }
}

impl AsRawFd for PathFd {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[test]
fn path_fd() {
    use std::fs::File;

    PathBeneath::new(&PathFd::new("/").unwrap());
    PathBeneath::new(&File::open("/").unwrap());
    // TODO: Test that reading the content doesn't work.
}
