use crate::{
    uapi, Access, AddRuleError, AddRulesError, CompatError, Compatibility, Compatible,
    HandleAccessError, HandleAccessesError, PathBeneathError, PathFdError, PrivateAccess,
    PrivateRule, Rule, Ruleset, RulesetCreated, TryCompat, ABI,
};
use enumflags2::{bitflags, make_bitflags, BitFlags};
use std::fs::{File, OpenOptions};
use std::io::Error;
use std::mem::zeroed;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

/// File system access right.
///
/// Each variant of `AccessFs` is an [access right](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights)
/// for the file system.
/// A set of access rights can be created with [`BitFlags<AccessFs>`](BitFlags).
///
/// # Example
///
/// ```
/// use landlock::{ABI, Access, AccessFs, BitFlags, make_bitflags};
///
/// let exec = AccessFs::Execute;
///
/// let exec_set: BitFlags<AccessFs> = exec.into();
///
/// let file_content = make_bitflags!(AccessFs::{Execute | WriteFile | ReadFile});
///
/// let fs_v1 = AccessFs::from_all(ABI::V1);
///
/// let without_exec = fs_v1 & !AccessFs::Execute;
/// ```
///
/// # Warning
///
/// To avoid compile time behavior at run time,
/// which may look like undefined behavior,
/// don't use `BitFlags::<AccessFs>::all()` nor `BitFlags::ALL`,
/// but [`AccessFs::from_all(ABI::V1)`](Access::from_all) instead.
/// See [`ABI`] for the rational.
#[bitflags]
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessFs {
    /// Execute a file.
    Execute = uapi::LANDLOCK_ACCESS_FS_EXECUTE as u64,
    /// Open a file with write access.
    WriteFile = uapi::LANDLOCK_ACCESS_FS_WRITE_FILE as u64,
    /// Open a file with read access.
    ReadFile = uapi::LANDLOCK_ACCESS_FS_READ_FILE as u64,
    /// Open a directory or list its content.
    ReadDir = uapi::LANDLOCK_ACCESS_FS_READ_DIR as u64,
    /// Remove an empty directory or rename one.
    RemoveDir = uapi::LANDLOCK_ACCESS_FS_REMOVE_DIR as u64,
    /// Unlink (or rename) a file.
    RemoveFile = uapi::LANDLOCK_ACCESS_FS_REMOVE_FILE as u64,
    /// Create (or rename or link) a character device.
    MakeChar = uapi::LANDLOCK_ACCESS_FS_MAKE_CHAR as u64,
    /// Create (or rename) a directory.
    MakeDir = uapi::LANDLOCK_ACCESS_FS_MAKE_DIR as u64,
    /// Create (or rename or link) a regular file.
    MakeReg = uapi::LANDLOCK_ACCESS_FS_MAKE_REG as u64,
    /// Create (or rename or link) a UNIX domain socket.
    MakeSock = uapi::LANDLOCK_ACCESS_FS_MAKE_SOCK as u64,
    /// Create (or rename or link) a named pipe.
    MakeFifo = uapi::LANDLOCK_ACCESS_FS_MAKE_FIFO as u64,
    /// Create (or rename or link) a block device.
    MakeBlock = uapi::LANDLOCK_ACCESS_FS_MAKE_BLOCK as u64,
    /// Create (or rename or link) a symbolic link.
    MakeSym = uapi::LANDLOCK_ACCESS_FS_MAKE_SYM as u64,
}

impl Access for AccessFs {
    fn from_all(abi: ABI) -> BitFlags<Self> {
        match abi {
            // An empty access-right would be an error if passed to the kernel, but because the
            // kernel doesn't support Landlock, no Landlock syscall should be called.
            // try_compat() should also return RestrictionStatus::Unrestricted when called with
            // unsupported/empty access-righs.
            ABI::Unsupported => BitFlags::empty(),
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

impl PrivateAccess for AccessFs {
    fn ruleset_handle_access(
        mut ruleset: Ruleset,
        access: BitFlags<Self>,
    ) -> Result<Ruleset, HandleAccessesError> {
        ruleset.requested_handled_fs = access;
        ruleset.actual_handled_fs = ruleset
            .requested_handled_fs
            .try_compat(&mut ruleset.compat)
            .map_err(HandleAccessError::Compat)?;
        Ok(ruleset)
    }

    fn into_add_rules_error(error: AddRuleError<Self>) -> AddRulesError {
        AddRulesError::Fs(error)
    }

    fn into_handle_accesses_error(error: HandleAccessError<Self>) -> HandleAccessesError {
        HandleAccessesError::Fs(error)
    }
}

const ACCESS_FILE: BitFlags<AccessFs> = make_bitflags!(AccessFs::{
    ReadFile | WriteFile | Execute
});

/// Landlock rule for a file hierarchy.
///
/// # Example
///
/// ```
/// use landlock::{AccessFs, PathBeneath, PathFd, PathFdError};
///
/// fn home_dir() -> Result<PathBeneath<PathFd>, PathFdError> {
///     Ok(PathBeneath::new(PathFd::new("/home")?, AccessFs::ReadDir))
/// }
/// ```
#[cfg_attr(test, derive(Debug))]
pub struct PathBeneath<F> {
    attr: uapi::landlock_path_beneath_attr,
    // Ties the lifetime of a file descriptor to this object.
    _parent_fd: F,
    allowed_access: BitFlags<AccessFs>,
    is_best_effort: bool,
}

impl<F> PathBeneath<F>
where
    F: AsRawFd,
{
    /// Creates a new `PathBeneath` rule identifying the `parent` directory of a file hierarchy,
    /// or just a file, and allows `access` on it.
    /// The `parent` file descriptor will be automatically closed with the returned `PathBeneath`.
    pub fn new<A>(parent: F, access: A) -> Self
    where
        A: Into<BitFlags<AccessFs>>,
    {
        PathBeneath {
            attr: uapi::landlock_path_beneath_attr {
                // Invalid access-rights until try_compat() is called.
                allowed_access: 0,
                parent_fd: parent.as_raw_fd(),
            },
            _parent_fd: parent,
            allowed_access: access.into(),
            is_best_effort: true,
        }
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

impl<F> TryCompat<AccessFs> for PathBeneath<F>
where
    F: AsRawFd,
{
    fn try_compat(self, compat: &mut Compatibility) -> Result<Self, CompatError<AccessFs>> {
        let mut filtered = self.filter_access()?;
        filtered.attr.allowed_access = filtered.allowed_access.try_compat(compat)?.bits();
        Ok(filtered)
    }
}

impl<F> Compatible for PathBeneath<F> {
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
            PathBeneath::new(PathFd::new(file).unwrap(), ro_access)
                .set_best_effort(false)
                .try_compat(&mut compat_copy)
                .unwrap_err(),
            CompatError::PathBeneath(PathBeneathError::DirectoryAccess { access, incompatible })
                if access == ro_access && incompatible == AccessFs::ReadDir
        ));
        // compat_copy.state is not consistent when an error occurs.

        let mut compat_copy = compat.clone();
        assert!(matches!(
            PathBeneath::new(PathFd::new(file).unwrap(), BitFlags::EMPTY)
                .try_compat(&mut compat_copy)
                .unwrap_err(),
            CompatError::Access(AccessError::Empty)
        ));
        // compat_copy.state is not consistent when an error occurs.
    }

    let full_access = AccessFs::from_all(ABI::V1);
    for best_effort in &[true, false] {
        let mut compat_copy = compat.clone();
        let raw_access = PathBeneath::new(PathFd::new("/").unwrap(), full_access)
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
impl<F> Rule<AccessFs> for PathBeneath<F> where F: AsRawFd {}

impl<F> PrivateRule<AccessFs> for PathBeneath<F>
where
    F: AsRawFd,
{
    fn as_ptr(&self) -> *const libc::c_void {
        &self.attr as *const _ as _
    }

    fn get_type_id(&self) -> uapi::landlock_rule_type {
        uapi::landlock_rule_type_LANDLOCK_RULE_PATH_BENEATH
    }

    fn get_flags(&self) -> u32 {
        0
    }

    fn check_consistency(&self, ruleset: &RulesetCreated) -> Result<(), AddRulesError> {
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
            }
            .into())
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
            .handle_access(ro_access)
            .unwrap()
            .create()
            .unwrap()
            .add_rule(PathBeneath::new(PathFd::new("/").unwrap(), rx_access))
            .unwrap_err(),
        RulesetError::AddRules(AddRulesError::Fs(AddRuleError::UnhandledAccess { access, incompatible }))
            if access == rx_access && incompatible == AccessFs::Execute
    ));
}

/// Simple helper to open a file or a directory with the `O_PATH` flag.
///
/// This is the recommended way to identify a path
/// and manage the lifetime of the underlying opened file descriptor.
/// Indeed, using other [`AsRawFd`] implementations such as [`File`] brings more complexity
/// and may lead to unexpected errors (e.g., denied access).
///
/// # Example
///
/// ```
/// use landlock::{AccessFs, PathBeneath, PathFd, PathFdError};
///
/// fn allowed_root_dir(access: AccessFs) -> Result<PathBeneath<PathFd>, PathFdError> {
///     let fd = PathFd::new("/")?;
///     Ok(PathBeneath::new(fd, access))
/// }
/// ```
#[cfg_attr(test, derive(Debug))]
pub struct PathFd {
    file: File,
}

impl PathFd {
    pub fn new<T>(path: T) -> Result<Self, PathFdError>
    where
        T: AsRef<Path>,
    {
        Ok(PathFd {
            file: OpenOptions::new()
                .read(true)
                // If the O_PATH is not supported, it is automatically ignored (Linux < 2.6.39).
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(path.as_ref())
                .map_err(|e| PathFdError::OpenCall {
                    source: e,
                    path: path.as_ref().into(),
                })?,
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
    use std::io::Read;
    use std::os::unix::io::FromRawFd;

    PathBeneath::new(PathFd::new("/").unwrap(), AccessFs::Execute);
    PathBeneath::new(File::open("/").unwrap(), AccessFs::Execute);

    let mut buffer = [0; 1];
    // Checks that PathFd really returns an FD opened with O_PATH (Bad file descriptor error).
    unsafe {
        File::from_raw_fd(PathFd::new("/etc/passwd").unwrap().as_raw_fd())
            .read(&mut buffer)
            .unwrap_err()
    };
}
