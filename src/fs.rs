use crate::{
    uapi, Access, AddRuleError, AddRulesError, CompatError, Compatibility, Compatible,
    HandleAccessError, HandleAccessesError, PathBeneathError, PathFdError, PrivateAccess,
    PrivateRule, Rule, Ruleset, RulesetCreated, RulesetError, TryCompat, ABI,
};
use enumflags2::{bitflags, make_bitflags, BitFlags};
use std::fs::{File, OpenOptions};
use std::io::Error;
use std::mem::zeroed;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

#[cfg(test)]
use strum::IntoEnumIterator;

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
///
/// assert_eq!(fs_v1 | AccessFs::Refer, AccessFs::from_all(ABI::V2));
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
    /// Link or rename a file from or to a different directory.
    Refer = uapi::LANDLOCK_ACCESS_FS_REFER as u64,
}

impl Access for AccessFs {
    // Roughly read (i.e. not all FS actions are handled).
    fn from_read(abi: ABI) -> BitFlags<Self> {
        match abi {
            ABI::Unsupported => BitFlags::EMPTY,
            ABI::V1 | ABI::V2 => make_bitflags!(AccessFs::{
                Execute
                | ReadFile
                | ReadDir
            }),
        }
    }

    // Roughly write (i.e. not all FS actions are handled).
    fn from_write(abi: ABI) -> BitFlags<Self> {
        match abi {
            ABI::Unsupported => BitFlags::EMPTY,
            ABI::V1 => make_bitflags!(AccessFs::{
                WriteFile
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
            ABI::V2 => Self::from_write(ABI::V1) | AccessFs::Refer,
        }
    }
}

#[test]
fn consistent_access_fs_rw() {
    for abi in ABI::iter() {
        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);
        let access_write = AccessFs::from_write(abi);
        assert_eq!(access_read, !access_write & access_all);
        assert_eq!(access_read | access_write, access_all);
    }
}

impl PrivateAccess for AccessFs {
    fn ruleset_handle_access(
        mut ruleset: Ruleset,
        access: BitFlags<Self>,
    ) -> Result<Ruleset, HandleAccessesError> {
        ruleset.requested_handled_fs |= access;
        ruleset.actual_handled_fs |= access
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
        Ruleset::from(ABI::Unsupported)
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

/// Helper to quickly create an iterator of PathBeneath rules.
///
/// Silently ignores paths that cannot be opened.
///
/// # Example
///
/// ```
/// use landlock::{ABI, Access, AccessFs, Ruleset, RulesetStatus, RulesetError, path_beneath_rules};
///
/// fn restrict_thread() -> Result<(), RulesetError> {
///     let abi = ABI::V1;
///     let status = Ruleset::new()
///         .handle_access(AccessFs::from_all(abi))?
///         .create()?
///         // Read-only access to /usr, /etc and /dev.
///         .add_rules(path_beneath_rules(&["/usr", "/etc", "/dev"], AccessFs::from_read(abi)))?
///         // Read-write access to /home and /tmp.
///         .add_rules(path_beneath_rules(&["/home", "/tmp"], AccessFs::from_all(abi)))?
///         .restrict_self()?;
///     match status.ruleset {
///         // The FullyEnforced case must be tested by the developer.
///         RulesetStatus::FullyEnforced => println!("Fully sandboxed."),
///         RulesetStatus::PartiallyEnforced => println!("Partially sandboxed."),
///         // Users should be warned that they are not protected.
///         RulesetStatus::NotEnforced => println!("Not sandboxed! Please update your kernel."),
///     }
///     Ok(())
/// }
/// ```
pub fn path_beneath_rules<I, P, A>(
    paths: I,
    access: A,
) -> impl Iterator<Item = Result<PathBeneath<PathFd>, RulesetError>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
    A: Into<BitFlags<AccessFs>>,
{
    let access = access.into();
    paths.into_iter().filter_map(move |p| match PathFd::new(p) {
        Ok(f) => Some(Ok(PathBeneath::new(f, access))),
        Err(_) => None,
    })
}

#[test]
fn path_beneath_rules_iter() {
    let _ = Ruleset::new()
        .handle_access(AccessFs::from_all(ABI::V1))
        .unwrap()
        .create()
        .unwrap()
        .add_rules(path_beneath_rules(
            &["/usr", "/opt", "/does-not-exist", "/root"],
            AccessFs::Execute,
        ))
        .unwrap();
}
