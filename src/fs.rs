use crate::{
    uapi, CompatState, Compatibility, Compatible, PrivateRule, Rule, RulesetCreated, SupportLevel,
    TryCompat, ABI,
};
use enumflags2::{bitflags, make_bitflags, BitFlags};
use std::io::Error;
use std::marker::PhantomData;
use std::mem::zeroed;
use std::os::unix::io::AsRawFd;

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
    level: SupportLevel,
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
            level: SupportLevel::Optional,
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

    // Check with our own support level.
    fn filter_access(&mut self) -> Result<(), Error> {
        let is_file = unsafe {
            let mut stat = zeroed();
            match libc::fstat(self.attr.parent_fd, &mut stat) {
                0 => (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR,
                _ => return Err(Error::last_os_error()),
            }
        };

        // Gets subset of valid accesses according the FD type.
        let valid_access = if is_file {
            self.allowed_access & ACCESS_FILE
        } else {
            self.allowed_access
        };

        if self.allowed_access != valid_access {
            match self.level {
                SupportLevel::Optional => self.allowed_access = valid_access,
                SupportLevel::Required => return Err(Error::from_raw_os_error(libc::EINVAL)),
            }
        }
        Ok(())
    }
}

impl TryCompat for PathBeneath<'_> {
    fn try_compat(mut self, compat: &mut Compatibility) -> Result<Self, Error> {
        if let Err(e) = self.filter_access() {
            compat.state.update(CompatState::No);
            return Err(e);
        }
        self.attr.allowed_access = self.allowed_access.try_compat(compat)?.bits();
        Ok(self)
    }
}

impl Compatible for PathBeneath<'_> {
    fn set_support_level(mut self, level: SupportLevel) -> Self {
        self.level = level;
        self
    }
}

#[test]
fn path_beneath_try_compat() {
    use crate::*;
    use std::fs::File;
    use std::io::ErrorKind;

    let compat = Compatibility {
        abi: ABI::V1,
        level: SupportLevel::Optional,
        state: CompatState::Start,
    };

    for file in &["/etc/passwd", "/dev/null"] {
        let mut compat_copy = compat.clone();
        assert_eq!(
            PathBeneath::new(&File::open(file).unwrap())
                .allow_access(AccessFs::ReadDir)
                .set_support_level(SupportLevel::Required)
                .try_compat(&mut compat_copy)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(compat_copy.state, CompatState::No);
    }

    let full_access: BitFlags<AccessFs> = ABI::V1.into();
    for level in &[SupportLevel::Required, SupportLevel::Optional] {
        let mut compat_copy = compat.clone();
        let raw_access = PathBeneath::new(&File::open("/").unwrap())
            .allow_access(full_access)
            .set_support_level(*level)
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
impl Rule for PathBeneath<'_> {}

impl PrivateRule for PathBeneath<'_> {
    fn as_ptr(&self) -> *const libc::c_void {
        &self.attr as *const _ as _
    }

    fn get_type_id(&self) -> uapi::landlock_rule_type {
        uapi::landlock_rule_type_LANDLOCK_RULE_PATH_BENEATH
    }

    fn get_flags(&self) -> u32 {
        0
    }

    fn check_consistency(&self, ruleset: &RulesetCreated) -> Result<(), Error> {
        // Checks that this rule doesn't contain a superset of the access-rights handled by the
        // ruleset.  This check is about requested access-rights but not actual access-rights.
        // Indeed, we want to get a deterministic behavior, i.e. not based on the running kernel
        // (which is handled by RulesetInit and RulesetCreated).
        if ruleset.requested_handled_fs.contains(self.allowed_access) {
            Ok(())
        } else {
            // TODO: Replace all Error::from_raw_os_error() with high-level errors.
            Err(Error::from_raw_os_error(libc::EINVAL))
        }
    }
}
