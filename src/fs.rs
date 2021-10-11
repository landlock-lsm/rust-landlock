use crate::{uapi, Compatibility, PrivateRule, Rule, TryCompat, ABI};
use enumflags2::{bitflags, make_bitflags, BitFlags};
use std::io::Error;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;

/// WARNING: Don't use `BitFlags::<AccessFs>::all()` nor `BitFlags::ALL` but `ABI::V1.into()`
/// instead.
#[bitflags]
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq)]
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

pub struct PathBeneath<'a> {
    attr: uapi::landlock_path_beneath_attr,
    // Ties the lifetime of a PathBeneath instance to the litetime of its wrapped attr.parent_fd .
    _parent_fd: PhantomData<&'a u32>,
    allowed_access: BitFlags<AccessFs>,
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
}

impl TryCompat for PathBeneath<'_> {
    fn try_compat(mut self, compat: &mut Compatibility) -> Result<Self, Error> {
        self.attr.allowed_access = self.allowed_access.try_compat(compat)?.bits();
        Ok(self)
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
}
