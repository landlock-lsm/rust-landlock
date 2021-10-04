use super::{uapi, Compat, Compatibility, Rule, ABI};
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
}

impl PathBeneath<'_> {
    pub fn new<'a, T>(compat: &Compatibility, parent: &'a T) -> Result<Compat<Self>, Error>
    where
        T: AsRawFd,
    {
        compat.create(1, || {
            // By default, allows all v1 accesses on this path exception.
            let allowed: BitFlags<AccessFs> = ABI::V1.into();
            PathBeneath {
                attr: uapi::landlock_path_beneath_attr {
                    allowed_access: allowed.bits(),
                    parent_fd: parent.as_raw_fd(),
                },
                _parent_fd: PhantomData,
            }
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

impl Compat<PathBeneath<'_>> {
    // TODO: Replace with `append_allowed_accesses()`?
    pub fn allow_access(self, allowed: BitFlags<AccessFs>) -> Result<Self, Error> {
        self.update(1, |mut data| {
            data.attr.allowed_access = allowed.bits();
            // TODO: Checks supported bitflags and update accordingly.
            Ok(data)
        })
    }
}
