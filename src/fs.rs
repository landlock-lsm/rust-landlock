use super::{uapi, Compat, Compatibility, Rule, ABI};
use std::io::Error;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;

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

impl From<ABI> for AccessFs {
    fn from(abi: ABI) -> Self {
        match abi {
            ABI::V1 => AccessFs::from_bits_truncate(
                AccessFs::EXECUTE.bits()
                    | AccessFs::WRITE_FILE.bits()
                    | AccessFs::READ_FILE.bits()
                    | AccessFs::READ_DIR.bits()
                    | AccessFs::REMOVE_DIR.bits()
                    | AccessFs::REMOVE_FILE.bits()
                    | AccessFs::MAKE_CHAR.bits()
                    | AccessFs::MAKE_DIR.bits()
                    | AccessFs::MAKE_REG.bits()
                    | AccessFs::MAKE_SOCK.bits()
                    | AccessFs::MAKE_FIFO.bits()
                    | AccessFs::MAKE_BLOCK.bits()
                    | AccessFs::MAKE_SYM.bits(),
            ),
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
            let allowed: AccessFs = ABI::V1.into();
            PathBeneath {
                attr: uapi::landlock_path_beneath_attr {
                    allowed_access: allowed.bits,
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
    pub fn allow_access(self, allowed: AccessFs) -> Result<Self, Error> {
        self.update(1, |mut data| {
            data.attr.allowed_access = allowed.bits();
            // TODO: Checks supported bitflags and update accordingly.
            Ok(data)
        })
    }
}
