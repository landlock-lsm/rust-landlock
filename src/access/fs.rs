use super::*;
use crate::uapi;

#[derive(Debug, Copy, Clone)]
#[repr(u64)]
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

// It would be nice to have const BitOr implementations:
// https://github.com/rust-lang/rfcs/blob/master/text/0911-const-fn.md
impl AccessFs {
    /// Returns `ReadFile | ReadDir`.
    pub fn read() -> AccessRights<Self> {
        AccessFs::ReadFile | AccessFs::ReadDir
    }

    /// Returns `MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym`.
    pub fn make() -> AccessRights<Self> {
        AccessFs::MakeChar
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeSym
    }

    /// Returns `RemoveDir | RemoveFile`.
    pub fn remove() -> AccessRights<Self> {
        AccessFs::RemoveDir | AccessFs::RemoveFile
    }

    /// Returns `Execute | WriteFile | ReadFile | ReadDir | RemoveDir | RemoveFile | MakeChar |
    /// MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym`.
    pub fn group1() -> AccessRights<Self> {
        AccessFs::Execute
            | AccessFs::WriteFile
            | AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::RemoveDir
            | AccessFs::RemoveFile
            | AccessFs::MakeChar
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeSym
    }
}

impl AccessFlags for AccessFs {
    fn get_flags(self) -> u64 {
        self as u64
    }
}

impl AccessRights<AccessFs> {
    // This will stay compatible because it only removes access bits.
    /// Masks access rights that are not compatible with files, i.e. only keeps `Execute |
    /// WriteFile | ReadFile`.
    pub fn mask_dir_accesses(mut self) -> Self {
        self.flags &=
            AccessFs::Execute as u64 | AccessFs::WriteFile as u64 | AccessFs::ReadFile as u64;
        self
    }
}

impl AccessFlagsInner for AccessFs {}

pub trait AccessFlagsFs: AccessFlags {}

impl AccessFlagsFs for AccessFs {}

impl AccessFlagsFs for AccessRights<AccessFs> {}

impl<T> BitOr<T> for AccessFs
where
    T: AccessFlagsFs,
{
    type Output = AccessRights<Self>;

    fn bitor(self, rhs: T) -> Self::Output {
        AccessRights {
            flags: self as u64 | rhs.get_flags(),
            _sub: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_accesses<T>(set: T)
    where
        T: Into<AccessRights<AccessFs>>,
    {
        println!("access set: {:?}", set.into());
    }

    #[test]
    fn access_fs() {
        let _read = AccessFs::read();
        //let read_set_set: AccessRights<AccessRights<AccessFs>> = _read.into();

        let exec = AccessFs::Execute;
        let _exec_set: AccessRights<AccessFs> = exec.into();

        let mut set1 = exec | AccessFs::WriteFile | AccessFs::ReadFile;
        get_accesses(set1);
        get_accesses(AccessFs::Execute);

        let set2 = AccessFs::WriteFile | set1;
        set1 |= AccessFs::MakeChar;
        set1 = set2 | set1;
        set1 |= set2;
    }
}
