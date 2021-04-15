#[macro_use]
extern crate bitflags;

use libc::close;
use std::io::Error;
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

pub enum Rule {
    PathBeneath(uapi::landlock_path_beneath_attr),
}

impl Rule {
    // We may want to duplicate the FD.
    pub fn new_path_beneath<T>(fd: T, access: AccessFs) -> Rule where T: AsRawFd {
        Rule::PathBeneath(uapi::landlock_path_beneath_attr {
            allowed_access: access.bits,
            parent_fd: fd.as_raw_fd(),
        })
    }

    fn as_ptr(&self) -> *const libc::c_void {
        match self {
            Rule::PathBeneath(attr) => attr as *const _ as _,
        }
    }
}

impl Into<uapi::landlock_rule_type> for &Rule {
    fn into(self) -> uapi::landlock_rule_type {
        match self {
            Rule::PathBeneath(_) => uapi::landlock_rule_type_LANDLOCK_RULE_PATH_BENEATH,
        }
    }
}

pub struct Ruleset {
    fd: RawFd,
}

impl Ruleset {
    pub fn new() -> Result<Ruleset, Error> {
        // The API should be future-proof: one Rust program or library should have the same
        // behavior if builded with an old or a newer crate (e.g. with an extended ruleset_attr
        // enum).  It should then not be possible to give an "all-possible-handled-accesses" to the
        // Ruleset builder because this value would be relative to the running kernel.
        // FIXME: Will return -ENOMSG
        let attr = uapi::landlock_ruleset_attr { handled_access_fs: 0 };

        match unsafe { uapi::landlock_create_ruleset(&attr, size_of_val(&attr), 0) } {
            fd if fd >= 0 => Ok(Ruleset { fd }),
            _ => Err(Error::last_os_error()),
        }
    }

    pub fn add_rule(&mut self, rule: &Rule) -> Result<(), Error> {
        match unsafe { uapi::landlock_add_rule(self.fd, rule.into(), rule.as_ptr(), 0) } {
            0 => Ok(()),
            _ => Err(Error::last_os_error()),
        }
    }

    // Eager method, may not fit with all use-cases though.
    pub fn restrict_self(self) -> Result<(), Error> {
        // TODO: call prctl?
        match unsafe { uapi::landlock_restrict_self(self.fd, 0) } {
            0 => Ok(()),
            _ => Err(Error::last_os_error()),
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
