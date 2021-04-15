use libc::close;
use std::io::Error;
use std::mem::size_of_val;
use std::os::unix::io::RawFd;

mod uapi;

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
}

impl Drop for Ruleset {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}
