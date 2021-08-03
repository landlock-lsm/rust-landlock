pub use fs::*;
use std::marker::PhantomData;
use std::ops::{BitOr, BitOrAssign};

mod fs;

#[cfg(test)]
mod net;

pub trait AccessFlags: BitOr + Sized {
    fn get_flags(self) -> u64;
}

pub trait AccessFlagsInner: AccessFlags + BitOr<AccessRights<Self>> + Sized {}

#[derive(Debug, Copy, Clone)]
pub struct AccessRights<T>
where
    T: AccessFlagsInner,
{
    flags: u64,
    _sub: PhantomData<T>,
}

impl<T> AccessFlags for AccessRights<T>
where
    T: AccessFlagsInner,
{
    fn get_flags(self) -> u64 {
        self.flags
    }
}

impl<T> From<T> for AccessRights<T>
where
    T: AccessFlagsInner,
{
    fn from(access: T) -> Self {
        AccessRights {
            flags: access.get_flags(),
            _sub: PhantomData,
        }
    }
}

impl<T> BitOr for AccessRights<T>
where
    T: AccessFlagsInner,
{
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self.flags |= rhs.get_flags();
        self
    }
}

impl<T> BitOr<T> for AccessRights<T>
where
    T: AccessFlagsInner,
{
    type Output = Self;

    fn bitor(mut self, rhs: T) -> Self::Output {
        self.flags |= rhs.get_flags();
        self
    }
}

impl<T> BitOrAssign for AccessRights<T>
where
    T: AccessFlagsInner,
{
    fn bitor_assign(&mut self, rhs: Self) {
        self.flags |= rhs.get_flags();
    }
}

impl<T> BitOrAssign<T> for AccessRights<T>
where
    T: AccessFlagsInner,
{
    fn bitor_assign(&mut self, rhs: T) {
        self.flags |= rhs.get_flags();
    }
}
