// TEST ONLY

use super::*;

#[derive(Debug, Copy, Clone)]
#[repr(u64)]
pub enum AccessNet {
    Connect = 1,
}

impl AccessFlags for AccessNet {
    fn get_flags(self) -> u64 {
        self as u64
    }
}

impl AccessFlagsInner for AccessNet {}

pub trait AccessFlagsNet: AccessFlags {}

impl AccessFlagsNet for AccessNet {}

impl AccessFlagsNet for AccessRights<AccessNet> {}

impl<T> BitOr<T> for AccessNet
where
    T: AccessFlagsNet,
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

    #[test]
    fn access_net() {
        let connect = AccessNet::Connect;
        let _connect_set: AccessRights<AccessNet> = connect.into();

        //let _connect_set_wrong_type: AccessRights<AccessFs> = connect.into();
    }
}
