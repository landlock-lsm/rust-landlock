use crate::{
    uapi, Access, AddRuleError, AddRulesError, HandleAccessError, HandleAccessesError,
    PrivateAccess, Ruleset, TryCompat, ABI,
};
use enumflags2::{bitflags, BitFlags};

/// Network access right.
///
/// Each variant of `AccessNet` is an [access right](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights)
/// for the file system.
/// A set of access rights can be created with [`BitFlags<AccessNet>`](BitFlags).
///
/// # Example
///
/// ```
/// use landlock::{ABI, Access, AccessNet, BitFlags, make_bitflags};
///
/// let bind = AccessNet::BindTcp;
///
/// let bind_set: BitFlags<AccessNet> = bind.into();
///
/// let bind_connect = make_bitflags!(AccessNet::{BindTcp | ConnectTcp});
///
/// let net_v4 = AccessNet::from_all(ABI::V4);
///
/// assert_eq!(bind_connect, net_v4);
/// ```
///
/// # Warning
///
/// To avoid unknown restrictions **don't use `BitFlags::<AccessNet>::all()` nor `BitFlags::ALL`**,
/// but use a version you tested and vetted instead,
/// for instance [`AccessNet::from_all(ABI::V4)`](Access::from_all).
/// Direct use of **the [`BitFlags`] API is deprecated**.
/// See [`ABI`] for the rationale and help to test it.
#[bitflags]
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccessNet {
    /// Bind to a TCP port.
    BindTcp = uapi::LANDLOCK_ACCESS_NET_BIND_TCP as u64,
    /// Connect to a TCP port.
    ConnectTcp = uapi::LANDLOCK_ACCESS_NET_CONNECT_TCP as u64,
}

/// # Warning
///
/// If `ABI <= ABI::V3`, `AccessNet::from_all()` returns an empty `BitFlags<AccessNet>`, which
/// makes `Ruleset::handle_access(AccessNet::from_all(ABI::V3))` return an error.
impl Access for AccessNet {
    fn from_all(abi: ABI) -> BitFlags<Self> {
        match abi {
            ABI::Unsupported | ABI::V1 | ABI::V2 | ABI::V3 => BitFlags::EMPTY,
            ABI::V4 => AccessNet::BindTcp | AccessNet::ConnectTcp,
        }
    }
}

impl PrivateAccess for AccessNet {
    fn ruleset_handle_access(
        ruleset: &mut Ruleset,
        access: BitFlags<Self>,
    ) -> Result<(), HandleAccessesError> {
        // We need to record the requested accesses for PrivateRule::check_consistency().
        ruleset.requested_handled_net |= access;
        ruleset.actual_handled_net |= match access
            .try_compat(
                ruleset.compat.abi(),
                ruleset.compat.level,
                &mut ruleset.compat.state,
            )
            .map_err(HandleAccessError::Compat)?
        {
            Some(a) => a,
            None => return Ok(()),
        };
        Ok(())
    }

    fn into_add_rules_error(error: AddRuleError<Self>) -> AddRulesError {
        AddRulesError::Net(error)
    }

    fn into_handle_accesses_error(error: HandleAccessError<Self>) -> HandleAccessesError {
        HandleAccessesError::Net(error)
    }
}
