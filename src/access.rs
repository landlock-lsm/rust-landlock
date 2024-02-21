use crate::{
    AccessError, AddRuleError, AddRulesError, BitFlags, CompatAccess, CompatError, CompatResult,
    CompatibleArgument, HandleAccessError, HandleAccessesError, Ruleset, TailoredCompatLevel,
    TryCompat, ABI,
};
use enumflags2::BitFlag;

#[cfg(test)]
use crate::{make_bitflags, AccessFs, CompatLevel, CompatState, Compatibility};

/*
pub trait Access
where
    Self: PrivateAccess,
        + Into<BitFlags<Self>>
        + Into<CompatAccess<Self>>,
        + CompatibleArgument<CompatSelf = BitFlags<Self>>,
    BitFlags<Self>:
        Into<CompatAccess<BitFlags<Self>>> + CompatibleArgument<CompatSelf = BitFlags<Self>>,
        Into<CompatAccess<Self>>,
*/
pub trait Access
where
    Self: PrivateAccess,
{
    /// Gets the access rights defined by a specific [`ABI`].
    /// Union of [`from_read()`](Access::from_read) and [`from_write()`](Access::from_write).
    fn from_all(abi: ABI) -> BitFlags<Self> {
        // An empty access-right would be an error if passed to the kernel, but because the kernel
        // doesn't support Landlock, no Landlock syscall should be called.  try_compat() should
        // also return RestrictionStatus::Unrestricted when called with unsupported/empty
        // access-righs.
        Self::from_read(abi) | Self::from_write(abi)
    }

    /// Gets the access rights identified as read-only according to a specific ABI.
    /// Exclusive with [`from_write()`](Access::from_write).
    fn from_read(abi: ABI) -> BitFlags<Self>;

    /// Gets the access rights identified as write-only according to a specific ABI.
    /// Exclusive with [`from_read()`](Access::from_read).
    fn from_write(abi: ABI) -> BitFlags<Self>;
}

pub trait PrivateAccess: BitFlag {
    fn ruleset_handle_access(
        ruleset: &mut Ruleset,
        access: CompatAccess<Self>,
        //access: CompatAccess<BitFlags<Self>>,
    ) -> Result<(), HandleAccessesError>
    where
        Self: Access;

    fn into_add_rules_error(error: AddRuleError<Self>) -> AddRulesError
    where
        Self: Access;

    fn into_handle_accesses_error(error: HandleAccessError<Self>) -> HandleAccessesError
    where
        Self: Access;
}

// Creates an illegal/overflowed BitFlags<T> with all its bits toggled, including undefined ones.
fn full_negation<T>(flags: BitFlags<T>) -> BitFlags<T>
where
    T: Access,
{
    unsafe { BitFlags::<T>::from_bits_unchecked(!flags.bits()) }
}

#[test]
fn bit_flags_full_negation() {
    let scoped_negation = !BitFlags::<AccessFs>::all();
    assert_eq!(scoped_negation, BitFlags::<AccessFs>::empty());
    // !BitFlags::<AccessFs>::all() could be equal to full_negation(BitFlags::<AccessFs>::all()))
    // if all the 64-bits would be used, which is not currently the case.
    assert_ne!(scoped_negation, full_negation(BitFlags::<AccessFs>::all()));
}

impl<A> TailoredCompatLevel for BitFlags<A> where A: Access {}

impl<A> TryCompat<A> for BitFlags<A>
where
    A: Access,
{
    fn try_compat_inner(self, abi: ABI) -> Result<CompatResult<Self, A>, CompatError<A>> {
        if self.is_empty() {
            // Empty access-rights would result to a runtime error.
            Err(AccessError::Empty.into())
        } else if !Self::all().contains(self) {
            // Unknown access-rights (at build time) would result to a runtime error.
            // This can only be reached by using the unsafe BitFlags::from_bits_unchecked().
            Err(AccessError::Unknown {
                access: self,
                unknown: self & full_negation(Self::all()),
            }
            .into())
        } else {
            let compat = self & A::from_all(abi);
            if compat.is_empty() {
                Ok(CompatResult::No(
                    AccessError::Incompatible { access: self }.into(),
                ))
            } else if compat != self {
                let error = AccessError::PartiallyCompatible {
                    access: self,
                    incompatible: self & full_negation(compat),
                }
                .into();
                Ok(CompatResult::Partial(compat, error))
            } else {
                Ok(CompatResult::Full(self))
            }
        }
    }
}

#[test]
fn compat_bit_flags() {
    use crate::ABI;

    let mut compat: Compatibility = ABI::V1.into();
    assert!(compat.state == CompatState::Init);

    let ro_access = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
    assert_eq!(
        ro_access,
        ro_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap()
            .unwrap()
    );
    assert!(compat.state == CompatState::Full);

    let empty_access = BitFlags::<AccessFs>::empty();
    assert!(matches!(
        empty_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap_err(),
        CompatError::Access(AccessError::Empty)
    ));

    let all_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63) };
    assert!(matches!(
        all_unknown_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == all_unknown_access && unknown == all_unknown_access
    ));
    // An error makes the state final.
    assert!(compat.state == CompatState::Dummy);

    let some_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63 | 1) };
    assert!(matches!(
        some_unknown_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == some_unknown_access && unknown == all_unknown_access
    ));
    assert!(compat.state == CompatState::Dummy);

    compat = ABI::Unsupported.into();

    // Tests that the ruleset is marked as unsupported.
    assert!(compat.state == CompatState::No);

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    assert_eq!(
        None,
        ro_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap()
    );

    // Tests that the ruleset is in an unsupported state, which is important to be able to still
    // enforce no_new_privs.
    assert!(compat.state == CompatState::No);

    // Access-rights are not valid when they are required for the current ABI.
    compat.level = Some(CompatLevel::HardRequirement);
    assert!(matches!(
        ro_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::Incompatible { access }) if access == ro_access
    ));

    compat = ABI::V1.into();

    // Tests that the ruleset is marked as the unknown compatibility state.
    assert!(compat.state == CompatState::Init);

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    assert_eq!(
        ro_access,
        ro_access
            .try_compat(compat.abi(), compat.level, &mut compat.state)
            .unwrap()
            .unwrap()
    );

    // Tests that the ruleset is in an unsupported state, which is important to be able to still
    // enforce no_new_privs.
    assert!(compat.state == CompatState::Full);

    let v2_access = ro_access | AccessFs::Refer;

    // Access-rights are not valid when they are required for the current ABI.
    compat.level = Some(CompatLevel::HardRequirement);
    assert!(matches!(
        v2_access.try_compat(compat.abi(), compat.level, &mut compat.state).unwrap_err(),
        CompatError::Access(AccessError::PartiallyCompatible { access, incompatible })
            if access == v2_access && incompatible == AccessFs::Refer
    ));
}

/*
impl<A> From<BitFlags<A>> for CompatAccess<A>
where
    A: Access,
{
    fn from(access: BitFlags<A>) -> Self {
        // XXX: How?
        access.into()
    }
}
*/

impl<A> CompatibleArgument for A
where
    A: Access,
{
    type CompatSelf = A;
}

impl<A> CompatibleArgument for BitFlags<A>
where
    A: Access,
{
    type CompatSelf = A;
}

#[test]
fn compat_arg() {
    use crate::{AccessFs, BitFlags, CompatibleArgument, Consequence, Ruleset, RulesetAttr};

    let exec: BitFlags<_> = AccessFs::Execute.into();
    Ruleset::from(ABI::Unsupported)
        .handle_access(exec.if_unmet(Consequence::DisableRuleset))
        .unwrap();

    Ruleset::from(ABI::Unsupported)
        .handle_access(AccessFs::Execute.if_unmet(Consequence::DisableRuleset))
        .unwrap();
}
