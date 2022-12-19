use crate::{
    AccessError, AddRuleError, AddRulesError, BitFlags, CompatError, CompatLevel, CompatState,
    Compatibility, HandleAccessError, HandleAccessesError, Ruleset, TryCompat, ABI,
};
use enumflags2::BitFlag;

#[cfg(test)]
use crate::{make_bitflags, AccessFs};

pub trait Access: PrivateAccess {
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
        access: BitFlags<Self>,
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

impl<T> TryCompat<T> for BitFlags<T>
where
    T: Access,
{
    fn try_compat(self, compat: &mut Compatibility) -> Result<Option<Self>, CompatError<T>> {
        let (state, ret) = if self.is_empty() {
            // Empty access-rights would result to a runtime error.
            (CompatState::Dummy, Err(AccessError::Empty.into()))
        } else if !Self::all().contains(self) {
            // Unknown access-rights (at build time) would result to a runtime error.
            // This can only be reached by using the unsafe BitFlags::from_bits_unchecked().
            (
                CompatState::Dummy,
                Err(AccessError::Unknown {
                    access: self,
                    unknown: self & full_negation(Self::all()),
                }
                .into()),
            )
        } else {
            let compat_bits = self & T::from_all(compat.abi());
            if compat_bits.is_empty() {
                match compat.level {
                    // Empty access-rights are ignored to avoid an error when passing them to
                    // landlock_add_rule().
                    CompatLevel::BestEffort => (CompatState::No, Ok(None)),
                    CompatLevel::SoftRequirement => (CompatState::Dummy, Ok(None)),
                    CompatLevel::HardRequirement => (
                        CompatState::Dummy,
                        Err(AccessError::Incompatible { access: self }.into()),
                    ),
                }
            } else if compat_bits != self {
                match compat.level {
                    CompatLevel::BestEffort => (CompatState::Partial, Ok(Some(compat_bits))),
                    CompatLevel::SoftRequirement => (CompatState::Dummy, Ok(None)),
                    CompatLevel::HardRequirement => (
                        CompatState::Dummy,
                        Err(AccessError::PartiallyCompatible {
                            access: self,
                            incompatible: self & full_negation(compat_bits),
                        }
                        .into()),
                    ),
                }
            } else {
                (CompatState::Full, Ok(Some(compat_bits)))
            }
        };
        compat.update(state);
        ret
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
        ro_access.try_compat(&mut compat).unwrap().unwrap()
    );
    assert!(compat.state == CompatState::Full);

    let empty_access = BitFlags::<AccessFs>::empty();
    assert!(matches!(
        empty_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Empty)
    ));

    let all_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63) };
    assert!(matches!(
        all_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == all_unknown_access && unknown == all_unknown_access
    ));
    // An error makes the state final.
    assert!(compat.state == CompatState::Dummy);

    let some_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63 | 1) };
    assert!(matches!(
        some_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == some_unknown_access && unknown == all_unknown_access
    ));
    assert!(compat.state == CompatState::Dummy);

    compat = ABI::Unsupported.into();

    // Tests that the ruleset is marked as unsupported.
    assert!(compat.state == CompatState::No);

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    assert_eq!(None, ro_access.try_compat(&mut compat).unwrap());

    // Tests that the ruleset is in an unsupported state, which is important to be able to still
    // enforce no_new_privs.
    assert!(compat.state == CompatState::No);

    // Access-rights are not valid when they are required for the current ABI.
    compat.level = CompatLevel::HardRequirement;
    assert!(matches!(
        ro_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Incompatible { access }) if access == ro_access
    ));
}
